import base64
import hashlib
import json
import platform
import secrets
import struct
from functools import wraps
from pathlib import Path
from typing import Optional


class CredentialsNotFoundError(Exception):
    """Exception raised when the credentials file is not found."""

    def __init__(self, path):
        self.path = path
        self.message = f"Credentials file not found at {path}"
        super().__init__(self.message)


class IncorrectPasswordError(Exception):
    """Exception raised when the password entered is incorrect."""

    def __init__(self, msg: str = ''):
        self.message = msg
        super().__init__(self.message)


def _get_key_length() -> tuple[int, int]:
    """Determine the key and salt lengths based on system information.

    This function creates a unique hash based on the system's hardware and
    softwarecharacteristics, then uses this hash to derive lengths for the
    encryption key and salt.

    Returns:
        tuple[int, int]: A tuple containing the key length and salt length.
    """
    system_info = {
        'machine': platform.machine(),
        'processor': platform.processor(),
        'system': platform.system(),
        'architecture': struct.calcsize("P") * 8,  # 32 or 64 bit
    }

    # Create a string representation of the system info
    info_string = ''.join(f'{k}:{v}' for k, v in system_info.items())

    # Hash the string
    hash_object = hashlib.sha256(info_string.encode())
    hash_hex = hash_object.hexdigest()

    # Use the first 2 bytes of the hash to determine key length
    # This will give a number between 0 and 65535
    RADIX = 0x10
    key_length = int(hash_hex[:4], RADIX)
    # Use the next 2 bytes of the hash to determine salt length
    salt_length = int(hash_hex[4:8], RADIX)

    # Ensure the key length is within a reasonable range (e.g., 16 to 64 bytes)
    MIN_LENGTH, MAX_LENGTH = 0x10, 0x40

    def clip(length: int) -> int:
        return MIN_LENGTH + (length % (MAX_LENGTH - MIN_LENGTH + 1))

    return clip(key_length), clip(salt_length)


class CredentialsManager:
    """A class for securely managing and storing credentials.

    This class provides methods to store, retrieve, and save credentials
    using a password-based encryption scheme.
    """

    __KEY_RANGE, __SALT_RANGE = tuple(map(range, _get_key_length()))

    def __init__(
        self,
        password: str,
        *,
        salt: Optional[bytearray] = None,
        pswd_is_digest: bool = False,
    ):
        """Initialize the CredentialsManager.

        Args:
            password (str): The password used for encryption.
            salt (bytearray): A salt for the encryption key.
                              If not provided, a salt is generated.
            pswd_is_digest (bool): If True, the password is already
                                   a SHA-256 digest.
        """
        self.__mapping: dict[str, bytearray] = {}
        self._update_encryptions(
            password=password, salt=salt, pswd_is_digest=pswd_is_digest
        )

    def __getitem__(self, item: str) -> str:
        """Allow instances of this class to behave like dictionaries"""
        return self.get(item)

    def __setitem__(self, item: str, value: str) -> None:
        """Allow instances of this class to behave like dictionaries"""
        self.store(item, value)

    def _update_encryptions(
        self,
        password: str,
        salt: Optional[bytearray] = None,
        pswd_is_digest: bool = False,
    ) -> None:
        """Update the encryption key and re-encrypt stored credentials.

        This method is used internally to update the encryption key when the
        password is changed. It re-encrypts all stored credentials with the
        new key.

        Args:
            password (str): The new password for encryption.
            salt (Optional[bytearray]): A new salt for the encryption key.
                                        If not provided, the existing salt is used.
            pswd_is_digest (bool): If True, the password is already a SHA-256 digest.

        Note:
            This method should be called whenever the password or salt is changed
            to ensure all stored credentials remain accessible with the new key.

            Ideally, this method should not be called directly,
            rather it should be invoked by either
            the __init__ or `update_password` methods
        """
        if not pswd_is_digest:
            # Intentionally lose the reference to the password
            password = hashlib.sha256(password.encode()).hexdigest()

        pswd = bytearray(map(ord, password))

        # Make a salt, if not provided
        salt = salt or bytearray(
            [secrets.randbelow(0x100) for _ in self.__SALT_RANGE]
        )

        # Make a key using the password digest and the salt
        f = lambda i: pswd[i % len(pswd)] ^ salt[i % len(salt)]
        key = bytearray(map(f, self.__KEY_RANGE))

        # Update existing encryptions

        # Decrypt with the current key
        original: dict[str, str] = {
            k: self.get(k)
            for k in self.__mapping.keys()
            if k not in ('__cm_password__', '__salt__')
        }

        # Now encrypt with the new key
        self.__key = key
        for name, data in original.items():
            self.store(name, data, overwrite=True)

        # Update metadata
        self.__mapping.update(
            {
                '__cm_password__': pswd,
                '__salt__': salt,
            }
        )

    def update_password(self, old_password: str, new_password: str) -> None:
        """Update the password used for encryption.

        IMPORTANT: This does not automatically save the credentials to disk.
        Please use CredentialsManager.save(filename) to save the new
        encryptions to a file.

        Args:
            old_password (str): The current password.
            new_password (str): The new password to set.

        Raises:
            IncorrectPasswordError: If the old password is incorrect.
        """
        # Intentionally lose the references to the passwords
        old_password = hashlib.sha256(old_password.encode()).hexdigest()

        old_pswd = bytearray(map(ord, old_password))

        if old_pswd != self.__mapping['__cm_password__']:
            raise IncorrectPasswordError(
                'Cannot update password, old password is incorrect'
            )

        self._update_encryptions(password=new_password)

    def store(self, name: str, data: str, overwrite: bool = False) -> None:
        """Store a credential.

        Args:
            name (str): The name of the credential.
            data (str): The credential data to store.
            overwrite (bool): If True, allow overwriting existing credentials.

        Raises:
            ValueError: If the credential already exists and overwrite is False.
        """
        # Input validation starts
        if not isinstance(name, str):
            raise TypeError(
                f'Credential name must be of type {str},'
                f' found type {type(name)}'
            )

        if len(name) <= 0:
            raise ValueError("Credential name must be a non-empty string")

        if not isinstance(data, str):
            raise TypeError(
                f'Credential data must be of type {str},'
                f' found type {type(data)}'
            )

        if len(data) <= 0:
            raise ValueError("Credential data must be a non-empty string")

        if name in self.__mapping and not overwrite:
            raise ValueError(
                'Cannot overwrite credential unless `overwrite=True` is passed'
            )

        # Input validation ends, real work begins

        f = lambda x: ord(x[1]) ^ self.__key[x[0] % len(self.__key)]
        self.__mapping[name] = bytearray(map(f, enumerate(data)))

    def get(self, name: str) -> str:
        """Retrieve a stored credential.

        Args:
            name (str): The name of the credential to retrieve.

        Returns:
            str: The decrypted credential data.

        Raises:
            ValueError: If the credential name is not found.
        """
        # Input validation starts
        if not isinstance(name, str):
            raise TypeError(
                f'Credential name must be of type {str},'
                f' found type {type(name)}'
            )

        if len(name) <= 0:
            raise ValueError("Credential name must be a non-empty string")

        if name not in self.__mapping:
            raise ValueError(f'"{name}" is not a known credential')

        # Input validation ends, real work begins

        f = lambda x: x[1] ^ self.__key[x[0] % len(self.__key)]
        plain = bytearray(map(f, enumerate(self.__mapping[name])))
        return plain.decode('utf-8')

    def save(self, filename: str | Path) -> None:
        """Save the credentials to a file.

        Args:
            filename (str | Path): The path to save the credentials file.
        """
        if not filename or not isinstance(filename, (str, Path)):
            raise ValueError(
                f'filename must be a string or a pathlib.Path instance'
            )

        filename = str(filename)

        # We encode the bytearray to base64 to have JSON Serializable data
        # I do not believe this would make the credentials less secure
        data = {
            k: base64.b64encode(v).decode('utf-8')
            for k, v in self.__mapping.items()
        }

        with open(filename, 'w') as f:
            json.dump(data, f)

    @classmethod
    def load(cls, filename: str | Path, password: str) -> 'CredentialsManager':
        """Load credentials from a file.

        Args:
            filename (str | Path): The path to the credentials file.
            password (str): The password to decrypt the credentials.

        Returns:
            CredentialsManager: A new instance with the loaded credentials.

        Raises:
            CredentialsNotFoundError: If the credentials file is not found.
            TypeError: If the file content is not a valid dictionary.
            ValueError: If the file is missing required fields
            IncorrectPasswordError: If the password is incorrect.
        """
        if not filename or not isinstance(filename, (str, Path)):
            raise ValueError(
                f'filename must be a string or a pathlib.Path instance'
            )

        filename = str(filename)

        # Intentionally lose our reference to the password
        # We only care about the hash
        password = hashlib.sha256(password.encode()).hexdigest()
        given_pswd = bytearray(map(ord, password))

        # Open, read and load the file
        try:
            with open(filename) as f:
                data = json.load(f)
        except FileNotFoundError:
            raise CredentialsNotFoundError(filename)

        # Ensure the credentials file is the same format as expected
        if not isinstance(data, dict):
            raise TypeError('Invalid credentials file configuration')

        # These fields are essential, other the data is corrupt
        if '__cm_password__' not in data or '__salt__' not in data:
            raise ValueError(
                'Invalid credentials file. Missing required fields'
            )

        # Extract and decode the mappings from the credentials file
        mappings = {k: bytearray(base64.b64decode(v)) for k, v in data.items()}

        # Ensure the password hashes match
        loaded_pwsd = mappings['__cm_password__']
        if loaded_pwsd != given_pswd:
            raise IncorrectPasswordError('Incorrect password')

        # Passwords should always be decodable, they were SHA-256 digests
        # which are represented as ASCII values, so UTF-8 should have no problems
        password = loaded_pwsd.decode('utf-8')
        salt = mappings['__salt__']

        # We have all the pieces, create a Credential Manager instance
        obj = cls(password=password, salt=salt, pswd_is_digest=True)

        # Set the mappings
        obj.__mapping = mappings

        return obj


def check_credentials():
    """Check if credentials file exists."""
    credentials_path = Path.home() / ".lazy-coder-credentials.json"
    try:
        with Path.open(credentials_path) as json_file:
            return json.load(json_file)
    except FileNotFoundError as err:
        raise CredentialsNotFoundError(credentials_path) from err


# Decorator that loads and provides credentials to the function
# use funcools.wraps to preserve the function name and docstring
def use_credentials(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        credentials = check_credentials()
        return func(credentials, *args, **kwargs)

    return wrapper
