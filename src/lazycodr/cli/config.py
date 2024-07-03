import os
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

from lazycodr.utils.credentials import (
    CredentialsManager,
    IncorrectPasswordError,
)

app = typer.Typer()

console = Console()

CREDENTIALS_FILE = Path.home() / ".lazy-coder-credentials.json"

PSWD_PROMPT: str
CREDENTIALS_EXIST: bool = CREDENTIALS_FILE.exists()

if CREDENTIALS_EXIST:
    PSWD_PROMPT = 'Confirm your password'
else:
    PSWD_PROMPT = (
        'Please setup a password so your credentials can be encrypted\n'
        'Password'
    )


def get_exisiting_cm(password: str) -> Optional[CredentialsManager]:
    try:
        return CredentialsManager.load(CREDENTIALS_FILE, password)
    except (TypeError, ValueError) as e:
        console.print("Oh no! The credentials file is corrupted.",
                      style="bold red")
        console.print(f"Error: {str(e)}")

        os.unlink(str(CREDENTIALS_FILE))
        console.print(
            "For the security of your credentials, it has now been deleted",
            style="bold red"
        )

        console.print(
            "Please recreate your credentials with the following command",
            style="bold green"
        )

        console.print("  lazycodr config credentials", style="bold green")
    except IncorrectPasswordError as e:
        console.print(e.message, style="bold red")

    return None


@app.command()  # type: ignore[misc]
def credentials(  # type: ignore[no-untyped-def]
    openai_api_key: Annotated[str, typer.Option(prompt=True, hide_input=True)],
    github_token: Annotated[str, typer.Option(prompt=True, hide_input=True)],
    password: Annotated[str, typer.Option(prompt=PSWD_PROMPT, hide_input=True)]
):
    if CREDENTIALS_EXIST:
        cm = get_exisiting_cm(password)

        if cm is None:  # password validation failed
            return
    else:
        cm = CredentialsManager(password)

    cm["openai_api_key"] = openai_api_key
    cm["github_token"] = github_token

    cm.save(CREDENTIALS_FILE)

    console.print("Credentials securely saved", style="bold green")


@app.command()  # type: ignore[misc]
def update_password() -> None:
    curr_password: str = ''
    if CREDENTIALS_EXIST:
        for i in range(3):
            if i == 0:
                prompt = 'Enter current password'
            else:
                prompt = f'Enter current password (Attempt {i+1} / 3)'

            curr_password = typer.prompt(prompt, hide_input=True)
            cm = get_exisiting_cm(curr_password)

            if cm is not None:  # password validation success
                break
            # Otherwise retry
        else:  # But not too many times
            console.print("Too many incorrect attempts.", style="bold red")
            raise typer.Abort()
    else:
        console.print('There are no existing passwords to update',
                      style="bold red")

        create = typer.confirm("Would you like to create one?")
        if not create:
            return

    while True:
        new_password = typer.prompt('Enter new password', hide_input=True)
        confirm = typer.prompt('Re-enter new password', hide_input=True)

        if new_password == confirm:
            break

        console.print('Passwords do not match. Retry\n', style="bold red")

    if curr_password != '':  # Current pswd prompt would have updated this
        cm.update_password(curr_password, new_password)  # type: ignore[union-attr]
    else:
        cm = CredentialsManager(new_password)

    cm.save(CREDENTIALS_FILE)  # type: ignore[union-attr]
    console.print("Password updated successfully", style="bold green")


@app.command()  # type: ignore[misc]
def delete_credentials() -> None:
    if not CREDENTIALS_EXIST:
        console.print('There are no credentials to delete', style="bold red")
        return

    delete = typer.confirm("Are you sure you want to delete your credentials?")
    if not delete:
        raise typer.Abort()

    for i in range(3):
        if i == 0:
            prompt = 'Enter your password'
        else:
            prompt = f'Enter your password (Attempt {i+1} / 3)'

        pswd = typer.prompt(prompt, hide_input=True)

        if get_exisiting_cm(pswd) is not None:
            # Password validation success
            # Delete credentials file
            os.unlink(str(CREDENTIALS_FILE))
            console.print('Credentials deleted successfully', style="bold green")
            break

        # Otherwise retry
    else:  # But not too many times
        console.print("Too many incorrect attempts.", style="bold red")
        raise typer.Abort()


if __name__ == "__main__":
    app()
