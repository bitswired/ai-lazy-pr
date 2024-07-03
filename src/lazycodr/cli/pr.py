import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.progress import Progress, SpinnerColumn, TextColumn

from lazycodr.utils.pr import generate_pr, get_pr_diff

console = Console()


app = typer.Typer()


@app.command()
def generate(repo_name: str, pr_number: int):
    pr_template = typer.edit("<Enter PR template here>")
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        for func in (generate_pr, get_pr_diff):
            func.pbar = progress

        progress.add_task(description="Getting diff...", total=None)
        pr_diff = get_pr_diff(repo_name, pr_number)

        progress.add_task(description="Generating PR description...", total=None)
        res = generate_pr(pr_diff, pr_template)

        md = Markdown(res)
        console.print(md, width=90)

        for func in (generate_pr, get_pr_diff):
            func.pbar = None


if __name__ == "__main__":
    app()
