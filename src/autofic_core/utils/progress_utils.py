from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.style import Style

def create_progress():
    return Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("{task.description}", style=Style(color="cyan", bold=True), justify="left"),
        BarColumn(
            bar_width=55,
            style=Style(color="blue"),
            complete_style=Style(color="bright_blue"),
            finished_style=Style(color="bright_blue", bold=True),
        ),
        TextColumn("{task.percentage:>3.0f}%", style=Style(color="blue", bold=True)),
        transient=False
    )