from __future__ import annotations

from pathlib import Path
from typing import Optional

import click

from autofic_core.pipeline import AutoFiCPipeline


def _echo_cfg(repo_url, save_dir, sast_tool, run_llm, llm_retry, run_patch, run_pr, xsd_path):
    click.echo("AutoFiC - launching pipeline with the following options:\n")
    click.echo(f"  Repo URL       : {repo_url}")
    click.echo(f"  Save dir       : {save_dir}")
    click.echo(f"  SAST tool      : {sast_tool}")
    click.echo(f"  LLM enabled    : {run_llm}   (retry={llm_retry})")
    click.echo(f"  Patch enabled  : {run_patch}")
    click.echo(f"  PR enabled     : {run_pr}")
    click.echo(f"  XSD path       : {xsd_path if xsd_path else '(none)'}")
    click.echo("")


@click.command(context_settings=dict(help_option_names=["-h", "--help"]))
@click.option(
    "--repo",
    "repo_url",
    required=True,
    help="Target GitHub repository URL. e.g., https://github.com/org/project",
)
@click.option(
    "--save-dir",
    type=click.Path(path_type=Path, file_okay=False, dir_okay=True, writable=True),
    default=Path("./artifacts"),
    show_default=True,
    help="Directory to store outputs (snippets, XML, LLM responses, patches).",
)
@click.option(
    "--sast",
    "sast_tool",
    type=click.Choice(["semgrep", "codeql", "snykcode"], case_sensitive=False),
    default="semgrep",
    show_default=True,
    help="Choose SAST tool (legacy style): --sast <semgrep|codeql|snykcode>.",
)
@click.option(
    "--llm/--no-llm",
    "run_llm",
    default=True,
    show_default=True,
    help="Run LLM stage after SAST & XML.",
)
@click.option(
    "--retry",
    "llm_retry",
    is_flag=True,
    default=False,
    help="Use retry directories (retry_llm/retry_parsed/retry_patch).",
)
@click.option(
    "--patch/--no-patch",
    "run_patch",
    default=True,
    show_default=True,
    help="Generate unified diffs and attempt to apply patches.",
)
@click.option(
    "--pr/--no-pr",
    "run_pr",
    default=False,
    show_default=True,
    help="(Reserved) Create a PR automatically. (Not wired in this CLI)",
)
@click.option(
    "--xsd",
    "xsd_path",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    default=None,
    help="Path to custom_context.xsd for XML validation (optional). If omitted, CLI will look for ./custom_context.xsd.",
)
def main(
    repo_url: str,
    save_dir: Path,
    sast_tool: str,
    run_llm: bool,
    llm_retry: bool,
    run_patch: bool,
    run_pr: bool,
    xsd_path: Optional[Path],
) -> None:
    """
    AutoFiC — run pipeline end-to-end (legacy CLI).

    Examples:
      python -m autofic_core.cli --repo https://github.com/org/project --sast semgrep
      python -m autofic_core.cli --repo https://github.com/org/project --sast codeql --no-llm
    """
    # Normalize paths
    save_dir = save_dir.expanduser().resolve()

    # Default XSD at project root (optional)
    if xsd_path is None:
        local_xsd = Path("custom_context.xsd").resolve()
        if local_xsd.exists():
            xsd_path = local_xsd

    _echo_cfg(repo_url, save_dir, sast_tool, run_llm, llm_retry, run_patch, run_pr, xsd_path)

    pipe = AutoFiCPipeline(
        repo_url=repo_url,
        save_dir=save_dir,
        sast=True,                       
        sast_tool=sast_tool.lower(),
        llm=run_llm,
        llm_retry=llm_retry,
        patch=run_patch,
        pr=run_pr,
    )
    pipe.run()


if __name__ == "__main__":
    main()
