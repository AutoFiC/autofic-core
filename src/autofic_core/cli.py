import click
from autofic_core.app import AutoFiCApp 

SAST_TOOL_CHOICES = ['semgrep', 'codeql', 'snykcode']

@click.command()
@click.option('--explain', is_flag=True, help="Print AutoFiC usage guide.")
@click.option('--repo', required=False, help="Target GitHub repository URL to analyze (required).")
@click.option('--save-dir', required=False, default="artifacts/downloaded_repo", help="Directory to save analysis results.")
@click.option(
    '--sast',
    type=click.Choice(SAST_TOOL_CHOICES, case_sensitive=False),
    required=False,
    help='Select SAST tool to use (choose one of: semgrep, codeql, snykcode).'
)
@click.option('--llm', is_flag=True, help="Run LLM to fix vulnerable code and save responses.")
@click.option('--llm-retry', is_flag=True, help="Re-run LLM for final verification and fixes.")
@click.option('--patch', is_flag=True, help="Generate diffs and apply patches using git.")
@click.option('--pr', is_flag=True, help="Automatically create a pull request.")

def main(explain, repo, save_dir, sast, llm, llm_retry, patch, pr):
    app = AutoFiCApp(
        explain=explain,
        repo=repo,
        save_dir=save_dir,
        sast=sast,
        llm=llm,
        llm_retry=llm_retry,
        patch=patch,
        pr=pr
    )
    app.run()

if __name__ == "__main__":
    main()