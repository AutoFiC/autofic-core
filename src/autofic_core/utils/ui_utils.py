import time
from urllib.parse import urlparse
from rich.console import Console
from pathlib import Path

console = Console()

def print_divider(title: str):
    diamond = "◆"
    stage = f"[ {title} ]"
    content = f" {diamond} {stage} {diamond} "
    
    total_width = 90
    line_length = (total_width - len(content)) // 2
    line = "━" * line_length
    divider = f"{line}{content}{line}"

    console.print("\n\n" + f"[bold bright_magenta]{divider}[/bold bright_magenta]\n\n")


def extract_repo_name(repo_url: str) -> str:
    parsed = urlparse(repo_url)
    return parsed.path.strip("/").split("/")[-1]

def print_summary(repo_url: str, detected_issues_count: int, output_dir: str, response_files: list):
    print_divider("AutoFiC Summary")

    repo_name = extract_repo_name(repo_url)
    console.print(f"📦 [bold]Target Repository:[/bold] {repo_name}")
    console.print()
    console.print(f"🛡️  [bold]Files with detected vulnerabilities:[/bold] {detected_issues_count} files")
    console.print()
    console.print(f"🤖 [bold]LLM Responses:[/bold] Saved in the 'llm' folder")

    time.sleep(2.0)


def print_help_message():
    console.print("\n\n[blod magenta][ AutoFiC CLI Usage Guide ][/blod magenta]")
    console.print(r"""

✔️ How to use options:

--explain       Display AutoFiC usage guide

--repo          GitHub repository URL to analyze (required)
--save-dir      Directory to save analysis results (required)

--sast          Run SAST analysis using selected tool (semgrep, codeql, snyk)

--llm           Run LLM to fix vulnerable code and save response
--llm-retry     Re-run LLM to verify and finalize code

--patch         Generate diff and apply it to original file

--pr            Pull request the final modified files to both my forked repository and the original repository



※ Example usage:

    [ For Window ]
    ->  python -m autofic_core.cli --repo https://github.com/user/project --save-dir "C:\\Users\Username\\download\\AutoFiCResult" --sast --llm --patch --pr

    [ For Mac ]
    ->  python -m autofic_core.cli --repo https://github.com/user/project --save-dir "/Users/Username/Desktop/AutoFiCResult" --sast semgrep --llm --patch --pr



⚠️ Note:

  - The --save-dir option must be entered as an absolute path.
  - The --sast option must be run before using --llm or --llm-retry options.
  - The --llm and --llm-retry options can only be used with one of them.
  - The --patch option must be run before using --llm or --llm-retry options.
  - The --pr option must be run before using --patch option.
    """)