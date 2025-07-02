import click
import json
import time
import os
from dotenv import load_dotenv
from pathlib import Path
from autofic_core.utils.progress_utils import create_progress
from autofic_core.download.github_repo_handler import GitHubRepoHandler
from autofic_core.sast.semgrep_runner import SemgrepRunner
from autofic_core.sast.semgrep_preprocessor import SemgrepPreprocessor
from autofic_core.sast.semgrep_merger import merge_snippets_by_location
from autofic_core.llm.prompt_generator import PromptGenerator
from autofic_core.llm.llm_runner import LLMRunner, save_md_response
from autofic_core.llm.response_parser import ResponseParser
from autofic_core.patch.diff_generator import DiffGenerator
from autofic_core.patch.diff_merger import DiffMerger
from autofic_core.pr_auto.create_yml import AboutYml
from autofic_core.pr_auto.env_encrypt import EnvEncrypy
from autofic_core.pr_auto.pr_procedure import PRProcedure

load_dotenv()

@click.command()
@click.option('--repo', help='GitHub repository URL')
@click.option('--save-dir', default=os.getenv("DOWNLOAD_SAVE_DIR"), help="저장할 디렉토리 경로")
@click.option('--sast', is_flag=True, help='SAST 분석 수행 여부')
@click.option('--rule', default=os.getenv("SEMGREP_RULE"), help='Semgrep 규칙')
def main(repo, save_dir, sast, rule):
    run_cli(repo, save_dir, sast, rule)

def run_cli(repo, save_dir, sast, rule):
    save_dir = Path(save_dir).expanduser().resolve()

    handler = GitHubRepoHandler(repo_url=repo)
    if handler.needs_fork:
        click.secho(f"\n저장소에 대한 Fork를 시도합니다...\n", fg="cyan")
        handler.fork()
        time.sleep(2)
        click.secho(f"\n[ SUCCESS ] 저장소를 성공적으로 Fork 했습니다!\n", fg="green")
    time.sleep(3)
    clone_path = handler.clone_repo(save_dir=str(save_dir), use_forked=handler.needs_fork)
    click.secho(f"\n[ SUCCESS ] 저장소를 {clone_path}에 클론했습니다!\n", fg="green")

    if sast:
        click.echo("\nSemgrep 분석 시작\n")
        with create_progress() as progress:
            task = progress.add_task("[cyan]Semgrep 분석 진행 중...", total=100)
            for _ in range(100):
                progress.update(task, advance=1)
                time.sleep(0.05)

            semgrep_runner = SemgrepRunner(repo_path=clone_path, rule=rule)
            semgrep_result_obj = semgrep_runner.run_semgrep()
            progress.update(task, completed=100)

        if semgrep_result_obj.returncode != 0:
            click.echo(f"\n[ ERROR ] Semgrep 실행 실패 (리턴 코드: {semgrep_result_obj.returncode})\n")
            try:
                err_json = json.loads(semgrep_result_obj.stdout or semgrep_result_obj.stderr)
                click.echo("[ Semgrep 에러 내용 ]")
                for err in err_json.get("errors", []):
                    click.echo(f"- {err.get('message')} (코드: {err.get('code')})")
            except json.JSONDecodeError:
                click.echo("에러 메시지 JSON 파싱 실패 : ")
                click.echo(semgrep_result_obj.stderr or semgrep_result_obj.stdout)
            return

        sast_dir = save_dir / "sast"
        sast_dir.mkdir(parents=True, exist_ok=True)
        semgrep_result_path = sast_dir / "before.json"

        SemgrepPreprocessor.save_json_file(
            json.loads(semgrep_result_obj.stdout),
            semgrep_result_path
        )

        click.secho(f"\n[ SUCCESS ] Semgrep 분석 완료! 결과가 '{semgrep_result_path}'에 저장되었습니다.\n", fg="green")

        processed = SemgrepPreprocessor.preprocess(
            input_json_path=semgrep_result_path,
            base_dir=clone_path
        )
        merged = merge_snippets_by_location(processed)

        prompts_generator = PromptGenerator()
        prompts = prompts_generator.generate_prompts(merged)

        llm = LLMRunner()
        llm_output_dir = save_dir / "llm"
        click.echo("\nGPT 응답 생성 및 저장 시작\n")
        with create_progress() as progress:
            task = progress.add_task("[magenta]LLM 응답 중...", total=len(prompts))
            for p in prompts:
                response = llm.run(p.prompt)
                save_md_response(response, p.snippet, output_dir=llm_output_dir)
                progress.update(task, advance=1)
                time.sleep(0.05)
            progress.update(task, completed=100)

        click.secho(f"\n[ SUCCESS ] GPT 응답이 .md 파일로 저장 완료되었습니다!\n", fg="green")

    # diff 파일 생성
    diff_dir = save_dir / "diff"
    diff_dir.mkdir(parents=True, exist_ok=True)
    parser = ResponseParser(md_dir=llm_output_dir, diff_dir=diff_dir)
    success = parser.extract_and_save_all()
    if success:
        click.secho(f"\n[ SUCCESS ] diff 파일들이 '{diff_dir}'에 생성되었습니다.\n", fg="green")
    else:
        click.secho(f"\n[ ERROR ] diff 파일 생성 중 문제가 발생했습니다.\n", fg="red")
        return

    # diff 병합
    result_dir = save_dir / "result"
    result_dir.mkdir(parents=True, exist_ok=True)

    diff_generator = DiffGenerator(repo_dir=clone_path, diff_dir=diff_dir)
    diffs = diff_generator.load_diffs()
    if not diffs:
        click.secho(f"\n[ WARN ] 적용할 diff 파일이 없습니다.\n", fg="yellow")
        return

    click.echo("\nDiff 병합 및 파일 저장 시작\n")
    diff_merger = DiffMerger(diffs=diffs, clone_path=clone_path, result_path=result_dir)
    diff_merger.merge_all()

    click.secho(f"\n[ SUCCESS ] 병합된 결과가 '{result_dir}'에 저장되었습니다.\n", fg="green")
    
    # PR 자동화
    branch_num = 1
    base_branch = 'main'
    branch_name = "UNKNOWN"
    repo_name = "UNKOWN"
    upstream_owner = "UNKOWN"
    save_dir = save_dir.joinpath('repo')
    repo_url = repo.rstrip('/').replace('.git', '')
    secret_discord = os.getenv('DISCORD_WEBHOOK_URL')
    secret_slack = os.getenv('SLACK_WEBHOOK_URL')
    token = os.getenv('GITHUB_TOKEN')
    user_name = os.getenv('USER_NAME')
    slack_webhook = os.environ.get('SLACK_WEBHOOK_URL')
    discord_webhook = os.environ.get('DISCORD_WEBHOOK_URL')

    # Define PRProcedure class
    pr_procedure = PRProcedure(
        base_branch, repo_name, upstream_owner, 
        save_dir, repo_url, token, user_name
    )
    # Chapter 1
    pr_procedure.post_init()
    repo_name = pr_procedure.repo_name
    upstream_owner = pr_procedure.upstream_owner
    # Chaper 2
    pr_procedure.mv_workdir()
    # Chapter 3
    pr_procedure.check_branch_exists()
    branch_name = pr_procedure.branch_name
    # Chapter 4
    EnvEncrypy(user_name, repo_name, token).webhook_secret_notifier('DISCORD_WEBHOOK_URL', secret_discord)
    EnvEncrypy(user_name, repo_name, token).webhook_secret_notifier('SLACK_WEBHOOK_URL', secret_slack)
    # Chapter 5
    AboutYml().create_pr_yml()
    AboutYml().push_pr_yml(user_name, repo_name, token, branch_name)
    # Chapter 6
    pr_procedure.change_files()
    # Chapter 7
    pr_procedure.current_main_branch()
    # Chapter 8,9
    pr_procedure.generate_pr()
    pr_procedure.create_pr()

if __name__ == '__main__':
    main()
