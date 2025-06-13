import click
import json
import time
from autofic_core.download.github_handler import GitHubRepoHandler
from autofic_core.download.downloader import FileDownloader
from autofic_core.sast.semgrep import SemgrepRunner
from autofic_core.sast.semgrep_preprocessor import SemgrepPreprocessor 
from autofic_core.utils.progress_utils import create_progress

@click.command()
@click.option('--repo', help='GitHub repository URL')
@click.option('--save-dir', default="downloaded_repo", help="저장할 디렉토리 경로")
@click.option('--sast', is_flag=True, help='SAST 분석 수행 여부')
@click.option('--rule', default='p/javascript', help='Semgrep 규칙')
@click.option('--semgrep-result', default="semgrep_result.json", help="Semgrep 원본 결과 경로")

def main(repo, save_dir, sast, rule, semgrep_result):
    run_cli(repo, save_dir, sast, rule, semgrep_result)

def run_cli(repo, save_dir, sast, rule, semgrep_result):
            
    """ GitHub 저장소 분석 """

    click.echo(f"\n저장소 분석 시작: {repo}\n")
    with create_progress() as progress:
        task = progress.add_task("[cyan]파일 탐색 중...", total=100)
        for _ in range(100):
            progress.update(task, advance=1)
            time.sleep(0.05)
        repo_handler = GitHubRepoHandler(repo_url=repo)
        files = repo_handler.get_repo_files()
        progress.update(task, completed=100)
    if not files:
        click.secho("\n[ WARNING ] JS 파일을 찾지 못했습니다. 저장소 또는 GitHub 연결을 확인하세요.\n", fg="yellow")
        return 
    click.secho(f"\n[ SUCCESS ] JS 파일 {len(files)}개를 찾았습니다!\n", fg="green")
        
    """ 파일 다운로드 """

    click.echo(f"다운로드 시작\n")
    results = []
    downloader = FileDownloader(save_dir=save_dir)
    with create_progress() as progress:
        task = progress.add_task("[cyan]파일 다운로드 중...", total=len(files))
        for file in files:
            result = downloader.download_file(file)
            results.append(result)
            progress.update(task, advance=1)
            time.sleep(0.05)
        progress.update(task, completed=100)
    click.echo()
    for r in results:
        if r.status == "success":
            click.secho(f"[ SUCCESS ] {r.path} 다운로드 완료", fg="green")
        elif r.status == "skipped":
            click.secho(f"[ WARNING ] {r.path} 이미 존재함 - 건너뜀", fg="yellow")
        else:
            click.secho(f"[ ERROR ] {r.path} 다운로드 실패: {r.error}", fg="red")

    """ Semgrep 분석  """

    if sast:
        click.echo("\nSemgrep 분석 시작\n")
        with create_progress() as progress:
            task = progress.add_task("[cyan]Semgrep 분석 진행 중...", total=100)
            for _ in range(100):
                progress.update(task, advance=1)
                time.sleep(0.05)
            semgrep_runner = SemgrepRunner(repo_path=save_dir, rule=rule)
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
            
        SemgrepPreprocessor.save_json_file(json.loads(semgrep_result_obj.stdout), semgrep_result)
        click.secho(f"\n[ SUCCESS ] Semgrep 분석 완료! 결과가 '{semgrep_result}'에 저장되었습니다.\n", fg="green")
    
        processed = SemgrepPreprocessor.preprocess(semgrep_result)

        ''' processed 활용해서 이후 개발 '''

if __name__ == '__main__':
    main()