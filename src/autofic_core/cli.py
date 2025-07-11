import click
import json
import time
from pathlib import Path
from rich.console import Console
from pyfiglet import Figlet
from dotenv import load_dotenv

from autofic_core.utils.progress_utils import create_progress
from autofic_core.download.github_repo_handler import GitHubRepoHandler
from autofic_core.sast.semgrep_runner import SemgrepRunner
from autofic_core.sast.semgrep_preprocessor import SemgrepPreprocessor, SemgrepFileSnippet
from autofic_core.sast.semgrep_merger import merge_snippets_by_file
from autofic_core.llm.prompt_generator import PromptGenerator
from autofic_core.llm.llm_runner import LLMRunner, save_md_response
from autofic_core.llm.response_parser import ResponseParser
from autofic_core.patch.diff_generator import DiffGenerator
from autofic_core.patch.apply_patch import PatchApplier
import shutil

load_dotenv()
console = Console()

f = Figlet(font="slant")
ascii_art = f.renderText("AutoFiC")
console.print(f"[magenta]{ascii_art}[/magenta]")

def print_divider(title):
    console.print(f"\n[bold magenta]{'-'*20} [ {title} ] {'-'*20}[/bold magenta]\n")

def print_summary(repo_url: str, detected_issues_count: int, output_dir: str, response_files: list):
    print_divider("AutoFiC 작업 요약")
    console.print(f"✔️ [bold]분석 대상 저장소:[/bold] {repo_url}")
    console.print(f"✔️ [bold]취약점이 탐지된 파일:[/bold] {detected_issues_count} 개")
    if response_files:
        first_file = Path(response_files[0]).name
        last_file = Path(response_files[-1]).name
        console.print(f"✔️ [bold]저장된 응답 파일:[/bold] {first_file} ~ {last_file}")
    else:
        console.print(f"✔️ [bold]저장된 응답 파일:[/bold] 없음")
    console.print(f"\n[bold magenta]{'━'*64}[/bold magenta]\n")

class RepositoryManager:
    def __init__(self, repo_url: str, save_dir: Path):
        self.repo_url = repo_url
        self.save_dir = save_dir
        self.clone_path = None
        self.handler = GitHubRepoHandler(repo_url=self.repo_url)

    def clone(self):
        print_divider("저장소 다운로드 단계")
        if self.handler.needs_fork:
            console.print("\n저장소 Fork 시도 중...\n", style="cyan")
            self.handler.fork()
            time.sleep(1)
            console.print("\n[ SUCCESS ] Fork 완료\n", style="green")
        self.clone_path = Path(self.handler.clone_repo(save_dir=str(self.save_dir), use_forked=self.handler.needs_fork))
        console.print(f"\n[ SUCCESS ] 저장소 클론 완료: {self.clone_path}\n", style="green")

class SASTAnalyzer:
    def __init__(self, repo_path: Path, save_dir: Path, rule: str):
        self.repo_path = repo_path
        self.save_dir = save_dir
        self.rule = rule
        self.result_path = None

    def run(self):
        print_divider("SAST 분석 단계")
        console.print("\nSemgrep 분석 시작\n")
        with create_progress() as progress:
            task = progress.add_task("[cyan]Semgrep 분석 진행 중...", total=100)
            for _ in range(100):
                progress.update(task, advance=1)
                time.sleep(0.01)
            semgrep_runner = SemgrepRunner(repo_path=str(self.repo_path), rule=self.rule)
            semgrep_result_obj = semgrep_runner.run_semgrep()
            progress.update(task, completed=100)
        if semgrep_result_obj.returncode != 0:
            console.print(f"\n[ ERROR ] Semgrep 실행 실패 (리턴 코드: {semgrep_result_obj.returncode})\n", style="red")
            raise RuntimeError("Semgrep 실행 실패")
        sast_dir = self.save_dir / "sast"
        sast_dir.mkdir(parents=True, exist_ok=True)
        self.result_path = sast_dir / "before.json"
        SemgrepPreprocessor.save_json_file(
            json.loads(semgrep_result_obj.stdout),
            self.result_path
        )
        console.print(f"\n[ SUCCESS ] Semgrep 결과 저장 완료 (로그) →  {self.result_path}\n", style="green")
        snippets = SemgrepPreprocessor.preprocess(
            input_json_path=str(self.result_path),
            base_dir=str(self.repo_path)
        )
        merged_snippets = merge_snippets_by_file(snippets)
        merged_path = sast_dir / "merged_snippets.json"
        with open(merged_path, "w", encoding="utf-8") as f:
            json.dump([snippet.model_dump() for snippet in merged_snippets], f, indent=2, ensure_ascii=False)
        console.print(f"[ SUCCESS ] 병합된 스니펫 저장 완료 (로그) → {merged_path}\n", style="green")
        return merged_path

    def save_snippets(self, merged_snippets_path: Path):
        with open(merged_snippets_path, "r", encoding="utf-8") as f:
            merged_snippets = json.load(f)
        snippets_dir = self.save_dir / "snippets"
        snippets_dir.mkdir(parents=True, exist_ok=True)
        for snippet_data in merged_snippets:
            filename_base = snippet_data.get("path", "unknown").replace("/", "_")
            filename = f"snippet_{filename_base}.json"
            path = snippets_dir / filename
            with open(path, "w", encoding="utf-8") as f_out:
                json.dump(snippet_data.get("snippet", ""), f_out, indent=2, ensure_ascii=False)
        console.print(f"[ SUCCESS ] 스니펫 저장 완료 (로그) → {snippets_dir}\n", style="green")

class LLMProcessor:
    def __init__(self, semgrep_result_path: Path, repo_path: Path, save_dir: Path):
        self.semgrep_result_path = semgrep_result_path
        self.repo_path = repo_path
        self.save_dir = save_dir
        self.llm_output_dir = save_dir / "llm"
        self.parsed_dir = save_dir / "parsed"

    def run(self):
        print_divider("LLM 응답 생성 단계")
        prompt_generator = PromptGenerator()
        file_snippets = SemgrepPreprocessor.preprocess(str(self.semgrep_result_path), base_dir=str(self.repo_path))
        prompts = prompt_generator.generate_prompts(file_snippets)
        llm = LLMRunner()
        self.llm_output_dir.mkdir(parents=True, exist_ok=True)
        console.print("\nGPT 응답 생성 및 저장 시작\n")
        with create_progress() as progress:
            task = progress.add_task("[magenta]LLM 응답 중...", total=len(prompts))
            for p in prompts:
                response = llm.run(p.prompt)
                save_md_response(response, p, output_dir=self.llm_output_dir)
                progress.update(task, advance=1)
                time.sleep(0.01)
            progress.update(task, completed=100)
        console.print(f"\n[ SUCCESS ] LLM 응답 저장 완료 (로그) → {self.llm_output_dir}\n", style="green")
        return prompts, file_snippets

    def extract_and_save_parsed_code(self):
        print_divider("LLM 응답 코드 추출 및 저장 단계")
        parser = ResponseParser(md_dir=self.llm_output_dir, diff_dir=self.parsed_dir)
        success = parser.extract_and_save_all()
        if success:
            console.print(f"\n[ SUCCESS ] 파싱된 코드 저장 완료 (로그) → {self.parsed_dir}\n", style="green")
        else:
            console.print(f"\n[ WARN ] 파싱된 코드가 없습니다.\n", style="yellow")

class PatchManager:
    def __init__(self, parsed_dir: Path, patch_dir: Path, repo_dir: Path):
        self.parsed_dir = parsed_dir
        self.patch_dir = patch_dir
        self.repo_dir = repo_dir

    def run(self):
        print_divider("Diff 생성 및 패치 적용 단계")
        diff_generator = DiffGenerator(
            repo_dir=self.repo_dir,
            parsed_dir=self.parsed_dir,
            patch_dir=self.patch_dir,
        )
        diff_generator.run()
        console.print(f"\n[ SUCCESS ] Diff 생성 완료 → {self.patch_dir}\n", style="green")
        patch_applier = PatchApplier(patch_dir=self.patch_dir, repo_dir=self.repo_dir)
        failed_files = patch_applier.apply_all()
        if failed_files:
            console.print(f"\n[ WARN ] 일부 패치 적용 실패 발생 → {self.repo_dir}\n", style="yellow")
            for failed in failed_files:
                rel_path = failed.replace(".diff", "")
                parsed_file = self.parsed_dir / rel_path
                repo_file = self.repo_dir / rel_path
                if parsed_file.exists():
                    repo_file.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(parsed_file, repo_file)
                    console.print(f"[ REPLACED ] 패치 실패하여 전체 파일 교체: {rel_path}", style="cyan")
                else:
                    console.print(f"[ SKIP ] parsed 파일 없음: {parsed_file}", style="red")
        else:
            console.print(f"[SUCCESS] 모든 패치 적용 완료 → {self.repo_dir}\n", style="green")

class AutoFiCPipeline:
    def __init__(self, repo_url: str, save_dir: Path, sast: bool, rule: str, llm: bool):
        self.repo_url = repo_url
        self.save_dir = save_dir.expanduser().resolve()
        self.sast = sast
        self.rule = rule
        self.llm = llm
        self.repo_manager = RepositoryManager(self.repo_url, self.save_dir)
        self.sast_analyzer = None
        self.llm_processor = None

    def run(self):
        self.repo_manager.clone()
        semgrep_result_path = None
        if self.sast:
            self.sast_analyzer = SASTAnalyzer(self.repo_manager.clone_path, self.save_dir, self.rule)
            semgrep_result_path = self.sast_analyzer.run()
            self.sast_analyzer.save_snippets(semgrep_result_path)
        if self.llm:
            if not semgrep_result_path:
                raise RuntimeError("LLM 실행 시 SAST 결과 필요")
            self.llm_processor = LLMProcessor(semgrep_result_path, self.repo_manager.clone_path, self.save_dir)
            prompts, file_snippets = self.llm_processor.run()
            self.llm_processor.extract_and_save_parsed_code()
            prompt_generator = PromptGenerator()
            unique_file_paths = prompt_generator.get_unique_file_paths(file_snippets)
            llm_output_dir = self.llm_processor.llm_output_dir
            response_files = sorted([f.name for f in llm_output_dir.glob("response_*.md")])
            print_summary(
                repo_url=self.repo_url,
                detected_issues_count=len(unique_file_paths),
                output_dir=str(llm_output_dir),
                response_files=response_files
            )

@click.command()
@click.option('--explain', is_flag=True, help="AutoFiC 사용 설명서 출력")
@click.option('--repo', required=False, help="분석할 GitHub 저장소 URL (필수)")
@click.option('--save-dir', default="artifacts/downloaded_repo", help="분석 결과 저장 디렉토리")
@click.option('--sast', is_flag=True, help="Semgrep 기반 정적 분석 실행")
@click.option('--rule', default="p/default", help="SAST 수행 시 사용할 Semgrep 룰셋 경로 또는 preset")
@click.option('--llm', is_flag=True, help="LLM을 통한 취약 코드 수정 및 응답 저장")
@click.option('--patch', is_flag=True, help="diff 생성 및 git apply로 패치")
def main(explain, repo, save_dir, sast, rule, llm, patch):
    if explain:
        print_help_message()
        return
    if not repo:
        click.echo(" --repo는 필수입니다!", err=True)
        return
    if llm and not sast:
        click.secho("[ ERROR ] --llm 옵션은 --sast 없이 단독으로 사용할 수 없습니다!", fg="red")
        return
    try:
        pipeline = AutoFiCPipeline(repo, Path(save_dir), sast, rule, llm)
        pipeline.run()
        if patch:
            parsed_dir = Path(save_dir) / "parsed"
            patch_dir = Path(save_dir) / "patch"
            repo_dir = pipeline.repo_manager.clone_path
            patch_manager = PatchManager(parsed_dir, patch_dir, repo_dir)
            patch_manager.run()
    except Exception as e:
        console.print(f"[ ERROR ] {e}", style="red")

if __name__ == "__main__":
    main()
