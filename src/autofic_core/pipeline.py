import os
import sys
import json
import time
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console
from pyfiglet import Figlet
from uuid import uuid4

from autofic_core.errors import *
from autofic_core.utils.ui_utils import print_divider, print_summary
from autofic_core.utils.progress_utils import create_progress

from autofic_core.download.github_repo_handler import GitHubRepoHandler

from autofic_core.sast.snippet import BaseSnippet
from autofic_core.sast.semgrep.runner import SemgrepRunner
from autofic_core.sast.semgrep.preprocessor import SemgrepPreprocessor
from autofic_core.sast.codeql.runner import CodeQLRunner
from autofic_core.sast.codeql.preprocessor import CodeQLPreprocessor
from autofic_core.sast.snykcode.runner import SnykCodeRunner
from autofic_core.sast.snykcode.preprocessor import SnykCodePreprocessor
from autofic_core.sast.merger import merge_snippets_by_file
# ⬇️ 여기만 변경
from autofic_core.sast.xml_generator import render_custom_context, RenderOptions

from autofic_core.llm.prompt_generator import PromptGenerator
from autofic_core.llm.llm_runner import LLMRunner, save_md_response
from autofic_core.llm.retry_prompt_generator import RetryPromptGenerator
from autofic_core.llm.response_parser import ResponseParser
from autofic_core.patch.apply_patch import PatchApplier

load_dotenv()
console = Console()

f = Figlet(font="slant")
ascii_art = f.renderText("AutoFiC")
console.print(f"\n\n\n[magenta]{ascii_art}[/magenta]")


class RepositoryManager:
    def __init__(self, repo_url: str, save_dir: Path):
        self.repo_url = repo_url
        self.save_dir = save_dir
        self.clone_path = None
        try:
            self.handler = GitHubRepoHandler(repo_url=self.repo_url)
        except (GitHubTokenMissingError, RepoURLFormatError):
            raise

    def clone(self):
        print_divider("Repository Cloning Stage")

        try:
            if self.handler.needs_fork:
                console.print("Attempting to fork the repository...\n", style="cyan")
                self.handler.fork()
                time.sleep(1)
                console.print("[ SUCCESS ] Fork completed\n", style="bold green")

            self.clone_path = Path(
                self.handler.clone_repo(save_dir=str(self.save_dir), use_forked=self.handler.needs_fork)
            )
            console.print(f"[ SUCCESS ] Repository cloned successfully: {self.clone_path}", style="bold green")

        except ForkFailedError:
            sys.exit(1)

        except RepoAccessError:
            raise

        except (PermissionError, OSError) as e:
            raise AccessDeniedError(path=str(self.save_dir), original_error=e)


class SemgrepHandler:
    def __init__(self, repo_path: Path, save_dir: Path):
        self.repo_path = repo_path
        self.save_dir = save_dir

    def run(self):
        description = "Running Semgrep...".ljust(28)
        with create_progress() as progress:
            task = progress.add_task(description, total=100)

            start = time.time()
            runner = SemgrepRunner(repo_path=str(self.repo_path), rule="p/javascript")
            result = runner.run_semgrep()
            end = time.time()

            duration = max(end - start, 0.1)
            step = duration / 100
            for _ in range(100):
                progress.update(task, advance=1)
                time.sleep(step)
            progress.update(task, completed=100)

        if result.returncode != 0:
            raise RuntimeError("Semgrep execution failed")

        return self._post_process(json.loads(result.stdout))

    def _post_process(self, data):
        sast_dir = self.save_dir / "sast"
        sast_dir.mkdir(parents=True, exist_ok=True)
        before_path = sast_dir / "before.json"
        SemgrepPreprocessor.save_json_file(data, before_path)

        snippets = SemgrepPreprocessor.preprocess(str(before_path), str(self.repo_path))
        merged = merge_snippets_by_file(snippets)

        merged_path = sast_dir / "merged_snippets.json"
        with open(merged_path, "w", encoding="utf-8") as f:
            json.dump([s.model_dump() for s in merged], f, indent=2, ensure_ascii=False)

        # Team-Atlanta XML 렌더링 + (선택) XSD 검증
        try:
            xml_out = sast_dir / "CUSTOM_CONTEXT.xml"
            schema_path = Path("schemas/custom_context.xsd").resolve()
            os.environ["AUTOFIC_LAST_SAST_TOOL"] = "semgrep"
            render_custom_context(
                merged_snippets=merged,
                output_path=xml_out,
                schema_path=schema_path if schema_path.exists() else None,
                options=RenderOptions(schema_location="schemas/custom_context.xsd")
            )
            console.print(f"[ SUCCESS ] CUSTOM_CONTEXT.xml generated → {xml_out}", style="bold green")
        except Exception as e:
            console.print(f"[ WARN ] CUSTOM_CONTEXT.xml generation/validation skipped: {e}", style="yellow")

        if not merged:
            console.print("\n[ INFO ] No vulnerabilities found.\n", style="yellow")
            console.print(
                "AutoFiC automation has been halted.--llm, --patch, and --pr stages will not be executed.\n",
                style="yellow",
            )
            return None

        return merged_path


class CodeQLHandler:
    def __init__(self, repo_path: Path, save_dir: Path):
        self.repo_path = repo_path
        self.save_dir = save_dir

    def run(self):
        description = "Running CodeQL...".ljust(28)
        with create_progress() as progress:
            task = progress.add_task(description, total=100)

            start = time.time()
            runner = CodeQLRunner(repo_path=str(self.repo_path))
            result_path = runner.run_codeql()
            end = time.time()

            duration = max(end - start, 0.1)
            step = duration / 100
            for _ in range(100):
                progress.update(task, advance=1)
                time.sleep(step)
            progress.update(task, completed=100)

        with open(result_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return self._post_process(data)

    def _post_process(self, data):
        sast_dir = self.save_dir / "sast"
        sast_dir.mkdir(parents=True, exist_ok=True)
        before_path = sast_dir / "before.json"
        CodeQLPreprocessor.save_json_file(data, before_path)

        snippets = CodeQLPreprocessor.preprocess(str(before_path), str(self.repo_path))
        merged = merge_snippets_by_file(snippets)

        merged_path = sast_dir / "merged_snippets.json"
        with open(merged_path, "w", encoding="utf-8") as f:
            json.dump([s.model_dump() for s in merged], f, indent=2, ensure_ascii=False)

        try:
            xml_out = sast_dir / "CUSTOM_CONTEXT.xml"
            schema_path = Path("schemas/custom_context.xsd").resolve()
            os.environ["AUTOFIC_LAST_SAST_TOOL"] = "codeql"
            render_custom_context(
                merged_snippets=merged,
                output_path=xml_out,
                schema_path=schema_path if schema_path.exists() else None,
                options=RenderOptions(schema_location="schemas/custom_context.xsd")
            )
            console.print(f"[ SUCCESS ] CUSTOM_CONTEXT.xml generated → {xml_out}", style="bold green")
        except Exception as e:
            console.print(f"[ WARN ] CUSTOM_CONTEXT.xml generation/validation skipped: {e}", style="yellow")

        if not merged:
            console.print("\n[ INFO ] No vulnerabilities found.\n", style="yellow")
            console.print(
                "AutoFiC automation has been halted.--llm, --patch, and --pr stages will not be executed.\n",
                style="yellow",
            )
            return None

        return merged_path


class SnykCodeHandler:
    def __init__(self, repo_path: Path, save_dir: Path):
        self.repo_path = repo_path
        self.save_dir = save_dir

    def run(self):
        description = "Running SnykCode...".ljust(28)
        with create_progress() as progress:
            task = progress.add_task(description, total=100)

            start = time.time()
            runner = SnykCodeRunner(repo_path=str(self.repo_path))
            result = runner.run_snykcode()
            end = time.time()

            duration = max(end - start, 0.1)
            step = duration / 100
            for _ in range(100):
                progress.update(task, advance=1)
                time.sleep(step)
            progress.update(task, completed=100)

        return self._post_process(json.loads(result.stdout))

    def _post_process(self, data):
        sast_dir = self.save_dir / "sast"
        sast_dir.mkdir(parents=True, exist_ok=True)
        before_path = sast_dir / "before.json"
        SnykCodePreprocessor.save_json_file(data, before_path)

        snippets = SnykCodePreprocessor.preprocess(str(before_path), str(self.repo_path))
        merged = merge_snippets_by_file(snippets)

        merged_path = sast_dir / "merged_snippets.json"
        with open(merged_path, "w", encoding="utf-8") as f:
            json.dump([s.model_dump() for s in merged], f, indent=2, ensure_ascii=False)

        try:
            xml_out = sast_dir / "CUSTOM_CONTEXT.xml"
            schema_path = Path("schemas/custom_context.xsd").resolve()
            os.environ["AUTOFIC_LAST_SAST_TOOL"] = "snykcode"
            render_custom_context(
                merged_snippets=merged,
                output_path=xml_out,
                schema_path=schema_path if schema_path.exists() else None,
                options=RenderOptions(schema_location="schemas/custom_context.xsd")
            )
            console.print(f"[ SUCCESS ] CUSTOM_CONTEXT.xml generated → {xml_out}", style="bold green")
        except Exception as e:
            console.print(f"[ WARN ] CUSTOM_CONTEXT.xml generation/validation skipped: {e}", style="yellow")

        if not merged:
            console.print("\n[ INFO ] No vulnerabilities found.\n", style="yellow")
            console.print(
                "AutoFiC automation has been halted.--llm, --patch, and --pr stages will not be executed.\n",
                style="yellow",
            )
            return None

        return merged_path


class SASTAnalyzer:
    def __init__(self, repo_path: Path, save_dir: Path, tool: str):
        self.repo_path = repo_path
        self.save_dir = save_dir
        self.tool = tool
        self.result_path = None
        self.handler = self._get_handler()

    def _get_handler(self):
        if self.tool == "semgrep":
            return SemgrepHandler(self.repo_path, self.save_dir)
        elif self.tool == "codeql":
            return CodeQLHandler(self.repo_path, self.save_dir)
        elif self.tool == "snykcode":
            return SnykCodeHandler(self.repo_path, self.save_dir)
        else:
            raise ValueError(f"[ ERROR ] Unsupported SAST tool: {self.tool}")

    def run(self):
        print_divider("SAST Analysis Stage")

        try:
            merged_path = self.handler.run()
            return merged_path
        except Exception as e:
            console.print(f"[ ERROR ] SAST tool [{self.tool}] failed: {e}", style="red")
            raise

    def save_snippets(self, merged_snippets_path: Path):
        with open(merged_snippets_path, "r", encoding="utf-8") as f:
            merged_snippets = json.load(f)

        snippets_dir = self.save_dir / "snippets"
        snippets_dir.mkdir(parents=True, exist_ok=True)

        for snippet_data in merged_snippets:
            if isinstance(snippet_data, dict):
                snippet_obj = BaseSnippet(**snippet_data)
            elif isinstance(snippet_data, BaseSnippet):
                snippet_obj = snippet_data
            else:
                raise TypeError(f"[ ERROR ] Unknown snippet type: {type(snippet_data)}")

            filename_base = snippet_obj.path.replace("\\", "_").replace("/", "_")
            filename = f"snippet_{filename_base}.json"
            path = snippets_dir / filename

            with open(path, "w", encoding="utf-8") as f_out:
                json.dump(snippet_obj.snippet, f_out, indent=2, ensure_ascii=False)


class LLMProcessor:
    def __init__(self, sast_result_path: Path, repo_path: Path, save_dir: Path, tool: str):
        self.sast_result_path = sast_result_path
        self.repo_path = repo_path
        self.save_dir = save_dir
        self.tool = tool
        self.llm_output_dir = save_dir / "llm"
        self.parsed_dir = save_dir / "parsed"
        self.patch_dir = save_dir / "patch"

    def run(self):
        print_divider("LLM Response Generation Stage")

        prompt_generator = PromptGenerator()
        merged_path = self.save_dir / "sast" / "merged_snippets.json"

        with open(merged_path, "r", encoding="utf-8") as f:
            merged_data = json.load(f)
        file_snippets = [BaseSnippet(**item) for item in merged_data]
        prompts = prompt_generator.generate_prompts(file_snippets)
        xml_path = self.save_dir / "sast" / "CUSTOM_CONTEXT.xml"

        if not prompts:
            console.print("[INFO] No valid prompts generated. Skipping LLM stage.\n", style="cyan")
            return [], []

        llm = LLMRunner()
        self.llm_output_dir.mkdir(parents=True, exist_ok=True)

        description = "Generating LLM responses... \n".ljust(28)
        with create_progress() as progress:
            task = progress.add_task(description, total=len(prompts))

            for p in prompts:

                context_meta = {
                    "trace_id": uuid4().hex,
                    "context_xml": str(xml_path),
                    "bit_trigger": getattr(p, "bit_trigger", None),
                    "bit_steps": getattr(p, "bit_steps", None),
                    "bit_reproduction": getattr(p, "bit_reproduction", None),
                    "bit_severity": getattr(p, "bit_severity", None),
                    "constraints": getattr(p, "constraints", None),
                    "kb_template": getattr(p, "kb_template", None)
                }
                
                response = llm.run(p.prompt)
                save_md_response(response, p, output_dir=self.llm_output_dir, context_meta=context_meta)

                progress.update(task, advance=1)
                time.sleep(0.01)
            progress.update(task, completed=100)

        console.print(f"[ SUCCESS ] LLM responses saved → {self.llm_output_dir}", style="bold green")
        return prompts, file_snippets

    def retry(self):
        print_divider("LLM Retry Stage")

        retry_prompt_generator = RetryPromptGenerator(parsed_dir=self.parsed_dir)
        retry_prompts = retry_prompt_generator.generate_prompts()

        console.print("[ RETRY ] Regenerating GPT responses for modified files...\n")

        llm = LLMRunner()
        retry_output_dir = self.save_dir / "retry_llm"
        retry_output_dir.mkdir(parents=True, exist_ok=True)

        console.print("\nStarting GPT retry response generation\n")
        with create_progress() as progress:
            task = progress.add_task("[magenta]Retrying LLM responses...", total=len(retry_prompts))
            for prompt in retry_prompts:
                try:
                    response = llm.run(prompt.prompt)
                    save_md_response(response, prompt, output_dir=retry_output_dir)
                except LLMExecutionError as e:
                    console.print(str(e), style="red")
                finally:
                    progress.update(task, advance=1)
                    time.sleep(0.01)
            progress.update(task, completed=100)

        console.print(f"\n[ SUCCESS ] Retry LLM responses saved → {retry_output_dir}\n", style="bold green")

        return retry_prompts, retry_output_dir

    def extract_and_save_parsed_code(self):
        parser = ResponseParser(md_dir=self.llm_output_dir, diff_dir=self.parsed_dir)

        try:
            success = parser.extract_and_save_all()
        except ResponseParseError as e:
            console.print(str(e), style="red")
            success = False

        if not success:
            console.print(f"\n[ WARN ] No parsable content found in LLM responses.\n", style="yellow")


class PatchManager:
    def __init__(self, parsed_dir: Path, patch_dir: Path, repo_dir: Path):
        self.parsed_dir = parsed_dir
        self.patch_dir = patch_dir
        self.repo_dir = repo_dir

    def run(self):
        print_divider("Diff Generation and Patch Application Stage")

        from autofic_core.patch.diff_generator import DiffGenerator
        diff_generator = DiffGenerator(
            repo_dir=self.repo_dir,
            parsed_dir=self.parsed_dir,
            patch_dir=self.patch_dir,
        )
        diff_generator.run()
        time.sleep(0.1)

        patch_applier = PatchApplier(
            patch_dir=self.patch_dir,
            repo_dir=self.repo_dir,
            parsed_dir=self.parsed_dir,
        )
        success = patch_applier.apply_all()

        if success:
            console.print(f"[ SUCCESS ] All patches successfully applied", style="bold green")
        else:
            console.print(f"\n[ WARN ] Some patches failed to apply → {self.repo_dir}\n", style="yellow")


class AutoFiCPipeline:
    def __init__(self, repo_url: str, save_dir: Path, sast: bool, sast_tool: str,
                 llm: bool, llm_retry: bool, patch: bool, pr: bool):
        self.repo_url = repo_url
        self.save_dir = save_dir.expanduser().resolve()
        self.sast = sast
        self.llm = llm
        self.sast_tool = sast_tool
        self.llm_retry = llm_retry
        self.patch = patch
        self.pr = pr

        self.repo_manager = RepositoryManager(self.repo_url, self.save_dir)
        self.sast_analyzer = None
        self.llm_processor = None

    def run(self):
        self.repo_manager.clone()

        sast_result_path = None
        if self.sast:
            self.sast_analyzer = SASTAnalyzer(
                self.repo_manager.clone_path,
                self.save_dir,
                tool=self.sast_tool,
            )
            sast_result_path = self.sast_analyzer.run()

            if not sast_result_path:
                sys.exit(0)

            self.sast_analyzer.save_snippets(sast_result_path)

        if self.llm:
            if not sast_result_path:
                raise RuntimeError("SAST results are required before running LLM.")

            merged_path = self.save_dir / "sast" / "merged_snippets.json"
            if not merged_path.exists():
                console.print("[ INFO ] No merged_snippets.json file found. Skipping LLM stage.\n", style="cyan")
                sys.exit(0)

            with open(merged_path, "r", encoding="utf-8") as f:
                merged_data = json.load(f)

            self.llm_processor = LLMProcessor(
                sast_result_path, self.repo_manager.clone_path, self.save_dir, self.sast_tool
            )

            try:
                prompts, file_snippets = self.llm_processor.run()
            except LLMExecutionError as e:
                console.print(str(e), style="red")
                sys.exit(1)

            if not prompts:
                console.print(
                    "[ INFO ] No valid prompts returned from LLM processor. Exiting pipeline early.\n",
                    style="cyan",
                )
                sys.exit(0)

            self.llm_processor.extract_and_save_parsed_code()

            prompt_generator = PromptGenerator()
            unique_file_paths = prompt_generator.get_unique_file_paths(file_snippets)

            llm_output_dir = self.llm_processor.llm_output_dir
            response_files = sorted([f.name for f in llm_output_dir.glob("response_*.md")])

            print_summary(
                repo_url=self.repo_url,
                detected_issues_count=len(unique_file_paths),
                output_dir=str(llm_output_dir),
                response_files=response_files,
            )

        if self.patch:
            parsed_dir = self.save_dir / ("retry_parsed" if self.llm_retry else "parsed")
            patch_dir = self.save_dir / ("retry_patch" if self.llm_retry else "patch")

            patch_manager = PatchManager(parsed_dir, patch_dir, self.repo_manager.clone_path)
            patch_manager.run()