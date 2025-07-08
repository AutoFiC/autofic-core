import re
from pathlib import Path
from typing import List
from pydantic import BaseModel
import click

DIFF_BLOCK_PATTERN = re.compile(r"```(?:diff|[a-z]*)\n(.*?)```", re.DOTALL)
UNIFIED_DIFF_HEADER_PATTERN = re.compile(r"^@@ .*@@", re.MULTILINE)
LINE_NUMBER_PREFIX = re.compile(r"^\d+\s", re.MULTILINE)

class PatchParseResult(BaseModel):
    md_file: Path
    patch_file: Path

class ResponseParser(BaseModel):
    md_dir: Path
    diff_dir: Path

    def extract_and_save_all(self) -> List[PatchParseResult]:
        md_files = list(self.md_dir.glob("*.md"))
        if not md_files:
            click.secho(f"[WARN] {self.md_dir} 에 .md 파일이 없습니다.", fg="yellow")
            return []

        results = []
        for md_file in md_files:
            try:
                result = self.parse_response_and_save_patch(md_file)
                results.append(result)
            except Exception as e:
                click.secho(f"[ERROR] {md_file.name} 처리 실패: {e}", fg="red")

        return results

    def parse_response_and_save_patch(self, md_path: Path) -> PatchParseResult:
        content = md_path.read_text(encoding="utf-8")

        block = self.extract_code_block(content)
        if self.is_unified_diff(block):
            block = self.remove_leading_line_numbers_from_diff_lines(block)

        patch_filename = self.md_name_to_patch_name(md_path.name)
        patch_path = self.diff_dir / patch_filename
        self.save_patch_file(block, patch_path)

        return PatchParseResult(md_file=md_path, patch_file=patch_path)

    @staticmethod
    def extract_code_block(content: str) -> str:
        matches = DIFF_BLOCK_PATTERN.findall(content)
        if not matches:
            raise ValueError("코드 블럭이 없습니다.")
        if len(matches) > 1:
            click.secho("[WARN] 코드 블럭이 2개 이상 발견됨. 첫 번째 블럭만 사용합니다.", fg="yellow")
        return matches[0].strip()

    @staticmethod
    def is_unified_diff(block: str) -> bool:
        return bool(UNIFIED_DIFF_HEADER_PATTERN.search(block))

    @staticmethod
    def remove_leading_line_numbers_from_diff_lines(diff_content: str) -> str:
        """
        diff 내부 줄 시작에 붙은 숫자+공백 제거
        (예: '10  - some code' -> '- some code')
        """
        lines = diff_content.splitlines()
        cleaned_lines = [LINE_NUMBER_PREFIX.sub("", line) for line in lines]
        return "\n".join(cleaned_lines)

    @staticmethod
    def md_name_to_patch_name(md_filename: str) -> str:
        # response_011_core_appHandler.js.md -> patch_011_core_appHandler.js.patch
        stem = Path(md_filename).stem
        if not stem.startswith("response_"):
            raise ValueError(f"[PARSE ERROR] 잘못된 파일명 형식: {md_filename}")
        name = stem[len("response_"):]  # "011_core_appHandler.js"
        return f"patch_{name}.patch"

    # trailing whitespace 제거 & LF 개행으로 저장
    def save_patch_file(self, content: str, output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        lines = content.splitlines()
        cleaned_lines = [line.rstrip() for line in lines]
        cleaned_content = "\n".join(cleaned_lines) + "\n"
        output_path.write_text(cleaned_content, encoding="utf-8", newline="\n")