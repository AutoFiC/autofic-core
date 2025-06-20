import os
import difflib
from typing import Optional
from pydantic import BaseModel
from pathlib import Path


class DiffResult(BaseModel):
    filename: str
    diff: str
    success: bool
    error: Optional[str] = None
    saved_path: Optional[str] = None


class DiffGenerator:
    def __init__(
        self,
        downloaded_dir: str = "artifacts/downloaded_repo",
        diff_dir: str = "artifacts/diffs",
    ):
        self.downloaded_dir = Path(downloaded_dir)
        self.diff_dir = Path(diff_dir)
        self.diff_dir.mkdir(parents=True, exist_ok=True)

    def generate_diff(self, relative_path: str, modified_code: str) -> DiffResult:
        original_path = self.downloaded_dir / relative_path
        try:
            if not original_path.exists():
                raise FileNotFoundError(f"원본 파일이 존재하지 않습니다: {original_path}")

            original_lines = original_path.read_text(encoding="utf-8").splitlines()
            modified_lines = modified_code.strip().splitlines()

            diff_lines = list(
                difflib.unified_diff(
                    original_lines,
                    modified_lines,
                    fromfile=f"a/{relative_path}",
                    tofile=f"b/{relative_path}",
                    lineterm="",
                )
            )

            diff_text = "\n".join(diff_lines)

            return DiffResult(filename=relative_path, diff=diff_text, success=True)

        except Exception as e:
            return DiffResult(filename=relative_path, diff="", success=False, error=str(e))

    def save_diff(self, result: DiffResult) -> Optional[Path]:
        if not result.success:
            print(f"[ERROR] {result.filename} diff 생성 실패: {result.error}")
            return None

        if not result.diff.strip():
            print(f"[SKIP] {result.filename} : 변경 사항 없음 (diff 생성되지 않음)")
            return None

        flat_name = result.filename.replace("/", "__")
        diff_path = self.diff_dir / f"{flat_name}.diff"
        diff_path.write_text(result.diff, encoding="utf-8")
        result.saved_path = str(diff_path)
        print(f"[SUCCESS] {diff_path.name} diff 저장 완료")
        return diff_path

    def generate_and_save(self, relative_path: str, modified_code: str) -> DiffResult:
        result = self.generate_diff(relative_path, modified_code)
        self.save_diff(result)
        return result


if __name__ == "__main__":
    test_modified_code = """
    const express = require('express');
    const app = express();
    // filename: app.js
    app.get('/', (req, res) => {
        res.send('Hello, world!');
    });
    """

    diff_gen = DiffGenerator()
    diff_gen.generate_and_save("app.js", test_modified_code.strip())

