from pathlib import Path
import re
from typing import List, Dict, Any
import subprocess
import click

class DiffGenerator:
    def __init__(self, repo_dir: Path, diff_dir: Path):
        self.repo_dir = repo_dir
        self.diff_dir = diff_dir

    def parse_patch_filename_to_path(self, diff_filename: str) -> tuple[Path, int]:
        m = re.match(r"patch_(.+)_(\d+)\.patch$", diff_filename)
        if not m:
            click.secho(f"[ ERROR ] 잘못된 diff 파일명 형식: {diff_filename}", fg="red")
            raise ValueError(f"잘못된 diff 파일명 형식: {diff_filename}")
        
        flat_filename = m.group(1)
        line_no = int(m.group(2))

        parts = flat_filename.split("_")
        relative_path = Path(*parts[:-1]) / parts[-1]
        return relative_path, line_no

    def get_patch_files(self) -> List[Path]:
        return list(self.diff_dir.glob("*.patch"))

    def load_patches(self) -> List[Dict[str, Any]]:
        patch_files = self.get_patch_files()
        patches = []

        for patch_file in patch_files:
            try:
                relative_path, line_no = self.parse_patch_filename_to_path(patch_file.name)
                source_path = self.repo_dir / relative_path

                if not source_path.exists():
                    click.secho(f"[ WARN ] 원본 파일이 없습니다: {source_path}", fg="yellow")
                    continue

                patch_content = patch_file.read_text(encoding="utf-8")

                patches.append({
                    "source_path": source_path,
                    "patch_content": patch_content,
                    "patch_path": patch_file,
                    "start_line": line_no,
                })
            except Exception as e:
                click.secho(f"[ ERROR ] patch 파일 처리 실패: {patch_file} - {e}", fg="red")

        return patches

    def apply_patch(self, patch_path: Path) -> bool:
        try:
            result = subprocess.run(
                ["git", "apply", str(patch_path)],
                cwd=self.repo_dir,
                capture_output=True,
                text=True,
                check=False
            )
            if result.returncode != 0:
                click.secho(f"[ ERROR ] patch 적용 실패: {patch_path} - {result.stderr.strip()}", fg="red")
                return False
            click.secho(f"[ SUCCESS ] {patch_path} patch 적용 성공", fg="green")
            return True
        except Exception as e:
            click.secho(f"[ ERROR ] patch 적용 중 예외 발생: {patch_path} - {e}", fg="red")
            return False

    def apply_all_patches(self) -> List[Dict[str, Any]]:
        patches = self.load_patches()
        results = []

        for patch in patches:
            success = self.apply_patch(patch["patch_path"])
            results.append({
                "source_path": patch["source_path"],
                "patch_path": patch["patch_path"],
                "success": success,
            })

        return results