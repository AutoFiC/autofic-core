import subprocess
from pathlib import Path
import click

class PatchApplier:
    def __init__(self, patch_dir: Path, repo_dir: Path):
        self.patch_dir = patch_dir
        self.repo_dir = repo_dir

    def apply_all(self) -> list:
        patch_files = sorted(self.patch_dir.glob("*.diff"))
        failed_files = []

        if not patch_files:
            click.secho(f"[ WARN ] {self.patch_dir} 에 .diff 파일이 없습니다.", fg="yellow")
            return failed_files

        for patch_file in patch_files:
            result = subprocess.run(
                ["git", "apply", str(patch_file)],
                cwd=self.repo_dir,
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                click.secho(f"[ SUCCESS ] 패치 적용 완료 : {patch_file.name}", fg="green")
            else:
                click.secho(f"[ ERROR ] 패치 적용 실패 : {patch_file.name}", fg="red")
                click.secho(f"{result.stderr}", fg="red")
                failed_files.append(patch_file.name)

        return failed_files