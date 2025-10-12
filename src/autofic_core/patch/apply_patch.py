# =============================================================================
# Copyright 2025 AutoFiC Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# =============================================================================

import subprocess
from pathlib import Path
import shutil
from rich.console import Console
from autofic_core.errors import PatchWarningMessages, PatchErrorMessages, PatchFailMessages

class PatchApplier:
    def __init__(
        self,
        patch_dir: Path,
        repo_dir: Path,
        parsed_dir: Path = None,
        fallback_dir: Path = None,
    ):
        self.patch_dir = Path(patch_dir)
        self.repo_dir = Path(repo_dir)
        self.parsed_dir = Path(parsed_dir) if parsed_dir else self.patch_dir.parent / "parsed"
        self.fallback_dir = Path(fallback_dir) if fallback_dir else self.patch_dir / "fallbacks"
        self.fallback_dir.mkdir(exist_ok=True, parents=True)
        self.console = Console()

    def apply_all(self) -> bool:
        patch_files = sorted(self.patch_dir.glob("*.diff"))

        if not patch_files:
            self.console.print(f"[yellow][ WARN ] No .diff files found in {self.patch_dir}[/yellow]")
            return False

        failed_patches = []

        for patch_file in patch_files:
            success = self.apply_single(patch_file)
            if not success:
                failed_patches.append(patch_file)

        if failed_patches:
            self.console.print(f"[cyan][ INFO ] {len(failed_patches)} patches failed → trying overwrite from parsed (see logs)[/cyan]\n")
            for patch_file in failed_patches:
                self.overwrite_with_parsed(patch_file)

        return True

    def apply_single(self, patch_file: Path) -> bool:
        try:
            result = subprocess.run(
                ["git", "apply", str(patch_file)],
                cwd=self.repo_dir,
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                self.console.print(f"[white][✓] Patch applied: {patch_file.name}[/white]\n")
                return True
            else:
                self.console.print(PatchFailMessages.PATCH_FAILED.format(patch_file.name), style="yellow")
                self.console.print(result.stderr, style="yellow")
                return False

        except Exception as e:
            self.console.print(PatchErrorMessages.PATCH_EXCEPTION.format(patch_file.name, e), style="red")
            return False

    def parsed_diff_apply(self, patch_file: Path) -> bool:
        stem = patch_file.stem.replace("patch_", "")

        matched_file = None
        for file in self.parsed_dir.rglob("*.*"):
            if file.stem == stem:
                matched_file = file
                break

        if not matched_file:
            self.console.print(PatchWarningMessages.PARSED_FILE_NOT_FOUND.format(stem), style="yellow")
            return False

        try:
            relative_path = matched_file.relative_to(self.parsed_dir)
        except ValueError:
            self.console.print(PatchWarningMessages.RELATIVE_PATH_EXTRACTION_FAILED.format(matched_file), style="yellow")
            return False

        original_file = self.repo_dir / relative_path
        parsed_file = self.parsed_dir / relative_path

        if not original_file.exists():
            self.console.print(PatchWarningMessages.ORIGINAL_FILE_MISSING.format(original_file), style="yellow")
            return False

        fallback_diff = self.fallback_dir / f"parsed_{relative_path.with_suffix('.diff').name}"

        try:
            with open(fallback_diff, "w", encoding="utf-8") as f:
                subprocess.run(
                    ["git", "diff", "--no-index", str(original_file), str(parsed_file)],
                    check=True,
                    text=True,
                    stdout=f,
                    stderr=subprocess.DEVNULL,
                )

            result = subprocess.run(
                ["git", "apply", str(fallback_diff)],
                cwd=self.repo_dir,
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                self.console.print(f"[white][✓] Fallback diff applied: {fallback_diff.name}[/white]")
                return True
            else:
                self.console.print(PatchFailMessages.FALLBACK_APPLY_FAILED.format(fallback_diff.name), style="red")
                self.console.print(result.stderr, style="red")
                return False

        except Exception as e:
            self.console.print(PatchErrorMessages.FALLBACK_DIFF_FAILED.format(e), style="red")
            return False

    def overwrite_with_parsed(self, patch_file: Path) -> bool:
        stem = patch_file.stem.replace("patch_", "")

        matched_file = None
        for file in self.parsed_dir.rglob("*.*"):
            if file.stem == stem:
                matched_file = file
                break

        if not matched_file:
            self.console.print(PatchWarningMessages.PARSED_FILE_NOT_FOUND.format(stem), style="yellow")
            return False

        try:
            relative_path = matched_file.relative_to(self.parsed_dir)
        except ValueError:
            self.console.print(PatchWarningMessages.RELATIVE_PATH_EXTRACTION_FAILED.format(matched_file), style="yellow")
            return False

        repo_file = self.repo_dir / relative_path

        if not repo_file.exists():
            self.console.print(PatchWarningMessages.OVERWRITE_FILE_MISSING.format(repo_file), style="yellow")
            return False

        try:
            shutil.copyfile(matched_file, repo_file)
            self.console.print(f"[white][✓] Overwrote repo file: {repo_file}[/white]\n")
            return True
        except Exception as e:
            self.console.print(PatchErrorMessages.OVERWRITE_FAILED.format(e), style="red")
            return False