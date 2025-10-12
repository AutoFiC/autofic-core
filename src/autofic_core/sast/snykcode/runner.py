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

"""
SnykCodeRunner is responsible for executing Snyk Code analysis on a given repository path.

It authenticates using the SNYK_TOKEN, locates the Snyk CLI binary (via PATH or custom path),
runs the analysis, and saves the SARIF result as a JSON file.
"""

import subprocess
import shutil
import os
from pathlib import Path
from typing import Optional
from pydantic import BaseModel
import tempfile
from dotenv import load_dotenv
from autofic_core.errors import SnykCodeErrorMessages


load_dotenv()


class SnykCodeResult(BaseModel):
    """Model representing the result of Snyk Code analysis."""
    stdout: str
    stderr: str
    returncode: int
    result_path: Optional[str] = None


class SnykCodeRunner:
    """
    Handles Snyk Code CLI execution and SARIF result saving.

    Args:
        repo_path (Path): The path to the cloned repository to analyze.
    """

    def __init__(self, repo_path: Path):
        self.repo_path = Path(repo_path).resolve()
        self.snyk_token = os.environ.get("SNYK_TOKEN")

    def run_snykcode(self) -> SnykCodeResult:
        """
        Executes the Snyk CLI with 'code test --json' on the target repo.

        Returns:
            SnykCodeResult: Contains stdout, stderr, returncode, and result path.
        """
        snyk_cmd, use_shell, prepend_node = self._resolve_snyk_command()

        if not self.snyk_token:
            raise EnvironmentError(SnykCodeErrorMessages.TOKEN_MISSING)

        self._ensure_config()

        # Set up environment for subprocess
        env = os.environ.copy()
        env["SNYK_TOKEN"] = self.snyk_token

        # Simulate `snyk auth`
        self._ensure_authenticated(snyk_cmd, env)

        valid_exts = {".js", ".jsx", ".ts", ".mjs"}
        target_files = [
            p for p in self.repo_path.rglob("*")
            if p.suffix in valid_exts and p.is_file()
        ]

        if not target_files:
            return SnykCodeResult(
                stdout="",
                stderr=SnykCodeErrorMessages.NO_JS_FILES_FOUND,
                returncode=1
            )
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            for src_file in target_files:
                rel_path = src_file.relative_to(self.repo_path)
                dst_file = temp_path / rel_path
                dst_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src_file, dst_file)
            
            # Build command
            cmd = [snyk_cmd, "code", "test", "--json"] 
            if prepend_node:
                cmd.insert(0, "node")

            try:
                result = subprocess.run(
                    cmd if not use_shell else " ".join(cmd),
                    cwd=temp_path,
                    env=env,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace", 
                    check=False,
                    shell=use_shell
                )

                output_path = self.repo_path / "snyk_result.sarif.json"
                output_path.write_text(result.stdout, encoding="utf-8")

                return SnykCodeResult(
                    stdout=result.stdout,
                    stderr=result.stderr,
                    returncode=result.returncode,
                    result_path=str(output_path)
                )

            except subprocess.CalledProcessError as err:
                return SnykCodeResult(
                    stdout=err.stdout or "",
                    stderr=err.stderr or "",
                    returncode=err.returncode
                )

    def _ensure_authenticated(self, snyk_cmd: str, env: dict) -> None:
        """
        Authenticates with the Snyk CLI using the API token.

        Args:
            snyk_cmd (str): Path to the Snyk CLI command.
            env (dict): Environment variables with the token.
        """
        subprocess.run(
            [snyk_cmd, "config", "set", f"api={self.snyk_token}"],
            env=env,
            cwd=self.repo_path,
            capture_output=True,
            text=True,
            check=False
        )

    def _ensure_config(self) -> None:
        """
        Ensures a .snyk config file exists in the repo directory.
        """
        config_path = self.repo_path / ".snyk"
        if not config_path.exists():
            config_path.write_text("# empty config\n")

    def _resolve_snyk_command(self) -> tuple[str, bool, bool]:
        """
        Locates the Snyk CLI command.

        Priority:
            1. Environment variable SNYK_CMD_PATH
            2. System PATH (snyk, snyk.cmd, snyk.exe)
            3. npm global bin fallback

        Returns:
            tuple: (snyk_path, use_shell_flag, prepend_node_flag)
        """
        # 1. Custom path via env
        env_path = os.getenv("SNYK_CMD_PATH")
        if env_path and Path(env_path).exists():
            return env_path, env_path.endswith(".cmd"), env_path.endswith(".js")

        # 2. Search PATH
        for candidate in ["snyk.cmd", "snyk.exe", "snyk"]:
            path = shutil.which(candidate)
            if path:
                return path, candidate.endswith(".cmd"), False

        # 3. Fallback to npm global bin
        try:
            npm_bin = subprocess.check_output(["npm", "bin", "-g"], text=True).strip()
            for fallback in ["snyk.cmd", "snyk"]:
                fallback_path = Path(npm_bin) / fallback
                if fallback_path.exists():
                    return str(fallback_path), fallback_path.suffix == ".cmd", False
        except Exception:
            pass

        raise FileNotFoundError(SnykCodeErrorMessages.CLI_NOT_FOUND)