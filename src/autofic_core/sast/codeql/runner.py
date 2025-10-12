# =============================================================================
# Copyright 2025 Autofic Authors. All Rights Reserved.
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
CodeQLRunner: Executes the full CodeQL analysis pipeline.

Steps:
1. Downloads the query pack.
2. Creates a CodeQL database from the source.
3. Runs the analysis and saves the result as a SARIF file.
"""

import subprocess
from pathlib import Path
from autofic_core.errors import CodeQLExecutionError


class CodeQLRunner:
    """
    Executes CodeQL analysis for a given repository.

    Attributes:
        repo_path (Path): Path to the cloned repository.
        language (str): Programming language to analyze (default: "javascript").
        query_pack (str): Query pack path (e.g., "codeql/javascript-queries").
        db_path (Path): Path to the CodeQL database.
        result_dir (Path): Directory for storing analysis results.
        output_path (Path): Path to the generated SARIF report.
        log_path (Path): Path to the log file for subprocess outputs.
    """

    def __init__(self, repo_path: Path, language: str = "javascript"):
        self.repo_path = Path(repo_path).resolve()
        self.language = language.lower()
        self.query_pack = f"codeql/{self.language}-queries"
        self.db_path = self.repo_path / ".codeql-db"
        self.result_dir = self.repo_path / ".codeql-results"
        self.output_path = self.result_dir / "codeql.sarif.json"
        self.log_path = self.result_dir / "codeql.log"

    def _run_cmd(self, cmd: list[str], log_file):
        """
        Executes a shell command and logs its output.

        Args:
            cmd (list[str]): Command and arguments to run.
            log_file: File handle to write stdout and stderr.
        """
        subprocess.run(cmd, check=True, stdout=log_file, stderr=log_file)

    def run_codeql(self) -> Path:
        """
        Runs the full CodeQL analysis pipeline:
        1. Downloads the query pack.
        2. Creates the database from source code.
        3. Analyzes the database and exports SARIF results.

        Returns:
            Path: Path to the resulting SARIF JSON file.

        Raises:
            CodeQLExecutionError: If any subprocess call fails.
        """
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            with self.log_path.open("w") as log_file:
                # Step 1: Ensure query pack is downloaded
                self._run_cmd([
                    "codeql", "pack", "download", self.query_pack
                ], log_file)

                # Step 2: Create a database from the repository
                self._run_cmd([
                    "codeql", "database", "create", str(self.db_path),
                    f"--language={self.language}",
                    "--source-root", str(self.repo_path)
                ], log_file)

                # Step 3: Analyze the database and generate SARIF report
                self._run_cmd([
                    "codeql", "database", "analyze", str(self.db_path),
                    self.query_pack,
                    "--format=sarifv2.1.0",
                    "--output", str(self.output_path)
                ], log_file)

        except subprocess.CalledProcessError:
            raise CodeQLExecutionError()

        return self.output_path