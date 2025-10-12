# Copyright 2025 Autofic Authors. All Rights Reserved.
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

"""Contains their functional aliases.
"""

import subprocess
import os

class Ci_Automate:
    """
    Automates the execution of the Autofic static analysis tool on a list of repositories.
    Each repository URL in REPO_URLS will be processed in sequence.
    """

    def __init__(self):
        # List of repository URLs to process
        self.REPO_URLS = [
            'https://github.com/inyeongjang/corner4'
        ]
        self.save_dir = os.environ.get("RESULT_SAVE_DIR", os.path.abspath("result"))

    def run_autofic(self, repo_url):
        print(f"\n[RUN] {repo_url}")
        cmd = [
            'python', '-m', 'autofic_core.cli',
            '--repo', repo_url,
            '--save-dir', self.save_dir,
            '--sast', 'semgrep',
            '--llm', '--patch',
            '--pr'
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            print(result.stdout)
            print(result.stderr)
        except subprocess.CalledProcessError as e:
            print("=== CalledProcessError ===")
            print("stdout:", e.stdout)
            print("stderr:", e.stderr)
            raise

    def main(self):
        """
        Iterates over all repository URLs and runs the Autofic tool on each one.
        If an exception occurs during processing, an error message is printed for that repository.
        """
        for repo_url in self.REPO_URLS:
            try:
                self.run_autofic(repo_url)
            except Exception as e:
                print(f"[ERROR] {repo_url}: {e}")

if __name__ == "__main__":
    # Entry point: creates a Ci_Automate instance and starts the main automation process.
    Ci_Automate().main()
