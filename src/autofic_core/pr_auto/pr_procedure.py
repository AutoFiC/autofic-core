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

"""Contains their functional aliases.
"""
import os
import re
import json
import time
import datetime
import requests
import subprocess
from pydantic import BaseModel
from typing import List, Optional

"""
Pydantic Vulnerability Report Model Structure

- VulnerabilityReport
  - results: List of VulnerabilityItem
    - path: File path
    - start: Start position (dict)
    - end: End position (dict)
    - extra: VulnerabilityExtra
      - message: Description message
      - severity: Severity level
      - metadata: VulnerabilityMeta
        - vulnerability_class: List of vulnerability categories
        - cwe: List of CWE identifiers
        - references: List of reference links
"""

class VulnerabilityMeta(BaseModel):
    """
    Metadata for a single vulnerability.
    - vulnerability_class: List of vulnerability categories (strings)
    - cwe: List of CWE identifiers (strings)
    - references: List of reference links (strings)
    """
    vulnerability_class: Optional[List[str]] = []
    cwe: Optional[List[str]] = []
    references: Optional[List[str]] = []

class VulnerabilityExtra(BaseModel):
    """
    Message, severity, and metadata for a vulnerability.
    - message: Description message
    - severity: Severity level (default: UNKNOWN)
    - metadata: VulnerabilityMeta object
    """
    message: Optional[str] = ""
    severity: Optional[str] = "UNKNOWN"
    metadata: Optional[VulnerabilityMeta] = VulnerabilityMeta()

class VulnerabilityItem(BaseModel):
    """
    An individual vulnerability result item.
    - path: File path where the vulnerability was found
    - start: Start position (e.g., {"line": 10, "col": 2})
    - end: End position (e.g., {"line": 10, "col": 18})
    - extra: VulnerabilityExtra object
    """
    path: Optional[str] = "Unknown"
    start: Optional[dict] = {}
    end: Optional[dict] = {}
    extra: Optional[VulnerabilityExtra] = VulnerabilityExtra()

class VulnerabilityReport(BaseModel):
    """
    Top-level vulnerability report object.
    - results: List of VulnerabilityItem objects
    """
    results: List[VulnerabilityItem] = []

class PRProcedure:
    """
    Handles all modules required for the pull request workflow.
    
    Responsibilities include:
    - Branch management
    - File changes and commit operations
    - Pull request generation to both fork and upstream repositories
    - CI status monitoring and validation
    - Generating PR markdown summaries from vulnerability reports
    """

    def __init__(self, base_branch: str, repo_name: str,
                 upstream_owner: str, save_dir: str, repo_url: str, token: str, user_name: str):
        """
        Initialize PRProcedure with repository and user configuration.

        :param base_branch: The default base branch for PRs (e.g., 'WHS_VULN_DETEC_1', 'WHS_VULN_DETEC_2')
        :param repo_name: The name of the repository
        :param upstream_owner: The original (upstream) repository owner
        :param save_dir: Local directory for repository operations
        :param repo_url: Repository URL
        :param token: GitHub authentication token
        :param user_name: GitHub username (forked owner)
        """
        self.branch_name = f'WHS_VULN_DETEC_{1}'
        self.base_branch = base_branch
        self.repo_name = repo_name
        self.upstream_owner = upstream_owner
        self.save_dir = save_dir
        self.repo_url = repo_url
        self.token = token
        self.user_name = user_name
        
    def post_init(self):
        """
        Post-initialization: Extracts the repo owner and name from the URL if needed.
        Raises RuntimeError for invalid configuration (if user_name not exist in .env).
        """
        if not self.user_name:
            raise RuntimeError
        if self.repo_url.startswith("https://github.com/"):
            parts = self.repo_url[len("https://github.com/"):].split('/')
            if len(parts) >= 2:
                # Extract original repo owner and name
                self.upstream_owner, self.repo_name = parts[:2]
            else:
                raise RuntimeError("Invalid repo URL")
        else:
            raise RuntimeError("Not a github.com URL")
    
    def mv_workdir(self, save_dir: str = None):
        """
        Move the working directory to the repository clone directory.
        """
        os.chdir(save_dir or self.save_dir)
    
    def check_branch_exists(self):
        """
        Checks for existing branches with 'WHS_VULN_DETEC_N' pattern, used by regular expression.
        Determines next available number, creates and checks out new branch.
        """
        branches = subprocess.check_output(['git', 'branch', '-r'], encoding='utf-8')
        prefix = "origin/WHS_VULN_DETEC_"
        nums = [
            int(m.group(1))
            for m in re.finditer(rf"{re.escape(prefix)}(\d+)", branches)
        ]
        if nums:
            next_num = max(nums) + 1
        else:
            next_num = 1
        self.branch_name = f'WHS_VULN_DETEC_{next_num}'
        subprocess.run(['git', 'checkout', '-b', self.branch_name], check=True)
    
    def change_files(self):
        """
        Simulates file changes (for demo: creates a dummy file and stages it) -> test.txt.
        Loads a Semgrep JSON result and commits with a summary message.
        Pushes the branch to the fork.
        If diff generator implemented, workflow_filename need to change '.'
        """
        workflow_filename = 'test.txt'
        workflow_content = "Codes is Modified!!!"
        with open(workflow_filename, 'w', encoding='utf-8') as f:
            f.write(workflow_content)
        subprocess.run(['git', 'add', workflow_filename], check=True)

        self.json_path = '../sast/before.json'
        with open(self.json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        subprocess.run(['git', 'commit', '-m', f"[Autofic] {len(data.get('results', []))} malicious code detected!!"], check=True)
        try:
            subprocess.run(['git', 'push', 'origin', self.branch_name], check=True)
            return True
        except subprocess.CalledProcessError as e:
            return False
    
    def current_main_branch(self):
        """
        Determines the main branch name ('main', 'master', or other).
        Basic branch is almost both main and master.
        But if both branche not exist, specify first branch.
        """
        branches = subprocess.check_output(['git', 'branch', '-r'], encoding='utf-8')
        if f'origin/main' in branches:
            self.base_branch = 'main'
        elif f'origin/master' in branches:
            self.base_branch = 'master'
        else:
            self.base_branch = branches[0].split('/')[-1]
            
    def generate_pr(self):
        """
        Creates a pull request on the fork repository.
        Uses vulnerability scan results (by semgrep) to generate a detailed PR body.
        If llm_generator implemented, then pr_body will add llm_result.
        """
        print(f"[INFO] Creating PR on {self.user_name}/{self.repo_name}. base branch: {self.base_branch}")
        pr_url = f"https://api.github.com/repos/{self.user_name}/{self.repo_name}/pulls"
        pr_body = self.generate_markdown(self.json_path)
        data_post = {
            "title": f"[Autofic] Security Patch {datetime.datetime.now().strftime('%Y-%m-%d')}",
            "head": f"{self.user_name}:{self.branch_name}",
            "base": self.base_branch,
            "body": pr_body
        }
        headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github+json"
        }
        pr_resp = requests.post(pr_url, json=data_post, headers=headers)
        if pr_resp.status_code in (201, 202):
            time.sleep(0.05)
            return True
        else:
            return False
    
    def create_pr(self):
        """
        After PR is opened on fork, waits for CI to pass and then automatically creates a PR to the upstream repository.
        """
        # Step 1. Find latest open PR on fork
        prs_url = f"https://api.github.com/repos/{self.user_name}/{self.repo_name}/pulls"
        headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github+json"
        }
        prs_resp = requests.get(prs_url, headers=headers, params={"state": "open", "per_page": 1, "sort": "created", "direction": "desc"})
        prs = prs_resp.json()
        if not prs:
            return
        recent_pr = prs[0]
        pr_number = recent_pr["number"]
        self.pr_branch = recent_pr["head"]["ref"]

        # Step 2. Find Actions run_id for that PR
        runs_url = f"https://api.github.com/repos/{self.user_name}/{self.repo_name}/actions/runs"
        run_id = None
        for _ in range(60):  # Wait up to 5 minutes
            runs_resp = requests.get(runs_url, headers=headers, params={"event": "pull_request", "per_page": 20})
            runs = runs_resp.json().get("workflow_runs", [])
            for run in runs:
                pr_list = run.get("pull_requests", [])
                if any(pr.get("number") == pr_number for pr in pr_list):
                    run_id = run["id"]
                    break
            if run_id:
                break
            time.sleep(5)
        else:
            return

        # Step 3. Wait until the workflow run completes successfully
        run_url = f"https://api.github.com/repos/{self.user_name}/{self.repo_name}/actions/runs/{run_id}"
        for _ in range(120):  # Wait up to 10 minutes
            run_resp = requests.get(run_url, headers=headers)
            run_info = run_resp.json()
            run_status = run_info.get("status")
            conclusion = run_info.get("conclusion") # This code block will judge whether pr to upstream repo
            if run_status == "completed":
                if conclusion == "success":
                    break
                else:
                    return
            time.sleep(5)
        else:
            return
        
        # Step 4. If all checks pass('success'), create PR to upstream/original repository
        pr_url = f"https://api.github.com/repos/{self.upstream_owner}/{self.repo_name}/pulls"
        pr_body = self.generate_markdown('../sast/before.json')
        data_post = {
            "title": f"[Autofic] Security Patch {datetime.datetime.now().strftime('%Y-%m-%d')}",
            "head": f"{self.user_name}:{self.pr_branch}",
            "base": self.base_branch,
            "body": pr_body
        }
        pr_resp = requests.post(pr_url, json=data_post, headers=headers)
        if pr_resp.status_code in (201, 202):
            pr_json = pr_resp.json()
        else:
            return
            
    def generate_markdown(self, json_path: str) -> str:
        """
        Loads the vulnerability report and generates a markdown summary
        for the PR body, including details on each finding and fix recommendations.

        :param json_path: Path to the vulnerability report JSON file
        :return: Markdown-formatted string
        """
        with open(json_path, 'r', encoding='utf-8') as f:
            try:
                data = VulnerabilityReport.parse_raw(f.read())
            except Exception:
                f.seek(0)
                data_dict = json.load(f)
                data = VulnerabilityReport(**data_dict)
        md = []
        md.append("## 🛠️ Security Patch Summary\n")
        for idx, item in enumerate(data.results, 1):
            path = item.path.split('/')[-1] or "Unknown"
            start_line = item.start.get("line", "?") if item.start else "?"
            start_col = item.start.get("col", "?") if item.start else "?"
            end_col = item.end.get("col", "?") if item.end else "?"
            extra = item.extra or VulnerabilityExtra()
            message = extra.message or ""
            severity = extra.severity or "UNKNOWN"
            meta = extra.metadata or VulnerabilityMeta()
            vuln_type = ", ".join(meta.vulnerability_class or [])
            cwe = ", ".join(meta.cwe or [])
            ref_link = meta.references[0] if meta.references else ""
            md.append(f"### {idx}. {vuln_type or cwe or 'N/A'} Detected\n")
            md.append(f"- **File:** {path}")
            md.append(f"- **Line:** {start_line} (col {start_col}~{end_col})")
            md.append(f"- **Severity:** {severity}")
            md.append(f"- **Message:** {message}")
            if ref_link:
                md.append(f"- **Reference:** {ref_link}")
        md.append("\n### 💉 Fix Details\n")
        md.append("All vulnerable code paths have been refactored to use parameterized queries or input sanitization as recommended in the references above. Please refer to the diff for exact code changes.\n")
        md.append("---\n")
        return "\n".join(md)