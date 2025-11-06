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
import os
import re
import json
import time
import datetime
import requests
import subprocess
from pathlib import Path
from typing import List
from rich.console import Console
from collections import defaultdict
import xml.etree.ElementTree as ET

from autofic_core.sast.snippet import BaseSnippet
from autofic_core.sast.semgrep.preprocessor import SemgrepPreprocessor
from autofic_core.sast.codeql.preprocessor import CodeQLPreprocessor
from autofic_core.sast.snykcode.preprocessor import SnykCodePreprocessor

console = Console()

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
                upstream_owner: str, save_dir: str, repo_url: str, token: str, user_name: str, json_path: str, tool: str):
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
        self.json_path = json_path
        self.tool = tool
        
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
        Stages all modified files and commits with a summary message based on vulnerability scan results.
        Pushes the branch to the forked repository.
        """
        with open('../sast/merged_snippets.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
        self.vulnerabilities = len(data)
        
        # Stage all modified/created files except ignored ones
        subprocess.run(['git', 'add', '--all'], check=True)

        # Remove common directories from staging
        ignore_paths = [
            '.codeql-db', '.codeql-results', 'node_modules', '.github', 
            '.snyk', 'snyk_result.sarif.json', '.eslintcache', 'eslint_tmp_env', '.DS_Store'
        ]
        for path in ignore_paths:
            if os.path.exists(path):
                subprocess.run(['git', 'reset', '-q', path], check=False)

        commit_message = f"[ AutoFiC ] {self.vulnerabilities} malicious code detected!!"
        subprocess.run(['git', 'commit', '-m', commit_message], check=True)

        try:
            subprocess.run(['git', 'push', 'origin', self.branch_name], check=True)
            return True
        except subprocess.CalledProcessError:
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
            
    def generate_pr(self) -> str:
        """
        Creates a pull request on the fork repository.
        Uses vulnerability scan results (by semgrep) to generate a detailed PR body.
        If llm_generator implemented, then pr_body will add llm_result.
        """
        console.print(f"[ INFO ] Creating PR on {self.user_name}/{self.repo_name}. Base branch: {self.base_branch}\n", style="white")
        pr_url = f"https://api.github.com/repos/{self.user_name}/{self.repo_name}/pulls"
        if self.tool == "semgrep":
            snippets = SemgrepPreprocessor.preprocess(self.json_path)
        elif self.tool == "codeql":
            snippets = CodeQLPreprocessor.preprocess(self.json_path)
        elif self.tool == "snykcode":
            snippets = SnykCodePreprocessor.preprocess(self.json_path)
        else:
            raise ValueError(f"Unknown tool: {self.tool}")
        pr_body = self.generate_markdown(snippets)
        data_post = {
            "title": f"[ AutoFiC ] Security Patch {datetime.datetime.now().strftime('%Y-%m-%d')}",
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
            pr_json = pr_resp.json()
            time.sleep(0.05) 
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
        
        workflow_file = Path(".github/workflows/pr_notify.yml")
        if workflow_file.exists():
            subprocess.run(['git', 'rm', str(workflow_file)], check=True)
            subprocess.run(['git', 'commit', '-m', "chore: remove CI workflow before upstream PR"], check=True)
            subprocess.run(['git', 'push', 'origin', self.pr_branch], check=True)

        # Step 4. If all checks pass('success'), create PR to upstream/original repository
        pr_url = f"https://api.github.com/repos/{self.upstream_owner}/{self.repo_name}/pulls"
        if self.tool == "semgrep":
            snippets = SemgrepPreprocessor.preprocess(self.json_path)
        elif self.tool == "codeql":
            snippets = CodeQLPreprocessor.preprocess(self.json_path)
        elif self.tool == "snykcode":
            snippets = SnykCodePreprocessor.preprocess(self.json_path)
        pr_body = self.generate_markdown(snippets) 
        data_post = {
            "title": f"[ AutoFiC ] Security Patch {datetime.datetime.now().strftime('%Y-%m-%d')}",
            "head": f"{self.user_name}:{self.pr_branch}",
            "base": self.base_branch,
            "body": pr_body
        }
        pr_resp = requests.post(pr_url, json=data_post, headers=headers)
        if pr_resp.status_code in (201, 202):
            pr_json = pr_resp.json()
            return pr_json.get("number")         
        else:
            return

    def generate_markdown(self, snippets: List[BaseSnippet]) -> str:
        def get_severity_emoji(level: str) -> str:
            level = level.upper()
            return {
                "ERROR": "🛑 ERROR",
                "WARNING": "⚠️ WARNING",
                "NOTE": "💡 NOTE"
            }.get(level, level)

        # Try to load CUSTOM_CONTEXT.xml (Team-Atlanta) generated alongside SAST artifacts
        xml_root = None
        xml_ns = {'c': 'urn:autofic:custom-context'}
        try:
            # save_dir points to cloned repo (…/repo). XML is saved one level above (…/CUSTOM_CONTEXT.xml)
            xml_path = Path(self.save_dir).parent / "CUSTOM_CONTEXT.xml"
            if xml_path.exists():
                xml_root = ET.parse(xml_path).getroot()
        except Exception:
            xml_root = None

        def get_xml_info_for_item(item: BaseSnippet):
            """Return XML-derived details for this snippet if available.
            Keys: cwes (list[str]), bit_severity (str|None), trigger (str|None), steps (list[str]), reproduction (str|None), references (list[str]), preconditions (list[str])
            """
            info = {"cwes": [], "bit_severity": None, "trigger": None, "steps": [], "reproduction": None, "references": [], "preconditions": []}
            if xml_root is None:
                return info
            try:
                for vuln in xml_root.findall('.//c:VULNERABILITY', xml_ns):
                    file_elem = vuln.find('c:FILE', xml_ns)
                    range_elem = vuln.find('c:RANGE', xml_ns)
                    if file_elem is None or range_elem is None:
                        continue
                    xml_path = file_elem.get('path')
                    xml_start = int(range_elem.get('start', 0))
                    if xml_path == item.path and xml_start == item.start_line:
                        # CWEs
                        we = vuln.find('c:WEAKNESSES', xml_ns)
                        if we is not None:
                            info["cwes"] = [cwe.get('id') for cwe in we.findall('c:CWE', xml_ns) if cwe.get('id')]
                        # BIT details
                        bit = vuln.find('c:BIT', xml_ns)
                        if bit is not None:
                            sev_el = bit.find('c:BIT_SEVERITY', xml_ns)
                            trig_el = bit.find('c:TRIGGER', xml_ns)
                            steps_el = bit.find('c:STEPS', xml_ns)
                            repro_el = bit.find('c:REPRODUCTION', xml_ns)
                            info["bit_severity"] = (sev_el.text or '').strip() if sev_el is not None and sev_el.text else None
                            info["trigger"] = (trig_el.text or '').strip() if trig_el is not None and trig_el.text else None
                            if steps_el is not None:
                                info["steps"] = [
                                    (s.text or '').strip() for s in steps_el.findall('c:STEP', xml_ns) if (s.text or '').strip()
                                ]
                            if repro_el is not None and repro_el.text:
                                info["reproduction"] = repro_el.text.strip()

                        # References and Preconditions
                        refs_el = vuln.find('c:REFERENCES', xml_ns)
                        if refs_el is not None:
                            info["references"] = [r.get('href') for r in refs_el.findall('c:REF', xml_ns) if r.get('href')]
                        pre_el = vuln.find('c:PRECONDITIONS', xml_ns)
                        if pre_el is not None:
                            info["preconditions"] = [
                                (p.text or '').strip() for p in pre_el.findall('c:ITEM', xml_ns) if (p.text or '').strip()
                            ]
                        break
            except Exception:
                pass
            return info
        
        def generate_markdown_from_llm(llm_path: str) -> str:
            """
            Parses an LLM-generated markdown response and formats it into a GitHub PR body.

            Expected sections in the markdown file:
            1. Vulnerability Description
            2. Potential Risks
            3. Recommended Fix
            4. Final Patched Code
            5. References
            """
            try:
                with open(llm_path, encoding='utf-8') as f:
                    content = f.read()
            except FileNotFoundError:
                return {
                    "Vulnerability": "",
                    "Risks": "",
                    "Recommended Fix": "",
                    "References": ""
                }
            
            sections = {
                "Vulnerability": "",
                "Risks": "",
                "Recommended Fix": "",
                "References": ""
            }

            # Try strict and relaxed patterns
            patterns = [
                re.compile(
                    r"1\.\s*Vulnerability Description\s*[:：]?\s*(.*?)\s*"
                    r"2\.\s*Potential Risk[s]?\s*[:：]?\s*(.*?)\s*"
                    r"3\.\s*Recommended Fix\s*[:：]?\s*(.*?)\s*"
                    r"(?:4\.\s*Final Modified Code.*?\s*)?"
                    r"5\.\s*(?:Additional Notes|References)\s*[:：]?\s*(.*)",
                    re.DOTALL | re.IGNORECASE,
                ),
                re.compile(
                    r"(?:^|\n)\s*(?:\d+\.\s*)?Vulnerability Description\s*[:：]?\s*(.*?)\s*"
                    r"(?:^|\n)\s*(?:\d+\.\s*)?(?:Potential Risk|Potential Risks)\s*[:：]?\s*(.*?)\s*"
                    r"(?:^|\n)\s*(?:\d+\.\s*)?Recommended Fix\s*[:：]?\s*(.*?)\s*"
                    r"(?:^|\n)\s*(?:\d+\.\s*)?(?:Additional Notes|References)\s*[:：]?\s*(.*)",
                    re.DOTALL | re.IGNORECASE,
                ),
            ]

            match = None
            for pat in patterns:
                m = pat.search(content)
                if m:
                    sections["Vulnerability"], sections["Risks"], sections["Recommended Fix"], sections["References"] = [
                        (g or "").strip() for g in m.groups(default="")[:4]
                    ]
                    match = m
                    break

            # Fallback heuristic using headings (non-numbered)
            if not match:
                def grab_block(label_variants):
                    for label in label_variants:
                        m = re.search(rf"(?:^|\n)\s*#*\s*{re.escape(label)}\s*[:：]?\s*(.*?)(?:\n\s*#|\Z)", content, re.DOTALL | re.IGNORECASE)
                        if m:
                            return m.group(1).strip()
                    return ""

                sections["Vulnerability"] = grab_block(["Vulnerability Description", "Vulnerability"]) or sections["Vulnerability"]
                sections["Recommended Fix"] = grab_block(["Recommended Fix", "Fix"]) or sections["Recommended Fix"]
                sections["Risks"] = grab_block(["Potential Risk", "Potential Risks", "Risk", "Risks"]) or sections["Risks"]
                sections["References"] = grab_block(["Additional Notes", "References"]) or sections["References"]

            return sections

        grouped_by_file = defaultdict(list)
        for item in snippets:
            # item.path is already a relative path like "src/utils/Faiss.py"
            filename = item.path.replace("\\", "/")
            grouped_by_file[filename].append(item)

        md = [
            "## 🔧 About This Pull Request",
            "This patch was automatically created by **[ AutoFiC ](https://autofic.github.io)**,\nan open-source framework that combines **static analysis tools** with **AI-driven remediation**.",
            "\nUsing **Semgrep**, **CodeQL**, and **Snyk Code**, AutoFiC detected potential **security flaws** and applied **verified fixes**.",
            "Each patch includes **contextual explanations** powered by a **large language model** to support **review and decision-making**.",
            "",
            "## 🔐 Summary of Security Fixes",
        ]

        if not grouped_by_file:
            md.append("No vulnerabilities detected. No changes made.\n")
            return "\n".join(md)
        
        md.append("### Overview\n")
        md.append(f"> Detected by: **{self.tool.upper()}**\n")
        md.append("| File | Total Issues | Levels | Top CWE(s) |")
        md.append("|------|---------------|--------|-------------|")

        def _choose_cwes_for_item(item: BaseSnippet, xml_info: dict) -> list:
            snippet_cwes = []
            if getattr(item, 'cwe', None):
                snippet_cwes = [c.split(":")[0] for c in item.cwe if c]
            xml_cwes = xml_info.get("cwes") or []
            if snippet_cwes and xml_cwes:
                inter = sorted(set(snippet_cwes).intersection(set(xml_cwes)))
                return inter if inter else snippet_cwes
            return snippet_cwes or xml_cwes

        for filename, items in grouped_by_file.items():
            levels = {"ERROR": 0, "WARNING": 0, "NOTE": 0}
            cwe_counter = {}
            for it in items:
                lev = (it.severity or '').upper()
                if lev in levels:
                    levels[lev] += 1
                for c in _choose_cwes_for_item(it, get_xml_info_for_item(it)):
                    cwe_counter[c] = cwe_counter.get(c, 0) + 1
            level_str = ", ".join([f"{k[:1]}:{v}" for k, v in levels.items() if v]) or "-"
            top_cwes = ", ".join([c for c, _ in sorted(cwe_counter.items(), key=lambda x: -x[1])[:2]]) or "-"
            md.append(f"| `{filename}` | **{len(items)}** | {level_str} | {top_cwes} |")
        
        file_idx = 1
        for filename, items in grouped_by_file.items():
            md.append(f"### {file_idx}. `{filename}`")

            # BIT Summary (per line)
            md.append("#### 🧷 BIT Summary (per line)")
            md.append("| Line | BIT Level | Trigger | Step |")
            md.append("|------|-----------|---------|------|")
            for it in items:
                xi = get_xml_info_for_item(it)
                # Fill BIT Level from XML; if missing, fall back to snippet severity (to avoid blanks)
                bit_level = get_severity_emoji(xi["bit_severity"]) if xi["bit_severity"] else (
                    get_severity_emoji((it.severity or '').upper()) if it.severity else ""
                )

                # Trigger: take first clause before '|'; if empty, fall back to snippet message first sentence
                trig_raw = xi["trigger"] or ""
                trig = next((p.strip() for p in trig_raw.split("|") if p.strip()), trig_raw.strip()) if trig_raw else ""
                if not trig and getattr(it, 'message', None):
                    # Use the first sentence of the SAST message as a lightweight fallback
                    msg = (it.message or '').strip()
                    trig = msg.split('|', 1)[0].split('\n', 1)[0].split('. ', 1)[0].strip()

                # Step: prefer XML step; otherwise synthesize per-line step
                if xi["steps"]:
                    step = xi["steps"][0]
                else:
                    step = (
                        f"Review line {it.start_line} in {it.path}" 
                        if it.start_line == it.end_line 
                        else f"Review lines {it.start_line}-{it.end_line} in {it.path}"
                    )

                # Sanitize cell contents for markdown tables (escape '|' and newlines)
                def _t(s, n=120):
                    s = (s or '').replace('|', '\\|').replace('\n', ' ').strip()
                    return (s[:n] + '…') if len(s) > n else s

                md.append(f"| {it.start_line} | {bit_level} | {_t(trig)} | {_t(step)} |")

            md.append("#### 🧩 SAST Analysis Summary")
            # Determine availability of CWE and BIT data (from XML if present)
            has_cwe = any((item.cwe or get_xml_info_for_item(item)["cwes"]) for items in grouped_by_file.values() for item in items)
            has_ref = any(item.references for items in grouped_by_file.values() for item in items)
            has_bit = any(get_xml_info_for_item(item)["bit_severity"] for items in grouped_by_file.values() for item in items)

            header = ["Line", "Type", "Level"]
            if has_bit:
                header.append("BIT Level")
            if has_cwe:
                header.append("CWE(s)")
            if has_ref:
                header.append("Ref")
            md.append("| " + " | ".join(header) + " |")
            md.append("|" + "|".join(["-" * len(col) for col in header]) + "|")

            for item in items:
                line_info = f"{item.start_line}" if item.start_line == item.end_line else f"{item.start_line}~{item.end_line}"
                vuln = item.vulnerability_class[0] if item.vulnerability_class else "N/A"
                severity = item.severity.upper() if item.severity else "N/A"
                
                row = [line_info, vuln, get_severity_emoji(severity)]

                # XML-driven BIT severity if available
                xml_info = get_xml_info_for_item(item)
                if has_bit:
                    bit_level = get_severity_emoji(xml_info["bit_severity"]) if xml_info["bit_severity"] else ""
                    row.append(bit_level)

                if has_cwe:
                    # Prefer the intersection of snippet CWEs and XML CWEs to avoid unrelated tags leaking in.
                    # Fallbacks: use snippet CWEs if present; otherwise use XML CWEs.
                    snippet_cwes = []
                    if getattr(item, 'cwe', None):
                        # Normalize entries like "CWE-022: Path Traversal" -> "CWE-022"
                        snippet_cwes = [c.split(":")[0] for c in item.cwe if c]

                    xml_cwes = xml_info["cwes"] if xml_info["cwes"] else []

                    chosen_cwes = []
                    if snippet_cwes and xml_cwes:
                        inter = sorted(set(snippet_cwes).intersection(set(xml_cwes)))
                        chosen_cwes = inter if inter else snippet_cwes
                    elif snippet_cwes:
                        chosen_cwes = snippet_cwes
                    else:
                        chosen_cwes = xml_cwes

                    row.append(", ".join(chosen_cwes) if chosen_cwes else "N/A")
                if has_ref:
                    ref = item.references[0] if item.references else ""
                    ref_link = f"[🔗]({ref})" if ref else ""
                    row.append(ref_link)

                md.append("| " + " | ".join(row) + " |")

            # BIT highlights (Team-Atlanta): concise per-line summary
            try:
                highlights = []
                for item in items:
                    xml_info = get_xml_info_for_item(item)
                    if xml_info["trigger"] or xml_info["steps"] or xml_info["reproduction"]:
                        # Clean up trigger that may contain multiple messages joined by '|'
                        trig_raw = xml_info["trigger"] or ""
                        if "|" in trig_raw:
                            trig_first = next((p.strip() for p in trig_raw.split("|") if p.strip()), trig_raw.strip())
                        else:
                            trig_first = trig_raw.strip()

                        # Prefer XML step, else synthesize per-line step for precision
                        if xml_info["steps"]:
                            step1 = xml_info["steps"][0]
                        else:
                            step1 = f"Review line {item.start_line} in {item.path}" if item.start_line == item.end_line else f"Review lines {item.start_line}-{item.end_line} in {item.path}"

                        repro = (xml_info["reproduction"] or "").strip()

                        def trim(s, n=180):
                            return (s[:n] + '…') if len(s) > n else s
                        parts = []
                        if trig_first:
                            parts.append(f"Trigger: {trim(trig_first)}")
                        if step1:
                            parts.append(f"Steps: {trim(step1)}")
                        if repro:
                            parts.append(f"Repro: {trim(repro)}")
                        if parts:
                            highlights.append(f"- Line {item.start_line}: " + "; ".join(parts))
                if highlights:
                    md.append("\n#### 🧠 BIT Highlights\n")
                    md.extend(highlights)
            except Exception:
                pass

            # Attach LLM analysis for this file (fix scope bug: match against the file of this group)
            try:
                llm_dir = os.path.abspath(os.path.join(self.save_dir, '..', 'llm'))
                target_path = items[0].path if items else None
                if target_path and os.path.isdir(llm_dir):
                    for eachname in os.listdir(llm_dir):
                        if not eachname.endswith('.md'):
                            continue
                        # Extract filename: response_src_utils_Faiss.py.md -> src_utils_Faiss.py
                        base_mdname = eachname[:-3]  # remove .md
                        if base_mdname.startswith("response_"):
                            base_mdname = base_mdname[len("response_"):]
                        # Convert underscores to slashes: src_utils_Faiss.py -> src/utils/Faiss.py
                        llm_target_path = base_mdname.replace("_", "/")
                        
                        # Match against target_path (which is already the full path like src/utils/Faiss.py)
                        if target_path == llm_target_path:
                            llm_path = os.path.join(llm_dir, eachname)
                            llm_summary = generate_markdown_from_llm(llm_path)
                            if llm_summary and any(llm_summary.values()):
                                md.append("\n#### 📝 LLM Analysis\n")
                                if llm_summary["Vulnerability"]:
                                    md.append("**🔸 Vulnerability Description**\n")
                                    md.append(llm_summary["Vulnerability"].strip() + "\n")
                                if llm_summary["Recommended Fix"]:
                                    md.append("**🔸 Recommended Fix**\n")
                                    md.append(llm_summary["Recommended Fix"].strip() + "\n")
                                if llm_summary["References"]:
                                    md.append("**🔸 Additional Notes**\n")
                                    md.append(llm_summary["References"].strip() + "\n")
                            break
            except Exception as e:
                # Debug: log the error if needed
                pass

            # Further Context from XML: References and Preconditions (deduplicated)
            try:
                refs_set = set()
                prec_set = set()
                for it in items:
                    xi = get_xml_info_for_item(it)
                    for r in (xi.get("references") or []):
                        refs_set.add(r)
                    for p in (xi.get("preconditions") or []):
                        prec_set.add(p)
                if refs_set or prec_set:
                    md.append("\n#### 📎 Further Context\n")
                    if refs_set:
                        md.append("- References:")
                        for r in sorted(refs_set):
                            md.append(f"  - [link]({r})")
                    if prec_set:
                        md.append("- Preconditions:")
                        for p in sorted(prec_set):
                            md.append(f"  - {p}")
            except Exception:
                pass

            file_idx += 1

        md.append("\n## 🛠 Fix Summary\n")
        md.append(
            "All identified **vulnerabilities** have been **remediated** following **security best practices** "
            "such as **parameterized queries** and **proper input validation**. "
            "Please refer to the **diff tab** for detailed **code changes**.\n"
        )
        md.append(
            "If you have **questions** or **feedback** regarding this **automated patch**, feel free to reach out via **[AutoFiC GitHub](https://github.com/autofic)**.\n"
        )
        return "\n".join(md)    

    def contains_all(self, text, *keywords):
        """ Check if all keywords are present in the text."""
        return all(k in text for k in keywords)