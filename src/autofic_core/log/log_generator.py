import datetime
import os
import json
import re
import hashlib
from pathlib import Path
from collections import Counter, defaultdict
from autofic_core.sast.semgrep.preprocessor import SemgrepPreprocessor
from autofic_core.sast.codeql.preprocessor import CodeQLPreprocessor
from autofic_core.sast.snykcode.preprocessor import SnykCodePreprocessor
from autofic_core.sast.snippet import BaseSnippet

class LogGenerator:
    def __init__(self, default_options=None):
        self.default_options = default_options or {}

    def generate_pr_log(self, owner, repo, user_name, repo_url, repo_hash, pr_number):
        today = datetime.datetime.now().isoformat()
        return {
            "date": today,
            "owner": owner,
            "repo": repo,
            "user_name":user_name,
            "repo_url": repo_url,
            "repo_hash": repo_hash,
            "pr_number": pr_number,
            "opened": True,
            "approved": False
        }

    def generate_repo_log(self, save_dir, name, owner, repo_url, sastTool, rerun=False):
        before_json = Path(save_dir) / 'sast' / 'before.json'
        vulnerabilities = 0
        byClass = []      
        
        if sastTool == "semgrep":
            snippets = SemgrepPreprocessor.preprocess(before_json)
        elif sastTool == "codeql":
            snippets = CodeQLPreprocessor.preprocess(before_json)
        elif sastTool == "snykcode":
            snippets = SnykCodePreprocessor.preprocess(before_json)
        else:
            raise ValueError(f"Unknown tool: {sastTool}")

        byClass_counter = Counter()
        for item in snippets:
            if item.vulnerability_class:
                byClass_counter[item.vulnerability_class[0]] += 1
        byClass = [{"type": k, "count": v} for k, v in byClass_counter.items()]
        vulnerabilities = sum(byClass_counter.values())

        analysis_lines = []
        analysis_lines.append("🔧 Security Patch Summary\n")
        analysis_lines.append(f"- SAST Tool: {sastTool.capitalize()}")
        analysis_lines.append(f"- Total vulnerabilities Detected: {vulnerabilities}\n")

        if vulnerabilities > 0:
            analysis_lines.append("| Type | Count |")
            analysis_lines.append("|------|-------|")
            for entry in byClass:
                analysis_lines.append(f"| {entry['type']} | {entry['count']} |")

        # SAST Summary
        analysis_lines.append("📁 File-by-File Summary\n")

        grouped_by_file = defaultdict(list)
        repo_dir = Path(save_dir) / "repo"

        for item in snippets:
            filename = os.path.relpath(item.path, repo_dir).replace("\\", "/")
            grouped_by_file[filename].append(item)

        file_idx = 1
        for filename, items in grouped_by_file.items():
            analysis_lines.append(f"\n### {file_idx}. `{filename}`")
            analysis_lines.append("🔏 SAST Analysis Summary")

            has_cwe = any(item.cwe for item in items)
            has_ref = any(item.references for item in items)

            header = ["Line", "Type", "Level"]
            if has_cwe:
                header.append("CWE")
            if has_ref:
                header.append("Ref")

            analysis_lines.append("| " + " | ".join(header) + " |")
            analysis_lines.append("|" + "|".join(["-" * len(h) for h in header]) + "|")

            for item in items:
                line = str(item.start_line) if item.start_line == item.end_line else f"{item.start_line}~{item.end_line}"
                vuln = item.vulnerability_class[0] if item.vulnerability_class else "N/A"
                level = item.severity.upper() if item.severity else "N/A"
                emoji = {
                    "ERROR": "🛑 ERROR",
                    "WARNING": "⚠️ WARNING",
                    "NOTE": "💡 NOTE"
                }.get(level, level)

                row = [line, vuln, emoji]

                if has_cwe:
                    cwe = item.cwe[0].split(":")[0] if item.cwe else "N/A"
                    row.append(cwe)
                if has_ref:
                    ref = item.references[0] if item.references else ""
                    ref = f"[🔗]({ref})" if ref else ""
                    row.append(ref)

                analysis_lines.append("| " + " | ".join(row) + " |")

            # LLM Summary
            llm_dir = Path(save_dir) / 'llm'
            analysis_lines.append("\n 🤖 LLM Analysis Summary")

            base_filename = filename.replace("/", "_")
            llm_file = llm_dir / f"response_{base_filename}.md"
            if llm_file.exists():
                with open(llm_file, encoding="utf-8") as f:
                    content = f.read().strip()
                if not content:
                    continue

                file_name = llm_file.name.replace("response_", "").replace(".md", "").replace("_", "/")
                analysis_lines.append(f"\n### 📄 `{file_name}`")

                parsed = self.parse_llm_response(content)
                if parsed["Vulnerability"]:
                    analysis_lines.append("#### 🔸 Vulnerability Description")
                    analysis_lines.append(parsed["Vulnerability"])
                if parsed["Recommended Fix"]:
                    analysis_lines.append("#### 🔸 Recommended Fix")
                    analysis_lines.append(parsed["Recommended Fix"])
                if parsed["References"]:
                    analysis_lines.append("#### 🔸 Additional Notes")
                    analysis_lines.append(parsed["References"])
                
            file_idx += 1

        analysis_text = "\n".join(analysis_lines)

        repo_dict = {
            "name": name,
            "owner": owner,
            "repo_url": repo_url,
            "vulnerabilities": vulnerabilities,
            "byClass": byClass,
            "analysis": analysis_text,
            "sastTool": sastTool,
            "rerun": rerun
        }
        repo_dict["repo_hash"] = self.get_repo_hash(repo_dict)
        return repo_dict

    def get_repo_hash(self, repo_dict):
        keys_to_include = ["repo_url", "sastTool", "rerun", "vulnerabilities", "byClass", "analysis"]
        filtered = {k: repo_dict.get(k) for k in keys_to_include}
        hash_input = json.dumps(filtered, sort_keys=True)
        return hashlib.sha256(hash_input.encode()).hexdigest()

    def parse_llm_response(self, content: str) -> dict:
        sections = {
            "Vulnerability": "",
            "Risks": "",
            "Recommended Fix": "",
            "References": ""
        }

        pattern = re.compile(
            r"1\. Vulnerability Description\s*[:：]?\s*(.*?)\s*"
            r"2\. Potential Risk\s*[:：]?\s*(.*?)\s*"
            r"3\. Recommended Fix\s*[:：]?\s*(.*?)\s*"
            r"(?:4\. Final Modified Code.*?\s*)?"
            r"5\. Additional Notes\s*[:：]?\s*(.*)",
            re.DOTALL
        )

        match = pattern.search(content)
        if match:
            sections["Vulnerability"] = match.group(1).strip()
            sections["Risks"] = match.group(2).strip()
            sections["Recommended Fix"] = match.group(3).strip()
            sections["References"] = match.group(4).strip()

        return sections