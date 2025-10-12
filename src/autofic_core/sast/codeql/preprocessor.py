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
CodeQLPreprocessor: Extracts vulnerability snippets from CodeQL SARIF results.

- Parses SARIF JSON results
- Matches vulnerabilities to code regions
- Generates BaseSnippet objects for downstream processing
"""

import json
import os
from typing import List
from autofic_core.sast.snippet import BaseSnippet


class CodeQLPreprocessor:
    """
    Processes SARIF output from CodeQL and extracts vulnerability information
    into a uniform BaseSnippet format.
    """

    @staticmethod
    def read_json_file(path: str) -> dict:
        """Reads JSON content from the given file path."""
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)

    @staticmethod
    def save_json_file(data: dict, path: str) -> None:
        """Saves the given dictionary as JSON to the specified path."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

    @staticmethod
    def preprocess(input_json_path: str, base_dir: str = ".") -> List[BaseSnippet]:
        """
        Parses CodeQL SARIF results and extracts code snippets for each finding.

        Args:
            input_json_path (str): Path to the SARIF result file.
            base_dir (str): Base path to resolve relative file URIs.

        Returns:
            List[BaseSnippet]: Extracted and structured vulnerability snippets.
        """
        results = CodeQLPreprocessor.read_json_file(input_json_path)

        # Build rule metadata lookup from SARIF tool section
        rule_metadata = {}
        for run in results.get("runs", []):
            for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
                rule_id = rule.get("id")
                if rule_id:
                    rule_metadata[rule_id] = {
                        "cwe": [
                            tag.split("/")[-1].replace("cwe-", "CWE-")
                            for tag in rule.get("properties", {}).get("tags", [])
                            if "cwe-" in tag
                        ],
                        "references": [rule.get("helpUri")] if rule.get("helpUri") else [],
                        "level": (
                            rule.get("defaultConfiguration", {}).get("level")
                            or rule.get("properties", {}).get("problem.severity", "UNKNOWN")
                        )
                    }

        processed: List[BaseSnippet] = []
        snippet_idx = 0

        for run in results.get("runs", []):
            for res in run.get("results", []):
                location = res.get("locations", [{}])[0].get("physicalLocation", {})
                artifact = location.get("artifactLocation", {})
                region = location.get("region", {})

                file_uri = artifact.get("uri", "Unknown")
                full_path = os.path.join(base_dir, file_uri)
                start_line = region.get("startLine", 0)
                end_line = region.get("endLine") or start_line

                rule_id = res.get("ruleId")
                meta = rule_metadata.get(rule_id, {}) if rule_id else {}

                # Normalize severity level
                level = res.get("level") or meta.get("level", "UNKNOWN")
                if isinstance(level, list):
                    level = level[0] if level else "UNKNOWN"
                severity = str(level).upper()

                snippet = ""
                lines = []

                try:
                    if os.path.exists(full_path):
                        with open(full_path, "r", encoding="utf-8") as code_file:
                            lines = code_file.readlines()

                        # Defensive check on line bounds
                        if start_line > len(lines) or start_line < 1:
                            continue

                        raw_snippet = (
                            lines[start_line - 1:end_line]
                            if end_line > start_line
                            else [lines[start_line - 1]]
                        )

                        if all(not line.strip() for line in raw_snippet):
                            continue

                        snippet = "".join(raw_snippet)

                except Exception:
                    continue  # Skip problematic entries silently

                processed.append(BaseSnippet(
                    input="".join(lines),
                    snippet=snippet.strip(),
                    path=file_uri,
                    idx=snippet_idx,
                    start_line=start_line,
                    end_line=end_line,
                    message=res.get("message", {}).get("text", ""),
                    severity=severity,
                    vulnerability_class=[rule_id.split("/", 1)[-1]] if rule_id else [],
                    cwe=meta.get("cwe", []),
                    references=meta.get("references", [])
                ))
                snippet_idx += 1

        return processed