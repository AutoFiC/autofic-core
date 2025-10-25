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
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional
import textwrap
import json

from autofic_core.sast.snippet import BaseSnippet


@dataclass
class PromptItem:
    """Container passed to LLMRunner and save_md_response."""
    file_path: str
    prompt: str
    meta: Dict[str, str]


class PromptGenerator:
    """
    Generate prompts grouped by file from merged SAST snippets.
    - Respects Team-Atlanta XML if present: `<save_dir>/sast/CUSTOM_CONTEXT.xml`
    - Produces one PromptItem per *file* (aggregating all issues in that file)
    """

    def __init__(self, save_dir: Optional[Path] = None) -> None:
        self.save_dir = Path(save_dir) if save_dir else Path(".")

    # ----------------------------- public API -----------------------------
    def generate_prompts(self, file_snippets: List[BaseSnippet]) -> List[PromptItem]:
        """Group snippets by file and generate prompts."""
        by_file = self._group_by_file(file_snippets)
        xml_path = self._find_custom_context_xml()

        prompts: List[PromptItem] = []
        for file_path, items in by_file.items():
            content = self._render_prompt_for_file(file_path, items, xml_path)
            prompts.append(
                PromptItem(
                    file_path=file_path,
                    prompt=content,
                    meta={"xml_path": str(xml_path) if xml_path else "", "issues_count": str(len(items))},
                )
            )
        return prompts

    def get_unique_file_paths(self, file_snippets: List[BaseSnippet]) -> List[str]:
        """Used by pipeline for summary display."""
        return sorted({sn.path for sn in file_snippets if getattr(sn, "path", None)})

    # ---------------------------- helpers --------------------------------
    def _group_by_file(self, snippets: Iterable[BaseSnippet]) -> Dict[str, List[BaseSnippet]]:
        grouped: Dict[str, List[BaseSnippet]] = {}
        for sn in snippets:
            path = getattr(sn, "path", "") or ""
            grouped.setdefault(path, []).append(sn)
        # stable order by start_line
        for k in grouped:
            grouped[k].sort(key=lambda s: (s.start_line or 0, s.end_line or 0))
        return grouped

    def _find_custom_context_xml(self) -> Optional[Path]:
        """Look for `<save_dir>/sast/CUSTOM_CONTEXT.xml`."""
        candidate = self.save_dir / "sast" / "CUSTOM_CONTEXT.xml"
        return candidate if candidate.exists() else None

    def _issues_section(self, items: List[BaseSnippet]) -> str:
        lines: List[str] = []
        for sn in items:
            sev = sn.bit_severity or sn.severity or "INFO"
            rng = f"{sn.start_line}–{sn.end_line}"
            trig = (sn.bit_trigger or sn.message or "").strip()
            cwe = ", ".join(sn.cwe) if sn.cwe else ""
            cwe_part = f"  (CWE: {cwe})" if cwe else ""
            lines.append(f"- [{sev}] lines {rng} — {trig}{cwe_part}")
        return "\n".join(lines)
    
    def _annotated_snippet(self, items: List[BaseSnippet], orig_code: List[str]) -> str:
        annotated_lines = []
        for sn in items:
            for ln in range(sn.start_line, sn.end_line + 1):
                line_num = ln
                code_line = orig_code[ln - 1].rstrip('\n') if len(orig_code) >= ln else ""
                annots = []
                if getattr(sn, "is_vuln", False):
                    annots.append("@BUG_HERE")
                if getattr(sn, "is_key_cond", False):
                    annots.append("@KEY_CONDITION")
                if getattr(sn, "was_visited", False):
                    annots.append("@VISITED")
                annotation = f" // {', '.join(annots)}" if annots else ""
                annotated_lines.append(f"[{line_num}]: {code_line}{annotation}")
        return "\n".join(annotated_lines)
    
    def _get_code_lines(self, file_path: str) -> List[str]:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return f.readlines()
        except Exception:
            return []

    def _render_prompt_for_file(self, file_path: str, items: List[BaseSnippet], xml_path: Optional[Path]) -> str:
        """
        Compose the final prompt text for a single file.
        Note: Keep instructions crisp for diff-only outputs.
        """
        issues = self._issues_section(items)
        xml_hint = f"\nTeam-Atlanta context XML is available at: {xml_path}\nUse it to confirm BIT (Trigger, Steps, Reproduction, Severity)." if xml_path else ""

        policy = textwrap.dedent("""
            Output policy:
            - Output ONLY unified diff for the repository file(s).
            - Do NOT include code fences, prose, file headers, or explanations.
            - Keep changes minimal, targeted to fix the vulnerabilities.
            - Do NOT change behavior beyond necessary security fixes.
            - Never replace 'http' with 'https' unless explicitly required by the issue.
        """).strip()

        file_intro = textwrap.dedent(f"""
            You are given merged SAST findings for a single file.

            Target file: {file_path}
            Issues:
            {issues}
        """).strip()

        # Optional: provide a tiny JSON with ranges to help a model focus.
        focus_json = {
            "file": file_path,
            "ranges": [{"start": s.start_line, "end": s.end_line, "severity": (s.bit_severity or s.severity or "INFO")}
                       for s in items]
        }

        orig_code_lines = self._get_code_lines(file_path)
    
        annotated_section = self._annotated_snippet(items, orig_code_lines)  # [11]: ... // @BUG_HERE

        prompt = f"""{file_intro}
{xml_hint}

Annotated snippet:
{annotated_section}

Focus hints (JSON):
{json.dumps(focus_json, ensure_ascii=False)}

{policy}
"""
        return prompt