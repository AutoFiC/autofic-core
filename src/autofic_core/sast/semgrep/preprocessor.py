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

from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import json

from autofic_core.sast.snippet import BaseSnippet

# Semgrep severity → our canonical
_SEMGR_SEV_MAP = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
}

def _normalize_severity(s: Optional[str]) -> Optional[str]:
    if not s:
        return None
    s = s.strip().upper()
    return _SEMGR_SEV_MAP.get(s, s)

def _safe_get(d: Dict[str, Any], path: List[Union[str, int]], default=None):
    cur: Any = d
    for key in path:
        if isinstance(key, int):
            if not isinstance(cur, list) or key >= len(cur):
                return default
            cur = cur[key]
        else:
            if not isinstance(cur, dict) or key not in cur:
                return default
            cur = cur[key]
    return cur


class SemgrepPreprocessor:
    @staticmethod
    def save_json_file(data: Dict[str, Any], path: Union[str, Path]) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    @staticmethod
    def preprocess(json_path: Union[str, Path], repo_root: Union[str, Path]) -> List[BaseSnippet]:
        with Path(json_path).open("r", encoding="utf-8") as f:
            data = json.load(f)
        return SemgrepPreprocessor._parse(data)

    @staticmethod
    def _parse(data: Dict[str, Any]) -> List[BaseSnippet]:
        results = data.get("results") or []
        out: List[BaseSnippet] = []

        for idx, r in enumerate(results):
            path = r.get("path") or _safe_get(r, ["extra", "path"]) or ""
            start_line = _safe_get(r, ["start", "line"], 0) or 0
            end_line = _safe_get(r, ["end", "line"], start_line) or start_line

            message = _safe_get(r, ["extra", "message"]) or ""
            severity_raw = _safe_get(r, ["extra", "severity"]) or r.get("severity")
            severity = _normalize_severity(severity_raw)

            snippet_text = _safe_get(r, ["extra", "lines"]) or _safe_get(
                r, ["extra", "metavars", "metavar", "abstract_content"]
            )

            rule_id = r.get("check_id") or _safe_get(r, ["extra", "engine_kind"])
            vuln_class: List[str] = []
            if rule_id:
                parts = str(rule_id).split(".")
                vuln_class.append(parts[-1] if len(parts) >= 2 else str(rule_id))

            # CWE / references
            cwe = []
            meta_cwe = _safe_get(r, ["extra", "metadata", "cwe"]) or _safe_get(
                r, ["extra", "metadata", "cwe_ids"]
            ) or []
            if isinstance(meta_cwe, list):
                cwe = [str(x) for x in meta_cwe]
            elif isinstance(meta_cwe, str):
                cwe = [meta_cwe]

            references: List[str] = []
            meta_refs = _safe_get(r, ["extra", "metadata", "references"]) or []
            if isinstance(meta_refs, list):
                references = [str(x) for x in meta_refs]
            elif isinstance(meta_refs, str):
                references = [meta_refs]

            # BIT heuristic
            bit_trigger = message or (vuln_class[0] if vuln_class else None)
            steps = [
                f"Open file `{path}`.",
                f"Go to lines {start_line}–{end_line}.",
            ]
            if message:
                steps.append(f"Observe: {message}")
            if cwe:
                steps.append(f"Related CWE: {', '.join(cwe)}")
            bit_steps = steps
            bit_reproduction = " / ".join(steps)
            bit_severity = severity

            out.append(
                BaseSnippet(
                    input=str(rule_id) if rule_id else "semgrep",
                    idx=idx,
                    path=path,
                    start_line=start_line,
                    end_line=end_line,
                    snippet=(snippet_text or "").strip() or None,
                    message=message,
                    vulnerability_class=vuln_class,
                    cwe=cwe,
                    severity=severity,
                    references=references,
                    bit_trigger=bit_trigger,
                    bit_steps=bit_steps,
                    bit_reproduction=bit_reproduction,
                    bit_severity=bit_severity,
                    constraints={},
                )
            )

        return out