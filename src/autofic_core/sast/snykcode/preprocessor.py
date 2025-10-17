from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import json
import re

from autofic_core.sast.snippet import BaseSnippet

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

def _map_severity_from_properties(props: Dict[str, Any]) -> Optional[str]:
    cand = None
    for key in ("severity", "problem.severity", "security-severity"):
        if key in (props or {}):
            cand = props[key]
            break
    if cand is None:
        return None
    s = str(cand).strip().upper()
    if s.isdigit():
        n = int(s)
        if n >= 9:
            return "CRITICAL"
        if n >= 7:
            return "HIGH"
        if n >= 4:
            return "MEDIUM"
        if n > 0:
            return "LOW"
        return "INFO"
    if "CRIT" in s:
        return "CRITICAL"
    if "HIGH" in s:
        return "HIGH"
    if "MED" in s:
        return "MEDIUM"
    if "LOW" in s:
        return "LOW"
    if "INFO" in s:
        return "INFO"
    return s

def _extract_cwe_from_tags(tags: List[str]) -> List[str]:
    out: List[str] = []
    for t in tags or []:
        m = re.search(r"cwe[-_/ ]?(\d+)", t, flags=re.I)
        if m:
            out.append(f"CWE-{m.group(1)}")
    # unique preserve order
    seen = set()
    ret = []
    for x in out:
        if x not in seen:
            seen.add(x)
            ret.append(x)
    return ret


class SnykCodePreprocessor:
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
        return SnykCodePreprocessor._parse(data)

    @staticmethod
    def _parse(data: Dict[str, Any]) -> List[BaseSnippet]:
        runs = data.get("runs") or []
        # (optional) build rule index
        rule_index: Dict[str, Dict[str, Any]] = {}
        for run in runs:
            rules = _safe_get(run, ["tool", "driver", "rules"], [])
            for rd in rules or []:
                rid = rd.get("id")
                if rid:
                    rule_index[rid] = rd

        out: List[BaseSnippet] = []
        for run in runs:
            results = run.get("results") or []
            for idx, res in enumerate(results):
                rule_id = res.get("ruleId")
                msg = _safe_get(res, ["message", "text"]) or _safe_get(res, ["message", "markdown"]) or ""

                loc = _safe_get(res, ["locations", 0, "physicalLocation"], {}) or {}
                path = _safe_get(loc, ["artifactLocation", "uri"]) or ""
                region = _safe_get(loc, ["region"], {}) or {}
                start_line = int(region.get("startLine") or 0)
                end_line = int(region.get("endLine") or start_line)
                snippet_text = _safe_get(region, ["snippet", "text"]) or ""

                rule_meta = rule_index.get(rule_id or "", {})
                props_rule = rule_meta.get("properties") or {}
                tags = props_rule.get("tags") or []

                props_res = res.get("properties") or {}
                severity = _map_severity_from_properties(props_res) or _map_severity_from_properties(props_rule)

                help_uri = rule_meta.get("helpUri")
                references: List[str] = []
                if help_uri:
                    references.append(str(help_uri))
                for t in tags:
                    if isinstance(t, str) and t.startswith("external/"):
                        references.append(t)

                cwe = _extract_cwe_from_tags(tags)
                vuln_class = [rule_id] if rule_id else []

                message = msg or _safe_get(rule_meta, ["shortDescription", "text"]) or ""

                # BIT
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
                        input=f"snyk:{rule_id}" if rule_id else "snyk",
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
