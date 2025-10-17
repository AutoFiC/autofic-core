from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from autofic_core.sast.snippet import BaseSnippet


@dataclass
class _Loc:
    path: str
    start: int
    end: int


class CodeQLPreprocessor:
    """
    Normalize CodeQL SARIF-like JSON into BaseSnippet list.

    - Coerces message/bit_trigger to *string* even if input is dict({"text": ...}).
    - Fills BIT fields (trigger/steps/reproduction/severity) heuristically when absent.
    - Extracts source snippet from repository file based on (start,end) lines.
    """

    # ---------------------- public helpers ----------------------
    @staticmethod
    def save_json_file(data: Dict[str, Any], path: Path | str) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    @staticmethod
    def preprocess(json_path: str, repo_root: str) -> List[BaseSnippet]:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return CodeQLPreprocessor._parse(data, Path(repo_root))

    # ---------------------- internal utils ----------------------
    @staticmethod
    def _as_text(val: Any) -> str:
        """
        Normalize CodeQL 'message' objects and other variants to plain string.
        Accepts str / dict / list / None.
        """
        if val is None:
            return ""
        if isinstance(val, str):
            return val
        if isinstance(val, dict):
            # common SARIF shape: {"text": "..."} or {"markdown": "..."}
            for k in ("text", "markdown", "message", "value"):
                if k in val and isinstance(val[k], str):
                    return val[k]
            try:
                return json.dumps(val, ensure_ascii=False)
            except Exception:
                return str(val)
        if isinstance(val, (list, tuple)):
            try:
                return " ".join(CodeQLPreprocessor._as_text(x) for x in val)
            except Exception:
                return str(val)
        return str(val)

    @staticmethod
    def _pick_severity(result: Dict[str, Any], rule: Optional[Dict[str, Any]]) -> str:
        # CodeQL SARIF often uses result.level: "error" | "warning" | "note"
        sev = CodeQLPreprocessor._as_text(result.get("level")).upper()
        if not sev:
            # sometimes rules have severity in properties
            sev = CodeQLPreprocessor._as_text(
                (rule or {}).get("properties", {}).get("problem.severity")
            ).upper()
        # map to common levels
        mapping = {"ERROR": "HIGH", "WARNING": "MEDIUM", "NOTE": "LOW"}
        return mapping.get(sev, sev or "INFO")

    @staticmethod
    def _locations(result: Dict[str, Any]) -> List[_Loc]:
        locs: List[_Loc] = []
        for loc in result.get("locations", []) or []:
            phys = (loc.get("physicalLocation") or {})
            art = (phys.get("artifactLocation") or {})
            uri = art.get("uri") or art.get("uriBaseId") or ""
            region = (phys.get("region") or {})
            start = int(region.get("startLine") or 1)
            end = int(region.get("endLine") or start)
            if uri:
                locs.append(_Loc(path=uri, start=start, end=end))
        # fallback: relatedLocations
        if not locs:
            for loc in result.get("relatedLocations", []) or []:
                phys = (loc.get("physicalLocation") or {})
                art = (phys.get("artifactLocation") or {})
                uri = art.get("uri") or ""
                region = (phys.get("region") or {})
                start = int(region.get("startLine") or 1)
                end = int(region.get("endLine") or start)
                if uri:
                    locs.append(_Loc(path=uri, start=start, end=end))
        return locs

    @staticmethod
    def _resolve_rule(result: Dict[str, Any], rules_by_id: Dict[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        rule_id = result.get("ruleId")
        if rule_id and rule_id in rules_by_id:
            return rules_by_id[rule_id]
        # sometimes index-based rule
        ridx = result.get("ruleIndex")
        if isinstance(ridx, int):
            for rid, rule in rules_by_id.items():
                if rule.get("_index") == ridx:
                    return rule
        return None

    @staticmethod
    def _build_rules_index(run: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        idx: Dict[str, Dict[str, Any]] = {}
        for i, rule in enumerate(run.get("tool", {}).get("driver", {}).get("rules", []) or []):
            rid = rule.get("id") or f"rule_{i}"
            rule["_index"] = i
            idx[str(rid)] = rule
        return idx

    @staticmethod
    def _read_snippet(repo_root: Path, loc: _Loc) -> Tuple[str, int, int]:
        """
        Return (snippet_text, start, end). If file cannot be read, snippet becomes empty string.
        """
        file_path = (repo_root / loc.path).resolve()
        if not file_path.exists():
            # Sometimes URIs are relative to repo root without normalization
            file_path = (repo_root / Path(loc.path.strip("/"))).resolve()
        text = ""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            start = max(1, loc.start)
            end = min(len(lines), max(loc.end, start))
            text = "".join(lines[start - 1 : end])
            return text, start, end
        except Exception:
            return "", loc.start, loc.end

    # ---------------------- main parse ----------------------
    @staticmethod
    def _parse(data: Dict[str, Any], repo_root: Path) -> List[BaseSnippet]:
        snippets: List[BaseSnippet] = []

        runs = data.get("runs") or []
        for run in runs:
            rules_idx = CodeQLPreprocessor._build_rules_index(run)
            results = run.get("results") or []
            for res in results:
                locs = CodeQLPreprocessor._locations(res)
                if not locs:
                    continue

                rule = CodeQLPreprocessor._resolve_rule(res, rules_idx)
                message_str = CodeQLPreprocessor._as_text(res.get("message"))

                # severity
                severity = CodeQLPreprocessor._pick_severity(res, rule)

                # CWE tags if present (very vendor-specific; best-effort)
                cwe: List[str] = []
                rule_tags = (rule or {}).get("properties", {}).get("tags", []) or []
                for t in rule_tags:
                    tstr = CodeQLPreprocessor._as_text(t)
                    if tstr.upper().startswith("CWE-"):
                        cwe.append(tstr)

                # For each location, create a snippet
                for loc in locs:
                    code, start, end = CodeQLPreprocessor._read_snippet(repo_root, loc)

                    # ---- BIT heuristics (string-only) ----
                    bit_trigger = message_str  # use CodeQL message as trigger by default
                    bit_steps: List[str] = []
                    if start == end:
                        bit_steps.append(f"Review line {start} in {loc.path}")
                    else:
                        bit_steps.append(f"Review lines {start}-{end} in {loc.path}")
                    bit_repro = "Inspect the indicated code region and verify unsafe data flow / pattern reported by CodeQL."
                    bit_sev = severity

                    # ---- Build BaseSnippet (all strings for message/BIT) ----
                    sn = BaseSnippet(
                        path=str(loc.path),
                        start_line=int(start),
                        end_line=int(end),
                        severity=str(severity),
                        message=str(message_str),
                        snippet=str(code),
                        cwe=cwe,
                        # BIT
                        bit_trigger=str(bit_trigger),
                        bit_steps=[str(s) for s in bit_steps],
                        bit_reproduction=str(bit_repro),
                        bit_severity=str(bit_sev),
                        tool="codeql",
                        classes=[],
                        references=[],
                        tags=[],
                        sources=["codeql"],
                    )
                    snippets.append(sn)

        return snippets
