from __future__ import annotations

from collections import defaultdict, OrderedDict
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Any, Optional, Iterable, Tuple, Set

# try to import project BaseSnippet; otherwise define a lightweight fallback
try:
    from snippet import BaseSnippet  # type: ignore
except Exception:
    @dataclass
    class BaseSnippet:
        input: str
        idx: Optional[int] = None
        start_line: int = 0
        end_line: int = 0
        snippet: Optional[str] = None
        message: str = ""
        vulnerability_class: List[str] = field(default_factory=list)
        cwe: List[str] = field(default_factory=list)
        severity: str = ""
        references: List[str] = field(default_factory=list)
        path: str = ""
        # optional BIT/extension fields
        bit_trigger: Optional[str] = None
        bit_steps: List[str] = field(default_factory=list)
        bit_reproduction: Optional[str] = None
        bit_severity: Optional[str] = None
        constraints: Dict[str, Any] = field(default_factory=dict)

# severity ranking helper (higher index => more severe)
_SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
_SEVERITY_MAP = {s: i for i, s in enumerate(_SEVERITY_ORDER)}

def _pick_worst_severity(severities: Iterable[str]) -> str:
    """Return the worst (highest) severity among given severities. Unknown are treated as INFO."""
    worst_idx = -1
    worst = ""
    for s in severities:
        if not s:
            idx = 0
        else:
            idx = _SEVERITY_MAP.get(s.upper(), 0)
        if idx > worst_idx:
            worst_idx = idx
            worst = s
    return worst or ""

def are_ranges_overlapping(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    """Return True if two inclusive ranges [a_start,a_end] and [b_start,b_end] overlap or touch."""
    return not (a_end < b_start - 1 or b_end < a_start - 1)

def _unique_preserve_order(items: Iterable[Any]) -> List[Any]:
    seen = set()
    out = []
    for it in items:
        if it is None:
            continue
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out

def _merge_constraints(constraints_list: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Merge a list of constraints dicts. In case of key collision, namespace keys with a suffix:
    original -> original__1, original__2, ...
    """
    merged: Dict[str, Any] = {}
    counts: Dict[str, int] = {}
    for cdict in constraints_list:
        if not cdict:
            continue
        for k, v in cdict.items():
            if k not in merged:
                merged[k] = v
                counts[k] = 1
            else:
                # collision: create a namespaced key
                counts[k] += 1
                merged[f"{k}__{counts[k]}"] = v
    return merged

def merge_group(snippets: List[BaseSnippet]) -> BaseSnippet:
    """
    Merge a list of BaseSnippet-like objects that belong to the same file and overlapping range.
    Returns a new BaseSnippet (instance of the same class if possible).
    """
    if not snippets:
        raise ValueError("merge_group called with empty list")

    # sort by start_line for deterministic output
    snippets_sorted = sorted(snippets, key=lambda s: (getattr(s, "start_line", 0), getattr(s, "end_line", 0)))
    base = snippets_sorted[0]

    path = getattr(base, "path", "")
    start_line = min(getattr(s, "start_line", 0) for s in snippets_sorted)
    end_line = max(getattr(s, "end_line", 0) for s in snippets_sorted)

    # merge textual snippets (preserve order, unique)
    snippet_texts = [getattr(s, "snippet", "") or "" for s in snippets_sorted]
    merged_snippet_text = "\n".join(_unique_preserve_order(snippet_texts)).strip()

    # messages
    messages = [getattr(s, "message", "") or "" for s in snippets_sorted]
    merged_message = " | ".join(_unique_preserve_order(messages))

    # vuln classes, cwe, references
    vuln_classes = []
    cwes = []
    references = []
    inputs = []
    constraints_list = []
    bit_triggers = []
    bit_steps_acc: List[str] = []
    bit_repros = []
    bit_severity_candidates = []
    for s in snippets_sorted:
        vuln_classes.extend(getattr(s, "vulnerability_class", []) or [])
        cwes.extend(getattr(s, "cwe", []) or [])
        references.extend(getattr(s, "references", []) or [])
        inputs.append(getattr(s, "input", ""))
        constraints_list.append(getattr(s, "constraints", {}) or {})
        # BIT fields (may not exist)
        if hasattr(s, "bit_trigger"):
            t = getattr(s, "bit_trigger")
            if t:
                bit_triggers.append(t)
        if hasattr(s, "bit_steps"):
            steps = getattr(s, "bit_steps") or []
            bit_steps_acc.extend(steps)
        if hasattr(s, "bit_reproduction"):
            r = getattr(s, "bit_reproduction")
            if r:
                bit_repros.append(r)
        if hasattr(s, "bit_severity"):
            bs = getattr(s, "bit_severity")
            if bs:
                bit_severity_candidates.append(bs)
        # severity
    merged_vuln_class = _unique_preserve_order(vuln_classes)
    merged_cwe = _unique_preserve_order(cwes)
    merged_references = _unique_preserve_order(references)
    merged_inputs = _unique_preserve_order(inputs)

    merged_constraints = _merge_constraints(constraints_list)
    merged_bit_trigger = " | ".join(_unique_preserve_order(bit_triggers)) if bit_triggers else None
    merged_bit_steps = _unique_preserve_order(bit_steps_acc)
    merged_bit_reproduction = None
    if bit_repros:
        merged_bit_reproduction = " | ".join(_unique_preserve_order(bit_repros))
    merged_bit_severity = _pick_worst_severity(bit_severity_candidates) if bit_severity_candidates else None

    # severity: pick worst among snippet.severity and bit_severity if provided
    severity_candidates = [getattr(s, "severity", "") or "" for s in snippets_sorted]
    # include bit severity candidates too (string)
    severity_candidates.extend([bs for bs in bit_severity_candidates if bs])
    merged_severity = _pick_worst_severity(severity_candidates)

    # build return instance; prefer using the same class as input if possible
    SnippetCls = type(base)
    try:
        merged = SnippetCls(
            input=";".join(merged_inputs),
            idx=None,
            start_line=start_line,
            end_line=end_line,
            snippet=merged_snippet_text,
            message=merged_message,
            vulnerability_class=merged_vuln_class,
            cwe=merged_cwe,
            severity=merged_severity,
            references=merged_references,
            path=path
        )
        # set optional/extension attributes if available
        if hasattr(merged, "bit_trigger"):
            setattr(merged, "bit_trigger", merged_bit_trigger)
        else:
            setattr(merged, "bit_trigger", merged_bit_trigger)
        if hasattr(merged, "bit_steps"):
            setattr(merged, "bit_steps", merged_bit_steps)
        else:
            setattr(merged, "bit_steps", merged_bit_steps)
        if hasattr(merged, "bit_reproduction"):
            setattr(merged, "bit_reproduction", merged_bit_reproduction)
        else:
            setattr(merged, "bit_reproduction", merged_bit_reproduction)
        if hasattr(merged, "bit_severity"):
            setattr(merged, "bit_severity", merged_bit_severity)
        else:
            setattr(merged, "bit_severity", merged_bit_severity)
        if hasattr(merged, "constraints"):
            setattr(merged, "constraints", merged_constraints)
        else:
            setattr(merged, "constraints", merged_constraints)
    except Exception:
        # fallback to the dataclass defined earlier
        merged = BaseSnippet(
            input=";".join(merged_inputs),
            idx=None,
            start_line=start_line,
            end_line=end_line,
            snippet=merged_snippet_text,
            message=merged_message,
            vulnerability_class=merged_vuln_class,
            cwe=merged_cwe,
            severity=merged_severity,
            references=merged_references,
            path=path,
            bit_trigger=merged_bit_trigger,
            bit_steps=merged_bit_steps,
            bit_reproduction=merged_bit_reproduction,
            bit_severity=merged_bit_severity,
            constraints=merged_constraints
        )

    # attach provenance metadata for debugging
    try:
        setattr(merged, "_merged_from_count", len(snippets_sorted))
        setattr(merged, "_merged_sources", merged_inputs)
    except Exception:
        pass

    return merged

def merge_snippets_by_file(snippets: List[BaseSnippet]) -> List[BaseSnippet]:
    """
    Merge a list of BaseSnippet objects across files. Snippets are grouped by path and
    overlapping line ranges are merged into a single snippet.

    Returns a list of merged BaseSnippet objects.
    """
    if not snippets:
        return []

    grouped: Dict[str, List[BaseSnippet]] = defaultdict(list)
    for s in snippets:
        p = getattr(s, "path", "") or ""
        grouped[p].append(s)

    merged_results: List[BaseSnippet] = []
    for path, slist in grouped.items():
        # sort by start_line
        ssorted = sorted(slist, key=lambda x: (getattr(x, "start_line", 0), getattr(x, "end_line", 0)))
        current_group: List[BaseSnippet] = []
        cur_start = None
        cur_end = None
        for s in ssorted:
            s_start = getattr(s, "start_line", 0)
            s_end = getattr(s, "end_line", 0)
            if not current_group:
                current_group = [s]
                cur_start, cur_end = s_start, s_end
                continue
            if are_ranges_overlapping(cur_start, cur_end, s_start, s_end):
                # expand current group range
                cur_end = max(cur_end, s_end)
                cur_start = min(cur_start, s_start)
                current_group.append(s)
            else:
                # flush group
                merged_results.append(merge_group(current_group))
                # start new group
                current_group = [s]
                cur_start, cur_end = s_start, s_end
        # flush last group
        if current_group:
            merged_results.append(merge_group(current_group))

    # stable sort by path and start_line for deterministic output
    merged_results_sorted = sorted(merged_results, key=lambda x: (getattr(x, "path", ""), getattr(x, "start_line", 0)))
    return merged_results_sorted

# If executed as script, provide simple demo (no external I/O)
if __name__ == "__main__":
    import json
    # quick smoke test
    a = BaseSnippet(input="a", start_line=10, end_line=12, snippet="foo()", message="vuln A", path="core/app.py", severity="HIGH")
    b = BaseSnippet(input="b", start_line=11, end_line=15, snippet="bar()", message="vuln B", path="core/app.py", severity="MEDIUM", bit_trigger="user input", bit_steps=["1. call foo"], constraints={"auth":"none"})
    c = BaseSnippet(input="c", start_line=200, end_line=210, snippet="baz()", message="other", path="utils.py", severity="LOW")
    merged = merge_snippets_by_file([a,b,c])
    print(json.dumps([{
        "path": m.path,
        "start": m.start_line,
        "end": m.end_line,
        "severity": getattr(m, "severity", ""),
        "bit_trigger": getattr(m, "bit_trigger", None),
        "bit_steps": getattr(m, "bit_steps", None),
        "constraints": getattr(m, "constraints", None),
    } for m in merged], indent=2, ensure_ascii=False))
