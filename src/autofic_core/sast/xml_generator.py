from __future__ import annotations

import os
import datetime
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Union

from autofic_core.sast.snippet import BaseSnippet

XML_NS = "urn:autofic:custom-context"
XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"
ET.register_namespace("", XML_NS)
ET.register_namespace("xsi", XSI_NS)


@dataclass
class RenderOptions:
    tool_name: str = "AutoFiC"
    schema_location: str = "schemas/custom_context.xsd"
    include_env: bool = True
    include_tracking: bool = True
    include_mitigations: bool = True
    context_lines_before: int = 0
    context_lines_after: int = 0


def _severity_pair(sev: Optional[str]) -> tuple[str, str]:
    v = (sev or "").upper() or "UNKNOWN"
    return v, v


def _as_snippets(items: Iterable[Union[BaseSnippet, dict]]) -> List[BaseSnippet]:
    out: List[BaseSnippet] = []
    for s in items:
        if isinstance(s, BaseSnippet):
            out.append(s)
        elif isinstance(s, dict):
            out.append(BaseSnippet(**s))
        else:
            raise TypeError(f"Unsupported snippet type: {type(s)}")
    return out


def generate_custom_context(
    merged_snippets: Iterable[Union[BaseSnippet, dict]],
    output_path: Path,
    schema_path: Optional[Path] = None,   
    options: Optional[RenderOptions] = None,
) -> Path:
    """
    병합된 스니펫으로 Team-Atlanta 스타일 CUSTOM_CONTEXT.xml 생성
    """
    opts = options or RenderOptions()
    snippets = _as_snippets(merged_snippets)

    root = ET.Element(f"{{{XML_NS}}}CUSTOM_CONTEXT")
    root.set("version", "1.1")
    root.set(f"{{{XSI_NS}}}schemaLocation", f"{XML_NS} {opts.schema_location}")

    meta = ET.SubElement(root, f"{{{XML_NS}}}META")
    meta.set("generatedAt", datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"))
    meta.set("tool", opts.tool_name)
    meta.set("count", str(len(snippets)))

    for s in snippets:
        v = ET.SubElement(root, f"{{{XML_NS}}}VULNERABILITY")
        v.set("id", f"{s.path}:{s.start_line}-{s.end_line}")

        f_el = ET.SubElement(v, f"{{{XML_NS}}}FILE")
        f_el.set("path", s.path)

        r_el = ET.SubElement(v, f"{{{XML_NS}}}RANGE")
        r_el.set("start", str(s.start_line))
        r_el.set("end", str(s.end_line))

        overall, bit = _severity_pair(s.severity)
        sev_el = ET.SubElement(v, f"{{{XML_NS}}}SEVERITY")
        sev_el.set("overall", overall)
        sev_el.set("bit", bit)

        msg_el = ET.SubElement(v, f"{{{XML_NS}}}MESSAGE")
        message_text = s.message or ""
        if " | " in message_text:
            messages_el = ET.SubElement(msg_el, f"{{{XML_NS}}}MESSAGES")
            for piece in [m.strip() for m in message_text.split("|") if m.strip()]:
                item = ET.SubElement(messages_el, f"{{{XML_NS}}}ITEM")
                item.text = piece
        else:
            msg_el.text = message_text

        snip_el = ET.SubElement(v, f"{{{XML_NS}}}SNIPPET")
        snip_el.text = s.snippet or ""

        bit_el = ET.SubElement(v, f"{{{XML_NS}}}BIT")
        trig_el = ET.SubElement(bit_el, f"{{{XML_NS}}}TRIGGER")
        trig_el.text = message_text or "Vulnerability detected."

        steps_el = ET.SubElement(bit_el, f"{{{XML_NS}}}STEPS")
        step = ET.SubElement(steps_el, f"{{{XML_NS}}}STEP")
        if s.start_line == s.end_line:
            step.text = f"Review line {s.start_line} in {s.path}"
        else:
            step.text = f"Review lines {s.start_line}-{s.end_line} in {s.path}"

        repro_el = ET.SubElement(bit_el, f"{{{XML_NS}}}REPRODUCTION")
        repro_el.text = "Inspect the indicated code region and verify unsafe data flow or pattern."

        bit_sev = ET.SubElement(bit_el, f"{{{XML_NS}}}BIT_SEVERITY")
        bit_sev.text = bit

        if s.vulnerability_class:
            classes = ET.SubElement(v, f"{{{XML_NS}}}CLASSES")
            for c in sorted(set(s.vulnerability_class)):
                ce = ET.SubElement(classes, f"{{{XML_NS}}}CLASS")
                ce.text = c

        if s.cwe:
            we = ET.SubElement(v, f"{{{XML_NS}}}WEAKNESSES")
            for cwe in sorted(set(s.cwe)):
                ce = ET.SubElement(we, f"{{{XML_NS}}}CWE")
                ce.set("id", cwe)

        if s.references:
            refs = ET.SubElement(v, f"{{{XML_NS}}}REFERENCES")
            for href in sorted(set(s.references)):
                re = ET.SubElement(refs, f"{{{XML_NS}}}REF")
                re.set("href", href)

        pre = ET.SubElement(v, f"{{{XML_NS}}}PRECONDITIONS")
        it = ET.SubElement(pre, f"{{{XML_NS}}}ITEM")
        it.text = "Authenticated user may be required depending on route."

        if opts.include_env:
            env = ET.SubElement(v, f"{{{XML_NS}}}ENV")
            runtime = ET.SubElement(env, f"{{{XML_NS}}}RUNTIME")
            runtime.set("node", os.getenv("NODE_MAJOR", "unknown"))
            runtime.set("os", os.name)

        if opts.include_mitigations:
            mit = ET.SubElement(v, f"{{{XML_NS}}}MITIGATION")
            summary = ET.SubElement(mit, f"{{{XML_NS}}}SUMMARY")
            summary.text = "Apply minimal changes: sanitize inputs, use parameterized APIs, and enforce allowlists."

        if opts.include_tracking:
            ET.SubElement(v, f"{{{XML_NS}}}TRACKING")

        if opts.context_lines_before or opts.context_lines_after:
            ctx = ET.SubElement(v, f"{{{XML_NS}}}CONTEXT")
            ctx.set("before", str(opts.context_lines_before))
            ctx.set("after", str(opts.context_lines_after))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(root).write(output_path, encoding="utf-8", xml_declaration=True)
    return output_path


def render_custom_context(
    merged_snippets: Iterable[Union[BaseSnippet, dict]],
    output_path: Path,
    schema_path: Optional[Path] = None,
    options: Optional[RenderOptions] = None,
) -> Path:
    return generate_custom_context(
        merged_snippets=merged_snippets,
        output_path=output_path,
        schema_path=schema_path,
        options=options,
    )


__all__ = [
    "RenderOptions",
    "generate_custom_context",
    "render_custom_context",
]