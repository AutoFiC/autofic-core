from typing import List
from autofic_core.sast.snippet import BaseSnippet

def inject_annotations(code_lines: List[str], vulns: List[BaseSnippet], marker: str = "@BUG_HERE") -> List[str]:
    for vuln in vulns:
        start_idx = vuln.start_line - 1
        end_idx = vuln.end_line - 1

        # 범위를 벗어나는 경우 방어
        if not (0 <= start_idx < len(code_lines)):
            continue
        if not (0 <= end_idx < len(code_lines)):
            end_idx = start_idx

        if start_idx == end_idx:
            # 단일 라인 취약점 → 해당 라인만 주석
            code_lines[start_idx] = code_lines[start_idx].rstrip("\n") + f"  # {marker}\n"
        else:
            # 범위 취약점 → 시작/끝 라인에만 주석
            code_lines[start_idx] = code_lines[start_idx].rstrip("\n") + f"  # {marker}_START\n"
            code_lines[end_idx] = code_lines[end_idx].rstrip("\n") + f"  # {marker}_END\n"

    return code_lines