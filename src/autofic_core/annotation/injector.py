from typing import List
from autofic_core.sast.snippet import BaseSnippet

def inject_annotations(code_lines: List[str], vulns: List[BaseSnippet], marker: str = "@BUG_HERE") -> List[str]:
    # 코드 라인별로 취약점 라인에 주석 삽입
    for vuln in vulns:
        for ln in range(vuln.start_line - 1, vuln.end_line):
            code_lines[ln] += f"  # {marker}"
    return code_lines