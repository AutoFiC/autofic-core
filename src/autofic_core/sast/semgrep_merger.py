from collections import defaultdict
from typing import List
from autofic_core.sast.semgrep_preprocessor import SemgrepSnippet

# 동일한 위치(파일, 시작/끝 라인)의 스니펫 병합
def merge_snippets_by_location(snippets: List[SemgrepSnippet]) -> List[SemgrepSnippet]:
    grouped = defaultdict(list)

    # 경로, 시작 라인, 끝 라인 기준으로 그룹핑
    for snippet in snippets:
        key = (snippet.path, snippet.start_line, snippet.end_line)
        grouped[key].append(snippet)

    merged_snippets = []

    # 각 그룹별로 하나의 스니펫으로 병합
    for (_, start_line, end_line), group in grouped.items():
        base = group[0]

        merged_snippets.append(SemgrepSnippet(
            input=base.input,
            output="",
            idx=base.idx,
            start_line=start_line,
            end_line=end_line,
            snippet="\n\n".join(s.snippet for s in group),
            snippet_numbered="\n\n".join(s.snippet_numbered for s in group),
            message=" | ".join(s.message for s in group),
            vulnerability_class=list({vc for s in group for vc in s.vulnerability_class}),
            cwe=list({c for s in group for c in s.cwe}),
            severity=max(
                (s.severity for s in group),
                key=lambda x: ["INFO", "WARNING", "ERROR"].index(x.upper()) if x else -1
            ),
            references=list({r for s in group for r in s.references}),
            path=base.path
        ))

    return merged_snippets