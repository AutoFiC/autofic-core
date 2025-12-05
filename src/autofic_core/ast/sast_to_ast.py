from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import ast

from autofic_core.sast.snippet import BaseSnippet


@dataclass
class SASTtoASTRequest:
    file_path: str
    source_code: str
    sast_snippets: List[BaseSnippet]


@dataclass
class SASTtoASTResponse:
    success: bool
    file_path: str
    ast_data: Optional[Dict[str, Any]] = None
    sast_mappings: Optional[List[Dict[str, Any]]] = None
    error_message: Optional[str] = None


class SASTtoAST:

    def __init__(self):
        self._tree: Optional[ast.AST] = None
        self._nodes: List[ast.AST] = []         # ast.walk 결과 캐시

    # AST 인덱스 / parent 포인터 구축
    def _build_index(self, tree: ast.AST) -> None:
        """
        - AST 전체를 walk 하면서 self._nodes에 캐싱
        - 각 child 노드에 `_parent` 속성으로 parent 포인터 부여
        """
        nodes: List[ast.AST] = []

        for parent in ast.walk(tree):
            nodes.append(parent)
            for child in ast.iter_child_nodes(parent):
                # parent 포인터 부여 (없으면 설정)
                if not hasattr(child, "_parent"):
                    setattr(child, "_parent", parent)

        self._nodes = nodes


    # AST Node -> Dict 변환
    def _ast_to_dict(self, node: Optional[ast.AST]) -> Optional[Dict[str, Any]]:
        if node is None:
            return None

        result: Dict[str, Any] = {
            "node_type": node.__class__.__name__,
            "lineno": getattr(node, "lineno", None),
            "col_offset": getattr(node, "col_offset", None),
            "end_lineno": getattr(node, "end_lineno", None),
            "end_col_offset": getattr(node, "end_col_offset", None),
        }

        for field_name, field_value in ast.iter_fields(node):
            if isinstance(field_value, list):
                result[field_name] = [
                    self._ast_to_dict(item) if isinstance(item, ast.AST) else item
                    for item in field_value
                ]
            elif isinstance(field_value, ast.AST):
                result[field_name] = self._ast_to_dict(field_value)
            else:
                result[field_name] = field_value

        return result


    # 위치 기반 AST 노드 탐색 
    def _find_node_at_location(
        self,
        tree: ast.AST,
        target_line: int,
        target_col: int
    ) -> Optional[ast.AST]:
        for node in ast.walk(tree):
            if hasattr(node, "lineno") and hasattr(node, "col_offset"):
                start_line = node.lineno
                end_line = getattr(node, "end_lineno", start_line)
                start_col = node.col_offset
                end_col = getattr(node, "end_col_offset", start_col)

                if (
                    start_line <= target_line <= end_line and
                    start_col <= target_col <= end_col
                ):
                    return node
        return None


    # 범위 기반 minimal covering node 탐색 
    @staticmethod
    def _lexi_leq(a: Tuple[int, int], b: Tuple[int, int]) -> bool:
        """(line, col) 기준 lexicographical <= 비교"""
        return a[0] < b[0] or (a[0] == b[0] and a[1] <= b[1])

    def _find_best_node_for_range(
        self,
        start_line: int,
        start_col: int,
        end_line: int,
        end_col: int
    ) -> Optional[ast.AST]:

        if self._tree is None or not self._nodes:
            return None

        snippet_start = (start_line, start_col)
        snippet_end = (end_line, end_col)

        best_cover_node: Optional[ast.AST] = None
        best_cover_area: Optional[Tuple[int, int]] = None       # (line_span, col_span)

        partial_node: Optional[ast.AST] = None
        partial_area: Optional[Tuple[int, int]] = None

        for node in self._nodes:
            # 위치 정보가 없는 노드는 스킵
            if not hasattr(node, "lineno") or not hasattr(node, "col_offset"):
                continue

            node_start = (
                getattr(node, "lineno", None),
                getattr(node, "col_offset", None),
            )
            node_end = (
                getattr(node, "end_lineno", node_start[0]),
                getattr(node, "end_col_offset", node_start[1]),
            )

            if node_start[0] is None or node_start[1] is None:
                continue

            # 노드가 snippet 전체를 완전히 포함하는지
            if (
                self._lexi_leq(node_start, snippet_start)
                and self._lexi_leq(snippet_end, node_end)
            ):
                line_span = node_end[0] - node_start[0]
                col_span = node_end[1] - node_start[1]
                area = (line_span, col_span)

                if best_cover_area is None or area < best_cover_area:
                    best_cover_area = area
                    best_cover_node = node

            # 완전 포함은 아니지만 snippet 시작을 포함하는 노드 
            elif (
                self._lexi_leq(node_start, snippet_start)
                and self._lexi_leq(snippet_start, node_end)
            ):
                line_span = node_end[0] - node_start[0]
                col_span = node_end[1] - node_start[1]
                area = (line_span, col_span)

                if partial_area is None or area < partial_area:
                    partial_area = area
                    partial_node = node

        # 1순위 : 전체 범위를 덮는 minimal covering node
        if best_cover_node is not None:
            return best_cover_node

        # 2순위 : 시작 위치만 덮는 노드들 중 minimal
        if partial_node is not None:
            return partial_node

        # 3순위
        return self._find_node_at_location(
            self._tree,
            start_line,
            start_col,
        )


    # AST 생성 + 전체 매핑 파이프라인
    def generate(self, request: SASTtoASTRequest) -> SASTtoASTResponse:
        try:
            # AST 파싱
            self._tree = ast.parse(request.source_code)

            # 인덱스 / parent 포인터 구축
            self._build_index(self._tree)

            # 전체 AST를 dict로 변환 
            ast_data = self._ast_to_dict(self._tree)

            # 각 snippet -> AST 매핑
            sast_mappings: List[Dict[str, Any]] = []
            for snippet in request.sast_snippets:
                node_dict = self._map_snippet_to_ast(snippet)
                if node_dict:
                    sast_mappings.append({
                        "snippet_id": getattr(snippet, "id", None),
                        "snippet_type": type(snippet).__name__,
                        "location": {
                            "line": snippet.start_line,
                            "col": snippet.start_col,
                            "end_line": getattr(snippet, "end_line", None),
                            "end_col": getattr(snippet, "end_col", None),
                        },
                        "ast_node": node_dict
                    })

            return SASTtoASTResponse(
                success=True,
                file_path=request.file_path,
                ast_data=ast_data,
                sast_mappings=sast_mappings,
            )

        except Exception as e:
            return SASTtoASTResponse(
                success=False,
                file_path=request.file_path,
                error_message=str(e),
            )


    # 단일 Snippet -> AST 매핑
    def _map_snippet_to_ast(self, snippet: BaseSnippet) -> Optional[Dict[str, Any]]:
        if self._tree is None:
            raise RuntimeError("AST not initialized. Call generate() first.")

        # end_line / end_col이 없을 수 있으므로 fallback 처리
        start_line = getattr(snippet, "start_line", None)
        start_col = getattr(snippet, "start_col", 0)
        end_line = getattr(snippet, "end_line", None)
        end_col = getattr(snippet, "end_col", 0)

        if start_line is None:
            return None

        if end_line is None:
            end_line = start_line
        
        # end_col이 0이더라도, 최소한 start_col 이상이 되도록 보정
        if end_col == 0:
            end_col = max(start_col, 0)

        node = self._find_best_node_for_range(
            start_line=start_line,
            start_col=start_col,
            end_line=end_line,
            end_col=end_col,
        )

        return self._ast_to_dict(node) if node else None


"""
# pipeline.py 예시 사용법
from autofic_core.ast.sast_to_ast import (
    SASTtoAST,
    SASTtoASTRequest
)

engine = SASTtoAST()

req = SASTtoASTRequest(
    file_path=path,
    source_code=code,
    sast_snippets=snippets
)

result = engine.generate(req)

if result.success:
    do_next_stage(result.ast_data, result.sast_mappings)

"""