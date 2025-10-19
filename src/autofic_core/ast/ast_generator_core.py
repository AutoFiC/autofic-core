from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import ast 

@dataclass
class SASTtoASTRequest:
    # SAST 결과를 기반으로 AST 생성 요청
    file_path: str
    source_code: str
    sast_snippets: List[Any]    # SAST 스니펫 리스트


@dataclass
class SASTtoASTResponse:
    # SAST 결과로부터 생성된 AST 응답
    success: bool
    file_path: str
    ast_data: Optional[Dict[str, Any]] = None
    sast_mappings: List[Dict[str, Any]] = None
    error_message: Optional[str] = None


class SASTtoASTCore:
    # SAST 결과 처리를 위한 AST 생성 파이프라인 코어

    def __init__(self):
        pass

    def _ast_to_dict(self, node) -> Dict[str, Any]:
        # AST 노드를 재귀적으로 탐색하여 딕셔너리 형태로 변환 
        
        if node is None:
            return None
        
        result = {
            'node_type': node.__class__.__name__,
            'lineno': getattr(node, 'lineno', None),
            'col_offset': getattr(node, 'col_offset', None),
            'end_lineno': getattr(node, 'end_lineno', None),
            'end_col_offset': getattr(node, 'end_col_offset', None),
        }       
        
        for field_name, field_value in ast.iter_fields(node):
            # 자식 필드가 리스트인 경우, 리스트의 각 항목에 대해 재귀적으로 변환 수행 
            if isinstance(field_value, list):
                result[field_name] = [
                    self._ast_to_dict(item) if isinstance(item, ast.AST) else item
                    for item in field_value
                ]
           
            # 자식 필드가 단일 AST 노드인 경우, 해당 노드에 대해 변환 수행 
            elif isinstance(field_value, ast.AST):
                result[field_name] = self._ast_to_dict(field_value)
            
            # 자식 필드가 기본 값인 경우, 값을 그대로 할당하고 종료 
            else:
                result[field_name] = field_value
        
        return result
    
    def _find_node_at_location(self, tree, target_line: int, target_col: int) -> Optional[ast.AST]:
        # 전체 AST 트리를 순회하며 특정 위치에 있는 노드 찾기 
    
        for node in ast.walk(tree):
            if hasattr(node, 'lineno') and hasattr(node, 'col_offset'):
                # 노드의 시작/끝 위치가 타겟을 포함하는지 확인
                if (node.lineno <= target_line <= getattr(node, 'end_lineno', node.lineno) and
                    node.col_offset <= target_col <= getattr(node, 'end_col_offset', node.col_offset)):
                    return node
        return None   
    
    def generate_ast_for_sast(self, request: SASTtoASTRequest) -> SASTtoASTResponse:
        # SAST 결과를 기반으로 AST 생성 및 매핑 수행
        
        try:
            # 소스코드를 AST로 파싱 
            tree = ast.parse(request.source_code)
            self.cached_tree = tree 

            # AST 노드를 딕셔너리로 변환  
            ast_data = self._ast_to_dict(tree)
            
            # SAST 스니펫들과 AST 노드 매핑 생성
            sast_mappings = []
            for snippet in request.sast_snippets:
                ast_node = self.get_ast_for_sast_snippet(snippet)
                if ast_node:
                    sast_mappings.append({
                        'snippet_id': getattr(snippet, 'id', None),
                        'snippet_type': type(snippet).__name__,
                        'location': {
                            'line': snippet.start_line,
                            'col': snippet.start_col
                        },
                        'ast_node': ast_node
                    })
            
            return SASTtoASTResponse(
                success=True,
                file_path=request.file_path,
                ast_data=ast_data,
                sast_mappings=sast_mappings,
                error_message=None
            )

        except Exception as e:
            return SASTtoASTResponse(
                success=False,
                file_path=request.file_path,
                error_message=str(e)
            )

    def get_ast_for_sast_snippet(self, snippet: Any) -> Optional[Dict[str, Any]]:
        # 특정 SAST 스니펫에 대한 AST 노드 정보 반환
        
        # SAST 스니펫에서 위치 정보 추출 
        start_line = snippet.start_line  
        start_col = snippet.start_col

        # AST 트리를 순회하면서 해당 위치의 노드 찾기
        node = self._find_node_at_location(self.cached_tree, start_line, start_col)
    
        if node:
            return self._ast_to_dict(node)
        
        return None