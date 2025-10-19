from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from autofic_core.sast.snippet import BaseSnippet
from .ast_generator_core import SASTtoASTCore, SASTtoASTRequest, SASTtoASTResponse


@dataclass
class SASTtoASTInterfaceRequest:
    # SAST 결과를 AST Core에 전달하기 위한 요청 구조
    file_path: str
    source_code: str
    sast_snippets: List[BaseSnippet]
    base_dir: str = "."


class SASTtoASTInterface:
    # SAST 결과를 받아 AST Core와 연동하는 인터페이스 계층

    def __init__(self):
        self.ast_core = SASTtoASTCore()

    def process_sast_results(self, request: SASTtoASTInterfaceRequest) -> SASTtoASTResponse:
        # SAST 결과를 AST Core에 전달하고 결과를 반환
        try:
            sast_request = SASTtoASTRequest(
                file_path=request.file_path,
                source_code=request.source_code,
                sast_snippets=request.sast_snippets
            )

            result = self.ast_core.generate_ast_for_sast(sast_request)

            return SASTtoASTResponse(
                success=result.success,
                file_path=result.file_path,
                ast_data=result.ast_data,
                sast_mappings=result.sast_mappings,
                error_message=result.error_message
            )

        except Exception as e:
            return SASTtoASTResponse(
                success=False,
                file_path=request.file_path,
                error_message=str(e)
            )

    def get_ast_for_sast_snippet(self, snippet: BaseSnippet) -> Optional[Dict[str, Any]]:
        # 특정 SAST 스니펫에 대한 AST 노드 정보 반환
        return self.ast_core.get_ast_for_sast_snippet(snippet)