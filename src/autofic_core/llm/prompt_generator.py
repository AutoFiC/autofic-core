from typing import List
from pydantic import BaseModel
from autofic_core.sast.semgrep_preprocessor import SemgrepSnippet, SemgrepPreprocessor
from autofic_core.errors import (
    PromptGenerationException,
    PromptGeneratorErrorCodes,
    PromptGeneratorErrorMessages,
)

class PromptTemplate(BaseModel):
    title: str
    content: str

    def render(self, snippet: SemgrepSnippet) -> str:
        if not snippet.snippet_numbered.strip():
            raise PromptGenerationException(
                PromptGeneratorErrorCodes.EMPTY_SNIPPET,
                PromptGeneratorErrorMessages.EMPTY_SNIPPET,
            )

        try:
            file_ext = snippet.path.split('.')[-1] if '.' in snippet.path else 'txt'
            return self.content.format(
                input=snippet.input,
                snippet_numbered=snippet.snippet_numbered,
                vulnerability_class=", ".join(snippet.vulnerability_class) or "알 수 없음",
                cwe=", ".join(map(str, snippet.cwe)) or "해당 없음",
                message=snippet.message or "없음",
                severity=snippet.severity or "정보 없음",
                path=snippet.path,
                start_line=snippet.start_line,
                end_line=snippet.end_line,
                file_ext=file_ext,
            )
        except Exception:
            raise PromptGenerationException(
                PromptGeneratorErrorCodes.TEMPLATE_RENDER_ERROR,
                PromptGeneratorErrorMessages.TEMPLATE_RENDER_ERROR,
            )

class GeneratedPrompt(BaseModel):
    title: str
    prompt: str
    snippet: SemgrepSnippet

class PromptGenerator:
    def __init__(self):
        self.template = PromptTemplate(
            title="취약한 코드 스니펫 리팩토링",
            content=(
                "전체 코드 (참고용):\n\n"
                "```{file_ext}\n"
                "{input}\n"
                "```\n\n"
                "다음 스니펫에 취약점이 존재합니다:\n\n"
                "```{file_ext}\n"
                "{snippet_numbered}\n"
                "```\n\n"
                "### 스니펫 정보\n"
                "- 파일 경로: {path}\n"
                "- 시작 줄: {start_line}\n"
                "- 끝 줄: {end_line}\n\n"
                "### 취약점 정보\n"
                "- 유형: {vulnerability_class}\n"
                "- CWE: {cwe}\n"
                "- 설명: {message}\n"
                "- 심각도: {severity}\n\n"
                "### 요청 사항\n"
                "**다음 조건을 반드시 지켜 수정해주세요:**\n"
                "1. 전체 코드를 다시 작성하지 마세요.\n"
                "2. 수정할 부분만 unified diff 형식으로 작성해주세요.\n"
                "3. diff 헤더(`--- a/파일명`, `+++ b/파일명`)와 범위 표시(`@@ -시작줄,줄수 +시작줄,줄수 @@`)를 반드시 포함하세요.\n"
                "4. 위 스니펫의 원래 줄은 반드시 diff에 포함되어야 합니다 (삭제하거나 무시하지 마세요).\n"
                "5. 생성된 diff는 `git apply` 또는 `patch` 명령어로 오류 없이 바로 적용 가능한 형태여야 합니다.\n"
                "6. 수정된 코드 내 주석은 포함하지 마세요.\n\n"
                "### 예시\n"
                "```diff\n"
                "--- a/core/appHandler.js\n"
                "+++ b/core/appHandler.js\n"
                "@@ -10,7 +10,7 @@\n"
                "-    기존코드\n"
                "+    수정된코드\n"
                "```\n\n"
                "### 출력 형식\n"
                "1. 취약점 설명:\n"
                "2. 예상 위험:\n"
                "3. 개선 방안:\n"
                "4. 수정된 코드 (unified diff 형식):\n"
                "5. 기타 참고사항:\n"
            )
        )

    def generate_prompt(self, snippet: SemgrepSnippet) -> GeneratedPrompt:
        rendered_prompt = self.template.render(snippet)
        return GeneratedPrompt(
            title=self.template.title, prompt=rendered_prompt, snippet=snippet
        )

    def generate_prompts(self, snippets: List[SemgrepSnippet]) -> List[GeneratedPrompt]:
        if not isinstance(snippets, list):
            raise PromptGenerationException(
                PromptGeneratorErrorCodes.INVALID_SNIPPET_LIST,
                PromptGeneratorErrorMessages.INVALID_SNIPPET_LIST,
            )
        return [self.generate_prompt(snippet) for snippet in snippets]

    def from_semgrep_file(self, semgrep_result_path: str, base_dir: str = ".") -> List[GeneratedPrompt]:
        snippets = SemgrepPreprocessor().preprocess(semgrep_result_path, base_dir=base_dir)
        return self.generate_prompts(snippets)