# =============================================================================
# Copyright 2025 AutoFiC Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# =============================================================================

from typing import List
from pydantic import BaseModel
from autofic_core.sast.snippet import BaseSnippet 
from autofic_core.errors import (
    PromptGenerationException,
    PromptGeneratorErrorCodes,
    PromptGeneratorErrorMessages,
)


class PromptTemplate(BaseModel):
    title: str
    content: str

    def render(self, file_snippet: BaseSnippet) -> str:
        """Render a prompt based on the provided code snippet."""
        if not file_snippet.input.strip():
            raise PromptGenerationException(
                PromptGeneratorErrorCodes.EMPTY_SNIPPET,
                PromptGeneratorErrorMessages.EMPTY_SNIPPET,
            )

        vulnerabilities_str = (
            f"Type: {', '.join(file_snippet.vulnerability_class) or 'Unknown'}\n"
            f"CWE: {', '.join(file_snippet.cwe) or 'N/A'}\n"
            f"Description: {file_snippet.message or 'None'}\n"
            f"Severity: {file_snippet.severity or 'Unknown'}\n"
            f"Location: {file_snippet.start_line} ~ {file_snippet.end_line} (Only modify this code range)\n\n"
        )

        try:
            return self.content.format(
                input=file_snippet.input,
                vulnerabilities=vulnerabilities_str,
            )
        except Exception:
            raise PromptGenerationException(
                PromptGeneratorErrorCodes.TEMPLATE_RENDER_ERROR,
                PromptGeneratorErrorMessages.TEMPLATE_RENDER_ERROR,
            )


class GeneratedPrompt(BaseModel):
    title: str
    prompt: str
    snippet: BaseSnippet


class PromptGenerator:
    def __init__(self):
        self.template = PromptTemplate(
            title="Refactoring Vulnerable Code Snippet (File Level)",
            content=(
                "The following is a JavaScript source file that contains security vulnerabilities.\n\n"
                "```javascript\n"
                "{input}\n"
                "```\n\n"
                "Detected vulnerabilities:\n\n"
                "{vulnerabilities}"
                "Please strictly follow the guidelines below when modifying the cozde:\n"
                "- Modify **only the vulnerable parts** of the file with **minimal changes**.\n"
                "- Preserve the **original line numbers, indentation, and code formatting** exactly.\n"
                "- **Do not modify any part of the file that is unrelated to the vulnerabilities.**\n"
                "- Output the **entire file**, not just the changed lines.\n"
                "- This code will be used for diff-based automatic patching, so structural changes may cause the patch to fail.\n\n"
                "Output format example:\n"
                "1. Vulnerability Description: ...\n"
                "2. Potential Risk: ...\n"
                "3. Recommended Fix: ...\n"
                "4. Final Modified Code:\n"
                "```javascript\n"
                "// Entire file content, but only vulnerable parts should be modified minimally\n"
                "...entire code...\n"
                "```\n"
                "5. Additional Notes: (optional)\n"
            ),
        )

    def generate_prompt(self, file_snippet: BaseSnippet) -> GeneratedPrompt:
        """Generate a single prompt from one code snippet."""
        if not isinstance(file_snippet, BaseSnippet):
            raise TypeError(f"[ ERROR ] generate_prompt: Invalid input type: {type(file_snippet)}")
        rendered_prompt = self.template.render(file_snippet)
        return GeneratedPrompt(
            title=self.template.title,
            prompt=rendered_prompt,
            snippet=file_snippet,
        )

    def generate_prompts(self, file_snippets: List[BaseSnippet]) -> List[GeneratedPrompt]:
        """Generate prompts from multiple snippets."""
        prompts = []
        for idx, snippet in enumerate(file_snippets):
            if isinstance(snippet, dict):
                snippet = BaseSnippet(**snippet)
            elif not isinstance(snippet, BaseSnippet):
                raise TypeError(f"[ ERROR ] generate_prompts: Invalid type at index {idx}: {type(snippet)}")
            prompts.append(self.generate_prompt(snippet))
        return prompts

    def get_unique_file_paths(self, file_snippets: List[BaseSnippet]) -> List[str]:
        """Extract unique paths from list of snippets."""
        paths = set()
        for idx, snippet in enumerate(file_snippets):
            if isinstance(snippet, dict):
                snippet = BaseSnippet(**snippet)
            elif not isinstance(snippet, BaseSnippet):
                raise TypeError(f"[ ERROR ] get_unique_file_paths: Type error at index {idx}: {type(snippet)}")
            paths.add(snippet.path)
        return sorted(paths)