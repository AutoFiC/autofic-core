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

from typing import List, Optional
from pathlib import Path
import xml.etree.ElementTree as ET
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

    def render(self, file_snippet: BaseSnippet, custom_context_xml: Optional[str] = None) -> str:
        """Render a prompt based on the provided code snippet and optional CUSTOM_CONTEXT.xml."""
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

        # Team-Atlanta 방식: CUSTOM_CONTEXT.xml을 프롬프트에 포함
        context_section = ""
        if custom_context_xml:
            context_section = (
                "\n## STRUCTURED CONTEXT (Team-Atlanta Approach)\n\n"
                "The following CUSTOM_CONTEXT.xml provides structured vulnerability information including:\n"
                "- BIT (Bug Information Template) with TRIGGER, STEPS, REPRODUCTION\n"
                "- Detailed CWE classifications and severity levels\n"
                "- Environmental context and mitigation strategies\n\n"
                "```xml\n"
                f"{custom_context_xml}\n"
                "```\n\n"
                "**Use the BIT information above to understand:**\n"
                "1. TRIGGER: What conditions activate this vulnerability\n"
                "2. STEPS: How to locate and review the vulnerable code\n"
                "3. REPRODUCTION: How to verify the issue\n"
                "4. BIT_SEVERITY: The criticality level of this vulnerability\n\n"
            )

        try:
            return self.content.format(
                input=file_snippet.input,
                vulnerabilities=vulnerabilities_str,
                context=context_section,
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
    def __init__(self, custom_context_xml_path: Optional[Path] = None):
        """
        Initialize PromptGenerator with optional CUSTOM_CONTEXT.xml path.
        
        Args:
            custom_context_xml_path: Path to CUSTOM_CONTEXT.xml file (Team-Atlanta approach)
        """
        self.custom_context_xml_path = custom_context_xml_path
        self.custom_context_content = None
        
        # Load XML if provided
        if custom_context_xml_path and custom_context_xml_path.exists():
            try:
                with open(custom_context_xml_path, 'r', encoding='utf-8') as f:
                    self.custom_context_content = f.read()
            except Exception as e:
                print(f"Warning: Could not load CUSTOM_CONTEXT.xml: {e}")
        
        self.template = PromptTemplate(
            title="Refactoring Vulnerable Code Snippet (File Level)",
            content=(
                "The following is a Python source file that contains security vulnerabilities.\n\n"
                "```python\n"
                "{input}\n"
                "```\n\n"
                "Detected vulnerabilities:\n\n"
                "{vulnerabilities}"
                "{context}"
                "Please strictly follow the guidelines below when modifying the code:\n"
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
                "```python\n"
                "# Entire file content, but only vulnerable parts should be modified minimally\n"
                "...entire code...\n"
                "```\n"
                "5. Additional Notes: (optional)\n"
            ),
        )

    def generate_prompt(self, file_snippet: BaseSnippet) -> GeneratedPrompt:
        """Generate a single prompt from one code snippet with optional XML context."""
        if not isinstance(file_snippet, BaseSnippet):
            raise TypeError(f"[ ERROR ] generate_prompt: Invalid input type: {type(file_snippet)}")
        
        # Extract relevant XML section for this specific file if available
        xml_context = None
        if self.custom_context_content:
            xml_context = self._extract_vulnerability_xml(file_snippet)
        
        rendered_prompt = self.template.render(file_snippet, custom_context_xml=xml_context)
        return GeneratedPrompt(
            title=self.template.title,
            prompt=rendered_prompt,
            snippet=file_snippet,
        )
    
    def _extract_vulnerability_xml(self, snippet: BaseSnippet) -> Optional[str]:
        """Extract the specific VULNERABILITY section from XML for this snippet."""
        if not self.custom_context_content:
            return None
        
        try:
            # Parse XML and find matching vulnerability
            root = ET.fromstring(self.custom_context_content)
            ns = {'c': 'urn:autofic:custom-context'}
            
            # Find vulnerability matching this file/line range
            for vuln in root.findall('.//c:VULNERABILITY', ns):
                file_elem = vuln.find('c:FILE', ns)
                range_elem = vuln.find('c:RANGE', ns)
                
                if file_elem is not None and range_elem is not None:
                    xml_path = file_elem.get('path')
                    xml_start = int(range_elem.get('start', 0))
                    
                    if (xml_path == snippet.path and xml_start == snippet.start_line):
                        # Return this vulnerability as formatted XML
                        return ET.tostring(vuln, encoding='unicode')
            
            return None
        except Exception as e:
            print(f"Warning: Could not extract vulnerability XML: {e}")
            return None

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