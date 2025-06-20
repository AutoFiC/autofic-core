import re
from typing import List, Optional
from pydantic import BaseModel

class ParsedCodeBlock(BaseModel):
    language: str
    code: str
    filename: Optional[str] = None

class LLMResponseParser:
    @staticmethod
    def extract_code_blocks(response: str) -> List[ParsedCodeBlock]:
         pattern = r"```(\w+)\n(.*?)```"
        matches = re.findall(pattern, response, re.DOTALL)

        code_blocks = []
        for language, code in matches:
            if language.lower() in ["js", "javascript"]:
                filename = LLMResponseParser.extract_filename(code)
                code_blocks.append(
                    ParsedCodeBlock(language=language, code=code.strip(), filename=filename)
                )

        return code_blocks

    @staticmethod
    def extract_filename(code: str) -> Optional[str]:
        filename_pattern = r"(?:\/\/|#|\/\*)\s*filename:\s*(.+?)(?:\s|\*\/|$)"
        match = re.search(filename_pattern, code)
        return match.group(1).strip() if match else None
