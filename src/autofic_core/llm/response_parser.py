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

import re
from pathlib import Path
from typing import List
from pydantic import BaseModel
from autofic_core.errors import ResponseParseError

CODE_BLOCK_PATTERN = re.compile(r"```(?:js|javascript)\n([\s\S]+?)```", re.IGNORECASE | re.MULTILINE)


class ParsedResponse(BaseModel):
    """Structured representation of parsed response."""
    filename: str
    code: str
    output_path: Path


def extract_code_blocks(content: str, filename: str) -> str:
    """
    Extract JavaScript code blocks from markdown content.
    Raises:
        ResponseParseError: if code block not found
    """
    matches = CODE_BLOCK_PATTERN.findall(content)
    if not matches:
        raise ResponseParseError(filename, "js/javascript 코드 블럭을 찾을 수 없습니다.")
    return "\n\n".join(m.strip() for m in matches)


def parse_md_filename(md_filename: str) -> str:
    """
    Convert response_*.md filename into relative path.
    Raises:
        ResponseParseError: if filename format is invalid
    """
    stem = Path(md_filename).stem
    if not stem.startswith("response_"):
        raise ResponseParseError(md_filename, "잘못된 파일명 형식")
    return stem[len("response_"):].replace("_", "/")


def parse_response(md_path: Path, output_dir: Path) -> ParsedResponse:
    """
    Extract code from md file and return parsed result as model.
    Raises:
        ResponseParseError: on any parsing or I/O failure
    """
    try:
        content = md_path.read_text(encoding="utf-8")
        code = extract_code_blocks(content, md_path.name)
        rel_path = parse_md_filename(md_path.name)
        output_path = output_dir / rel_path
        return ParsedResponse(
            filename=md_path.name,
            code=code,
            output_path=output_path
        )
    except Exception as e:
        raise ResponseParseError(md_path.name, str(e))


def save_code_file(response: ParsedResponse) -> None:
    """
    Save parsed code to target output path.
    """
    response.output_path.parent.mkdir(parents=True, exist_ok=True)
    response.output_path.write_text(response.code, encoding="utf-8")


class ResponseParser:
    """
    Extract and save code blocks from response_*.md files.
    """

    def __init__(self, md_dir: Path, diff_dir: Path):
        self.md_dir = md_dir
        self.diff_dir = diff_dir

    def extract_and_save_all(self) -> bool:
        """
        Extract all responses and save parsed code.
        Returns:
            bool: True if at least one file succeeded
        """
        md_files = list(self.md_dir.glob("*.md"))
        success = False
        for md_file in md_files:
            try:
                parsed = parse_response(md_file, self.diff_dir)
                save_code_file(parsed)
                success = True
            except ResponseParseError:
                continue
        return success
