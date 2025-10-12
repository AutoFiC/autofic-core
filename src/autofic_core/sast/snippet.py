# =============================================================================
# Copyright 2025 Autofic Authors. All Rights Reserved.
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

"""Defines a unified BaseSnippet model for all SAST tool outputs."""

from pydantic import BaseModel, Field
from typing import List, Optional


class BaseSnippet(BaseModel):
    """
    Unified structure for all vulnerability snippets from Semgrep, CodeQL, SnykCode, etc.

    Attributes:
        input (str): Full source code of the file.
        idx (int): Unique index of the snippet within the file.
        start_line (int): Start line number of the vulnerable code.
        end_line (int): End line number of the vulnerable code.
        snippet (str): Vulnerable code snippet.
        message (str): Description of the vulnerability.
        severity (str): Severity level (e.g., HIGH, MEDIUM, LOW).
        path (str): File path relative to the repository root.
        vulnerability_class (List[str]): List of vulnerability types (e.g., SQL Injection).
        cwe (List[str]): List of CWE identifiers.
        references (List[str]): List of external reference links.
    """
    input: str
    idx: Optional[int] = None
    start_line: int
    end_line: int
    snippet: Optional[str] = None
    message: str = ""
    vulnerability_class: List[str] = Field(default_factory=list)
    cwe: List[str] = Field(default_factory=list)
    severity: str = ""
    references: List[str] = Field(default_factory=list)
    path: str
