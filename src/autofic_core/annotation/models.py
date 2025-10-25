from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum


class StepType(Enum):
    REPRO = "repro"
    MITIGATION = "mitigation"
    VERIFICATION = "verification"
    NOTE = "note"


@dataclass
class BITStep:
    type: StepType
    description: str
    order: int
    code_snippet: Optional[str] = None


@dataclass
class BITInfo:
    trigger: Optional[str] = None
    steps: List[BITStep] = field(default_factory=list)
    reproduction: Optional[str] = None
    recommendation: Optional[str] = None
    severity: Optional[str] = None


@dataclass
class CodeSnippet:
    before: List[str] = field(default_factory=list)
    match: List[str] = field(default_factory=list)
    after: List[str] = field(default_factory=list)


@dataclass
class ParsedVuln:
    id: str
    path: str
    start_line: int
    end_line: int
    
    rule: Optional[str] = None
    tool: Optional[str] = None
    confidence: Optional[str] = None
    severity: Optional[str] = None
    message: Optional[str] = None
    
    snippet: Optional[str] = None
    code_snippet: Optional[CodeSnippet] = None
    
    bit: Optional[BITInfo] = None
    
    merged_from: List[str] = field(default_factory=list)
    
    unmapped: bool = False
    
    def __post_init__(self):
        self.path = self.path.replace('\\', '/')