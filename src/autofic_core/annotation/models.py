from dataclasses import dataclass
from typing import Optional

@dataclass
class ParsedVuln:
    path: str
    start_line: int
    end_line: int
    message: Optional[str] = None
    snippet: Optional[str] = None
    severity: Optional[str] = None