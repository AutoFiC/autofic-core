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

from __future__ import annotations

from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field, validator
from enum import Enum


class SeverityLevel(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

# canonical severity order for helpers
_SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _normalize_severity(s: Optional[str]) -> Optional[str]:
    if s is None:
        return None
    s_up = str(s).strip().upper()
    # try to map common variants
    if s_up in _SEVERITY_ORDER:
        return s_up
    # some scanners use numbers or words - attempt best-effort
    if s_up.isdigit():
        n = int(s_up)
        if n >= 9:
            return "CRITICAL"
        if n >= 7:
            return "HIGH"
        if n >= 4:
            return "MEDIUM"
        return "LOW"
    # fallback heuristics
    if "CRIT" in s_up:
        return "CRITICAL"
    if "HIGH" in s_up or "URGENT" in s_up:
        return "HIGH"
    if "MED" in s_up:
        return "MEDIUM"
    if "LOW" in s_up:
        return "LOW"
    if "INFO" in s_up:
        return "INFO"
    return s_up  # unknown but return normalized-case string


class BaseSnippet(BaseModel):
    """
    Standard snippet model for AutoFiC pipeline.

    주요 필드:
    - input: 원본 입력 식별자(예: semgrep rule id 또는 source filename)
    - idx: 내부 인덱스 (선택)
    - path: 대상 파일 경로 (repo 상대 경로)
    - start_line, end_line: 1-based 라인 범위, inclusive
    - snippet: 취약점이 포함된 코드/문맥
    - message: 탐지 메시지 / rule 설명
    - vulnerability_class: 취약점 분류(예: 'XSS','SQLi')
    - cwe: CWE 식별자 목록(예: ['CWE-89'])
    - severity: 전반적 심각도(자동 정규화)
    - references: 외부 참조 URL 등
    - constraints: 향후 확장용 key/value 메타
    - BIT 관련 필드: bit_trigger, bit_steps, bit_reproduction, bit_severity
    - kb_template: 외부 지식/템플릿 레퍼런스(옵션)
    - context_tags: 간단한 태그 리스트(예: ['input-sanitization','auth'])
    """

    # provenance / identifiers
    input: Optional[str] = Field(None, description="원본 입력 식별자 (예: tool+rule id)")
    idx: Optional[int] = Field(None, description="내부 인덱스(선택)")

    # location & code
    path: str = Field("", description="대상 파일의 repo 상대 경로")
    start_line: int = Field(0, description="시작 라인 (1-based, inclusive)")
    end_line: int = Field(0, description="종료 라인 (1-based, inclusive)")
    snippet: Optional[str] = Field(None, description="취약점이 포함된 코드 또는 코드 문맥")

    # basic vuln metadata
    message: Optional[str] = Field(None, description="탐지 메시지 / rule 설명")
    vulnerability_class: List[str] = Field(default_factory=list, description="취약점 분류(ex: XSS, SQLi)")
    cwe: List[str] = Field(default_factory=list, description="CWE 식별자 목록")
    severity: Optional[str] = Field(None, description="정규화된 심각도 (INFO/LOW/MEDIUM/HIGH/CRITICAL)")
    references: List[str] = Field(default_factory=list, description="참조 URL 또는 문서 목록")

    # BIT (Team-Atlanta style) fields
    bit_trigger: Optional[str] = Field(None, description="Trigger: 취약점 트리거/원인 요약")
    bit_steps: List[str] = Field(default_factory=list, description="Steps: 재현 단계(순서 있는 리스트)")
    bit_reproduction: Optional[str] = Field(None, description="Reproduction: 재현 설명(자유텍스트)")
    bit_severity: Optional[str] = Field(None, description="BIT 내 별도 심각도 (선택적)")

    # extensibility
    constraints: Dict[str, Any] = Field(default_factory=dict, description="확장 제약조건/메타 (key-value)")
    kb_template: Optional[str] = Field(None, description="외부 KB 템플릿 식별자 또는 템플릿 내용")
    context_tags: List[str] = Field(default_factory=list, description="간단한 컨텍스트 태그 목록")

    # annotation
    is_vuln: bool = Field(True, description="@BUG_HERE: 해당 코드/라인이 취약점 라인인지")
    is_key_cond: bool = Field(True, description="@KEY_CONDITION: 도달 조건/분기라인")
    was_visited: bool = Field(False, description="@VISITED: 실행/테스트에서 실제 도달했을 때 True")
    annot_labels: List[str] = Field(default_factory=list, description="인라인 주석/어노테이션 라벨 (@...)")

    class Config:
        # allow population by field name and arbitrary extra attributes (backwards compatibility)
        allow_population_by_field_name = True
        extra = "allow"
        validate_assignment = True
        arbitrary_types_allowed = True

    @validator("severity", pre=True, always=True)
    def _validate_severity(cls, v):
        if v is None:
            return None
        return _normalize_severity(v)

    @validator("bit_severity", pre=True, always=True)
    def _validate_bit_severity(cls, v):
        if v is None:
            return None
        return _normalize_severity(v)

    def worst_severity(self) -> Optional[str]:
        """
        Return the worst (highest) severity between `severity` and `bit_severity`.
        If both are None, returns None.
        """
        sev_vals = [s for s in (self.severity, self.bit_severity) if s]
        if not sev_vals:
            return None
        # use _SEVERITY_ORDER mapping; unknown strings treated as INFO (0)
        worst_val = None
        worst_idx = -1
        for s in sev_vals:
            idx = _SEVERITY_ORDER.get(s.upper(), 0)
            if idx > worst_idx:
                worst_idx = idx
                worst_val = s
        return worst_val

    def to_dict(self, include_none: bool = False) -> Dict[str, Any]:
        """
        Serialize snippet to dict. By default omits None fields unless include_none=True.
        """
        d = self.dict(by_alias=True, exclude_none=not include_none)
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BaseSnippet":
        """
        Construct BaseSnippet from a plain dict. Useful for deserializing preprocessor outputs.
        """
        return cls(**data)

    def merge_with(self, other: "BaseSnippet") -> "BaseSnippet":
        """
        Simple helper that merges another snippet into this one.
        NOTE: merger.py implements a more robust merge. This is a convenience function for
        quick combination: it will:
          - extend vulnerability_class, cwe, references, context_tags
          - append bit_steps (unique-preserve-order)
          - choose worst severity
          - expand start/end line and snippet text
        """
        # extend lists with uniqueness while preserving order
        def _uniq_extend(base: List[Any], add: List[Any]):
            seen = set(base)
            for a in add:
                if a not in seen:
                    base.append(a)
                    seen.add(a)

        _uniq_extend(self.vulnerability_class, other.vulnerability_class or [])
        _uniq_extend(self.cwe, other.cwe or [])
        _uniq_extend(self.references, other.references or [])
        _uniq_extend(self.context_tags, other.context_tags or [])

        if other.bit_steps:
            _uniq_extend(self.bit_steps, other.bit_steps)

        # merge snippet text
        parts = []
        if self.snippet:
            parts.append(self.snippet)
        if other.snippet and other.snippet not in parts:
            parts.append(other.snippet)
        self.snippet = "\n".join(parts).strip()

        # choose worst severity
        worst = BaseSnippet._choose_worst_severity(self.severity, other.severity, self.bit_severity, other.bit_severity)
        self.severity = worst

        # bit fields: prefer existing, append if missing
        if not self.bit_trigger and other.bit_trigger:
            self.bit_trigger = other.bit_trigger
        if not self.bit_reproduction and other.bit_reproduction:
            self.bit_reproduction = other.bit_reproduction

        # expand range
        self.start_line = min(self.start_line or other.start_line or 0, other.start_line or self.start_line or 0)
        self.end_line = max(self.end_line or other.end_line or 0, other.end_line or self.end_line or 0)

        # merge constraints (simple shallow merge; callers may use merger._merge_constraints for collision handling)
        if other.constraints:
            self.constraints = {**self.constraints, **other.constraints}

        # inputs concat
        if self.input and other.input:
            self.input = f"{self.input};{other.input}"
        elif other.input:
            self.input = other.input

        return self

    @staticmethod
    def _choose_worst_severity(*sevs: Optional[str]) -> Optional[str]:
        worst = None
        worst_idx = -1
        for s in filter(None, map(_normalize_severity, [s for s in (sevs or []) if s is not None])):
            idx = _SEVERITY_ORDER.get(s.upper(), 0)
            if idx > worst_idx:
                worst_idx = idx
                worst = s
        return worst

# convenience export
__all__ = ["BaseSnippet", "SeverityLevel", "_normalize_severity"]