"""
SAST (Static Application Security Testing) 모듈

XML 생성, 검증 및 취약점 분석 기능을 제공합니다.
"""
from autofic_core.sast.xml_generator import (
    generate_custom_context,
    render_custom_context,
    RenderOptions,
)
from autofic_core.sast.xml_validator import (
    XMLValidator,
    ValidationError,
    validate_xml,
    check_xmlschema_available,
)
from autofic_core.sast.snippet import BaseSnippet

__all__ = [
    # XML 생성
    "generate_custom_context",
    "render_custom_context",
    "RenderOptions",
    # XML 검증
    "XMLValidator",
    "ValidationError",
    "validate_xml",
    "check_xmlschema_available",
    # 스니펫
    "BaseSnippet",
]
