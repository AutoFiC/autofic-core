"""
XML Validator for CUSTOM_CONTEXT.xml

XSD 스키마를 사용하여 생성된 XML의 유효성을 검증합니다.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional, Tuple

try:
    import xmlschema
    XMLSCHEMA_AVAILABLE = True
except ImportError:
    XMLSCHEMA_AVAILABLE = False

logger = logging.getLogger(__name__)


class ValidationError(Exception):
    """XML 검증 실패 시 발생하는 예외"""
    def __init__(self, message: str, errors: Optional[List[str]] = None):
        super().__init__(message)
        self.errors = errors or []


class XMLValidator:
    """CUSTOM_CONTEXT.xml 검증기"""
    
    def __init__(self, schema_path: Path):
        """
        Args:
            schema_path: XSD 스키마 파일 경로
        """
        if not XMLSCHEMA_AVAILABLE:
            raise ImportError(
                "xmlschema 패키지가 설치되지 않았습니다. "
                "다음 명령으로 설치하세요: pip install xmlschema"
            )
        
        if not schema_path.exists():
            raise FileNotFoundError(f"스키마 파일을 찾을 수 없습니다: {schema_path}")
        
        self.schema_path = schema_path
        logger.info(f"Loading XSD schema from: {schema_path}")
        
        try:
            self.schema = xmlschema.XMLSchema(str(schema_path))
            logger.info("✓ XSD schema loaded successfully")
        except Exception as e:
            raise ValueError(f"스키마 파일 로드 실패: {e}") from e
    
    def validate(self, xml_path: Path) -> Tuple[bool, List[str]]:
        """
        XML 파일을 스키마에 대해 검증
        
        Args:
            xml_path: 검증할 XML 파일 경로
        
        Returns:
            (is_valid, errors): 검증 성공 여부와 오류 목록
        """
        if not xml_path.exists():
            return False, [f"XML 파일을 찾을 수 없습니다: {xml_path}"]
        
        logger.info(f"Validating XML: {xml_path}")
        errors: List[str] = []
        
        try:
            # xmlschema를 사용한 검증
            self.schema.validate(str(xml_path))
            logger.info("✓ XML validation successful")
            return True, []
        
        except xmlschema.XMLSchemaException as e:
            # 스키마 검증 오류
            error_msg = f"Schema validation error: {str(e)}"
            errors.append(error_msg)
            logger.error(error_msg)
            return False, errors
        
        except Exception as e:
            # 기타 오류
            error_msg = f"Validation failed: {str(e)}"
            errors.append(error_msg)
            logger.error(error_msg)
            return False, errors
    
    def validate_strict(self, xml_path: Path) -> None:
        """
        엄격한 검증 (실패 시 예외 발생)
        
        Args:
            xml_path: 검증할 XML 파일 경로
        
        Raises:
            ValidationError: 검증 실패 시
        """
        is_valid, errors = self.validate(xml_path)
        if not is_valid:
            raise ValidationError(
                f"XML 검증 실패: {xml_path}",
                errors=errors
            )
    
    def get_schema_info(self) -> dict:
        """스키마 정보 반환"""
        return {
            "schema_path": str(self.schema_path),
            "target_namespace": self.schema.target_namespace,
            "elements": list(self.schema.elements.keys()),
            "types": list(self.schema.types.keys()),
        }


def validate_xml(
    xml_path: Path,
    schema_path: Path,
    strict: bool = True
) -> Tuple[bool, List[str]]:
    """
    XML 파일 검증 헬퍼 함수
    
    Args:
        xml_path: 검증할 XML 파일
        schema_path: XSD 스키마 파일
        strict: True이면 실패 시 예외 발생
    
    Returns:
        (is_valid, errors)
    
    Raises:
        ValidationError: strict=True이고 검증 실패 시
    """
    validator = XMLValidator(schema_path)
    
    if strict:
        validator.validate_strict(xml_path)
        return True, []
    else:
        return validator.validate(xml_path)


def check_xmlschema_available() -> bool:
    """xmlschema 패키지 사용 가능 여부 확인"""
    return XMLSCHEMA_AVAILABLE


__all__ = [
    "XMLValidator",
    "ValidationError",
    "validate_xml",
    "check_xmlschema_available",
]
