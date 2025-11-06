"""
SAST XML 워크플로우

SAST 결과를 읽어 CUSTOM_CONTEXT.xml을 생성하고 검증하는 통합 워크플로우
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import List, Optional

from autofic_core.sast.xml_generator import generate_custom_context, RenderOptions
from autofic_core.sast.xml_validator import XMLValidator, check_xmlschema_available
from autofic_core.sast.snippet import BaseSnippet

logger = logging.getLogger(__name__)


class SASTXMLWorkflow:
    """SAST XML 생성 및 검증 워크플로우"""
    
    def __init__(
        self,
        schema_path: Optional[Path] = None,
        auto_validate: bool = True,
    ):
        """
        Args:
            schema_path: XSD 스키마 파일 경로 (None이면 기본 경로 사용)
            auto_validate: XML 생성 후 자동으로 검증할지 여부
        """
        self.auto_validate = auto_validate
        
        # 스키마 경로 설정
        if schema_path is None:
            # 기본 스키마 경로: 프로젝트 루트의 custom_context.xsd
            current_file = Path(__file__)
            project_root = current_file.parent.parent.parent.parent
            self.schema_path = project_root / "custom_context.xsd"
        else:
            self.schema_path = Path(schema_path)
        
        # 검증기 초기화 (xmlschema 사용 가능한 경우만)
        self.validator: Optional[XMLValidator] = None
        if auto_validate and check_xmlschema_available():
            if self.schema_path.exists():
                try:
                    self.validator = XMLValidator(self.schema_path)
                    logger.info(f"✓ XML validator initialized with schema: {self.schema_path}")
                except Exception as e:
                    logger.warning(f"Failed to initialize validator: {e}")
            else:
                logger.warning(f"Schema file not found: {self.schema_path}")
    
    def load_merged_snippets(self, json_path: Path) -> List[BaseSnippet]:
        """
        merged_snippets.json 로드
        
        Args:
            json_path: merged_snippets.json 파일 경로
        
        Returns:
            BaseSnippet 리스트
        """
        logger.info(f"Loading merged snippets from: {json_path}")
        
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        snippets = [BaseSnippet(**item) for item in data]
        logger.info(f"✓ Loaded {len(snippets)} snippets")
        
        return snippets
    
    def generate_xml(
        self,
        snippets: List[BaseSnippet],
        output_path: Path,
        options: Optional[RenderOptions] = None,
    ) -> Path:
        """
        CUSTOM_CONTEXT.xml 생성
        
        Args:
            snippets: 취약점 스니펫 리스트
            output_path: 출력 XML 파일 경로
            options: 렌더링 옵션
        
        Returns:
            생성된 XML 파일 경로
        """
        logger.info(f"Generating CUSTOM_CONTEXT.xml: {output_path}")
        
        # 기본 옵션 설정
        if options is None:
            options = RenderOptions(
                tool_name="AutoFiC-SAST",
                schema_location=f"file:///{self.schema_path.as_posix()}",
                include_env=True,
                include_tracking=True,
                include_mitigations=True,
                context_lines_before=3,
                context_lines_after=3,
            )
        
        # XML 생성
        xml_path = generate_custom_context(
            merged_snippets=snippets,
            output_path=output_path,
            schema_path=self.schema_path,
            options=options,
        )
        
        logger.info(f"✓ XML generated: {xml_path}")
        
        # 자동 검증
        if self.auto_validate and self.validator:
            logger.info("Running automatic validation...")
            is_valid, errors = self.validator.validate(xml_path)
            
            if is_valid:
                logger.info("✓ XML validation passed")
            else:
                logger.error("✗ XML validation failed:")
                for error in errors:
                    logger.error(f"  - {error}")
                raise ValueError(f"XML validation failed: {len(errors)} errors found")
        
        return xml_path
    
    def process_sast_results(
        self,
        merged_snippets_path: Path,
        output_xml_path: Path,
        options: Optional[RenderOptions] = None,
    ) -> Path:
        """
        SAST 결과를 읽어 XML 생성 및 검증
        
        Args:
            merged_snippets_path: merged_snippets.json 경로
            output_xml_path: 출력 XML 경로
            options: 렌더링 옵션
        
        Returns:
            생성된 XML 파일 경로
        """
        # 1. 스니펫 로드
        snippets = self.load_merged_snippets(merged_snippets_path)
        
        # 2. XML 생성
        xml_path = self.generate_xml(snippets, output_xml_path, options)
        
        return xml_path
    
    def validate_existing_xml(self, xml_path: Path) -> bool:
        """
        기존 XML 파일 검증
        
        Args:
            xml_path: 검증할 XML 파일 경로
        
        Returns:
            검증 성공 여부
        """
        if not self.validator:
            if not check_xmlschema_available():
                logger.error("xmlschema package is not installed")
                return False
            
            # 검증기 초기화 시도
            try:
                self.validator = XMLValidator(self.schema_path)
            except Exception as e:
                logger.error(f"Failed to initialize validator: {e}")
                return False
        
        is_valid, errors = self.validator.validate(xml_path)
        
        if is_valid:
            logger.info(f"✓ XML is valid: {xml_path}")
        else:
            logger.error(f"✗ XML validation failed: {xml_path}")
            for error in errors:
                logger.error(f"  - {error}")
        
        return is_valid


def create_custom_context_xml(
    merged_snippets_path: Path,
    output_xml_path: Path,
    schema_path: Optional[Path] = None,
    validate: bool = True,
    options: Optional[RenderOptions] = None,
) -> Path:
    """
    SAST 결과로부터 CUSTOM_CONTEXT.xml 생성 (헬퍼 함수)
    
    Args:
        merged_snippets_path: merged_snippets.json 경로
        output_xml_path: 출력 XML 경로
        schema_path: XSD 스키마 경로 (선택)
        validate: 검증 수행 여부
        options: 렌더링 옵션
    
    Returns:
        생성된 XML 파일 경로
    """
    workflow = SASTXMLWorkflow(
        schema_path=schema_path,
        auto_validate=validate,
    )
    
    return workflow.process_sast_results(
        merged_snippets_path=merged_snippets_path,
        output_xml_path=output_xml_path,
        options=options,
    )


__all__ = [
    "SASTXMLWorkflow",
    "create_custom_context_xml",
]
