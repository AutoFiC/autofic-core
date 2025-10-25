"""Annotation Injector - 전체 워크플로우 관리"""

import json
import uuid
from pathlib import Path
from typing import List, Dict, Any, Optional
from collections import defaultdict
from datetime import datetime
import logging

from .models import ParsedVuln
from .xml_parser import XMLParser
from .mapper import LineMapper
from .sidecar import SidecarGenerator
from .schema_validator import SchemaValidator

logger = logging.getLogger(__name__)


class AnnotationInjector:
    """Annotation Injector 메인 클래스 (설계 명세 준수)"""
    
    def __init__(
        self,
        xml_path: Path,
        repo_root: Path,
        output_dir: Path,
        schema_path: Optional[Path] = None,
        xsd_path: Optional[Path] = None,
        trace_id: Optional[str] = None,
        fail_on_invalid: bool = False,
        context_lines: int = 3,
        fuzzy_threshold: float = 0.8
    ):
        # 1) 입력 검증 & 초기화
        self.xml_path = xml_path
        self.repo_root = repo_root
        self.output_dir = output_dir
        self.schema_path = schema_path
        self.xsd_path = xsd_path
        self.trace_id = trace_id or str(uuid.uuid4())[:8]
        self.fail_on_invalid = fail_on_invalid
        
        self.parser = XMLParser(xml_path, xsd_path)
        self.mapper = LineMapper(repo_root, context_lines, fuzzy_threshold)
        self.sidecar_gen = SidecarGenerator(output_dir / 'annotations')
        
        if schema_path and schema_path.exists():
            self.validator = SchemaValidator(schema_path)
        else:
            self.validator = None
            logger.warning("Schema validator not initialized (schema_path not provided)")
        
        self.stats = {
            'total': 0,
            'success': 0,
            'invalid': 0,
            'unmapped': 0,
            'merged': 0
        }
        
        logger.info(f"AnnotationInjector initialized [trace_id={self.trace_id}]")
    
    def run(self) -> Dict[str, Any]:
        """
        전체 처리 흐름 실행
        0. 실행 컨텍스트 구성
        1. 입력 검증 & XSD 검증
        2. XML 파싱
        3. 파일별 그룹화 & 병합
        4. 라인 매핑 보정
        5. SNIPPET 추출 & 정규화
        6. BIT 결합/정제 (이미 포함됨)
        7. Sidecar JSON 생성
        8. JSON 스키마 검증
        9. 리포트/종료
        """
        logger.info(f"Starting annotation injection [trace_id={self.trace_id}]")
        
        try:
            if self.xsd_path:
                self.parser.validate_with_xsd(fail_on_error=self.fail_on_invalid)

            vulnerabilities = self.parser.parse()
            self.stats['total'] = len(vulnerabilities)
            
            if not vulnerabilities:
                logger.warning("No vulnerabilities parsed from XML")
                return self._generate_report()

            grouped = self._group_by_file(vulnerabilities)
            merged = self._merge_duplicates(grouped)

            remapped = self._remap_all(merged)
            
            snippets = self._extract_snippets(remapped)
            
            sidecar_files = self._generate_sidecars(remapped, snippets)

            if self.validator:
                self._validate_sidecars(sidecar_files)

            report = self._generate_report()
            
            logger.info(f"Annotation injection completed [trace_id={self.trace_id}]")
            return report
            
        except Exception as e:
            logger.error(f"Annotation injection failed: {e}", exc_info=True)
            raise
    
    def _group_by_file(self, vulns: List[ParsedVuln]) -> Dict[str, List[ParsedVuln]]:
        grouped = defaultdict(list)
        for vuln in vulns:
            grouped[vuln.path].append(vuln)
        return dict(grouped)
    
    def _merge_duplicates(self, grouped: Dict[str, List[ParsedVuln]]) -> Dict[str, List[ParsedVuln]]:
        merged = {}
        
        for path, vulns in grouped.items():
            range_map = defaultdict(list)
            for vuln in vulns:
                key = (vuln.start_line, vuln.end_line)
                range_map[key].append(vuln)
            
            merged_vulns = []
            for (start, end), group in range_map.items():
                if len(group) == 1:
                    merged_vulns.append(group[0])
                else:
                    primary = group[0]
                    primary.merged_from = [v.id for v in group[1:]]
                    merged_vulns.append(primary)
                    self.stats['merged'] += len(group) - 1
            
            merged[path] = merged_vulns
        
        return merged
    
    def _remap_all(self, grouped: Dict[str, List[ParsedVuln]]) -> Dict[str, List[ParsedVuln]]:
        remapped = {}
        
        for path, vulns in grouped.items():
            remapped_vulns = []
            for vuln in vulns:
                remapped_vuln = self.mapper.remap_lines(vuln)
                remapped_vulns.append(remapped_vuln)
                
                if remapped_vuln.unmapped:
                    self.stats['unmapped'] += 1
            
            remapped[path] = remapped_vulns
        
        return remapped
    
    def _extract_snippets(self, grouped: Dict[str, List[ParsedVuln]]) -> Dict[str, Any]:
        snippets = {}
        
        for path, vulns in grouped.items():
            for vuln in vulns:
                snippet = self.mapper.extract_snippet(vuln)
                if snippet:
                    snippets[vuln.id] = snippet
                    vuln.code_snippet = snippet
        
        return snippets
    
    def _generate_sidecars(self, grouped: Dict[str, List[ParsedVuln]], snippets: Dict) -> List[Path]:
        sidecar_files = []
        
        for path, vulns in grouped.items():
            try:
                sidecar_file = self.sidecar_gen.generate(vulns, snippets)
                sidecar_files.append(sidecar_file)
            except Exception as e:
                logger.error(f"Failed to generate sidecar for {path}: {e}")
        
        return sidecar_files
    
    def _validate_sidecars(self, sidecar_files: List[Path]):
        invalid_dir = self.output_dir / 'invalid'
        
        for sidecar_file in sidecar_files:
            is_valid, error_msg = self.validator.validate_file(sidecar_file)
            
            if is_valid:
                self.stats['success'] += 1
            else:
                self.stats['invalid'] += 1
                
                self.validator.move_to_invalid(sidecar_file, invalid_dir)
                
                if self.fail_on_invalid:
                    raise ValueError(f"Schema validation failed: {error_msg}")
    
    def _generate_report(self) -> Dict[str, Any]:
        exit_code = 0
        if self.stats['invalid'] > 0 and self.fail_on_invalid:
            exit_code = 2  
        elif self.stats['unmapped'] > 0:
            exit_code = 0 
        
        report = {
            "trace_id": self.trace_id,
            "timestamp": datetime.now().isoformat(),
            "xml_path": str(self.xml_path),
            "statistics": self.stats,
            "exit_code": exit_code
        }
        
        report_dir = self.output_dir / '_report'
        report_dir.mkdir(parents=True, exist_ok=True)
        report_file = report_dir / f"{self.trace_id}.json"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Report saved: {report_file}")
        return report