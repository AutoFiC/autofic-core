import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Optional
import logging
from lxml import etree

from .models import ParsedVuln, BITInfo, BITStep, StepType

logger = logging.getLogger(__name__)


class XMLParser:
    
    NAMESPACE = {'ns': 'urn:autofic:custom-context'}
    
    def __init__(self, xml_path: Path, xsd_path: Optional[Path] = None):
        self.xml_path = xml_path
        self.xsd_path = xsd_path
        self._validate_file_access()
        
    def _validate_file_access(self):
        if not self.xml_path.exists():
            raise FileNotFoundError(f"XML file not found: {self.xml_path}")
        if not self.xml_path.is_file():
            raise ValueError(f"Not a file: {self.xml_path}")
        import os
        if not os.access(self.xml_path, os.R_OK):
            raise PermissionError(f"Cannot read file: {self.xml_path}")
    
    def validate_with_xsd(self, fail_on_error: bool = False) -> bool:
        if not self.xsd_path or not self.xsd_path.exists():
            logger.warning("XSD file not provided, skipping XSD validation")
            return True
        
        try:
            with open(self.xsd_path, 'rb') as xsd_file:
                schema_root = etree.XML(xsd_file.read())
            schema = etree.XMLSchema(schema_root)
            
            with open(self.xml_path, 'rb') as xml_file:
                xml_doc = etree.parse(xml_file)
            
            is_valid = schema.validate(xml_doc)
            
            if not is_valid:
                error_log = '\n'.join(str(e) for e in schema.error_log)
                logger.error(f"XSD validation failed:\n{error_log}")
                
                if fail_on_error:
                    raise ValueError(f"XSD validation failed: {error_log}")
                return False
            
            logger.info("XSD validation successful")
            return True
            
        except Exception as e:
            logger.error(f"XSD validation error: {e}")
            if fail_on_error:
                raise
            return False
    
    def parse(self) -> List[ParsedVuln]:
        try:
            tree = ET.parse(self.xml_path)
            root = tree.getroot()
            
            vulnerabilities = []
            
            for vuln_elem in root.findall('.//ns:VULNERABILITY', self.NAMESPACE):
                vuln = self._parse_vulnerability(vuln_elem)
                if vuln:
                    vulnerabilities.append(vuln)
            
            logger.info(f"Parsed {len(vulnerabilities)} vulnerabilities from {self.xml_path}")
            return vulnerabilities
            
        except ET.ParseError as e:
            logger.error(f"XML parsing error: {e}")
            raise
    
    def _parse_vulnerability(self, elem: ET.Element) -> Optional[ParsedVuln]:
        try:
            vuln_id = elem.get('id', '')
            
            file_elem = elem.find('.//ns:FILE', self.NAMESPACE)
            file_path = file_elem.get('path', '') if file_elem is not None else ''
            
            range_elem = elem.find('.//ns:RANGE', self.NAMESPACE)
            start_line = int(range_elem.get('start', '0')) if range_elem is not None else 0
            end_line = int(range_elem.get('end', '0')) if range_elem is not None else 0
            
            # SEVERITY
            severity_elem = elem.find('.//ns:SEVERITY', self.NAMESPACE)
            severity = severity_elem.get('overall', '') if severity_elem is not None else ''
            
            # MESSAGE
            message_elem = elem.find('.//ns:MESSAGE', self.NAMESPACE)
            message = message_elem.text or '' if message_elem is not None else ''
            
            # SNIPPET
            snippet_elem = elem.find('.//ns:SNIPPET', self.NAMESPACE)
            snippet_text = snippet_elem.text or '' if snippet_elem is not None else ''
            
            # BIT
            bit_info = self._parse_bit(elem)
            
            # SOURCE
            source_elem = elem.find('.//ns:SOURCE', self.NAMESPACE)
            tool = source_elem.get('tool') if source_elem is not None else None
            
            return ParsedVuln(
                id=vuln_id,
                path=file_path,
                start_line=start_line,
                end_line=end_line,
                severity=severity,
                message=message,
                snippet=snippet_text,
                bit=bit_info,
                tool=tool
            )
            
        except Exception as e:
            logger.error(f"Error parsing vulnerability element: {e}")
            return None
    
    def _parse_bit(self, elem: ET.Element) -> Optional[BITInfo]:
        bit_elem = elem.find('.//ns:BIT', self.NAMESPACE)
        if bit_elem is None:
            return None
        
        trigger_elem = bit_elem.find('.//ns:TRIGGER', self.NAMESPACE)
        trigger = trigger_elem.text if trigger_elem is not None else None
        
        reproduction_elem = bit_elem.find('.//ns:REPRODUCTION', self.NAMESPACE)
        reproduction = reproduction_elem.text if reproduction_elem is not None else None
        
        bit_severity_elem = bit_elem.find('.//ns:BIT_SEVERITY', self.NAMESPACE)
        bit_severity = bit_severity_elem.text if bit_severity_elem is not None else None
        
        steps = []
        steps_elem = bit_elem.find('.//ns:STEPS', self.NAMESPACE)
        if steps_elem is not None:
            for idx, step_elem in enumerate(steps_elem.findall('.//ns:STEP', self.NAMESPACE)):
                if step_elem.text:
                    steps.append(BITStep(
                        type=StepType.NOTE,
                        description=step_elem.text,
                        order=idx
                    ))
        
        return BITInfo(
            trigger=trigger,
            steps=steps,
            reproduction=reproduction,
            severity=bit_severity
        )