import xml.etree.ElementTree as ET
from xml.dom import minidom
from pathlib import Path
from typing import List
from datetime import datetime
import logging
import xml.sax.saxutils as saxutils
from autofic_core.sast.snippet import BaseSnippet

logger = logging.getLogger(__name__)


class ContextGenerator:
    
    NAMESPACE = 'urn:autofic:custom-context'
    
    def __init__(self, tool_name: str = "AutoFiC"):
        self.tool_name = tool_name
    
    def generate(self, snippets: List[BaseSnippet], output_path: Path) -> Path:
        
        ET.register_namespace('', self.NAMESPACE)
        ET.register_namespace('xsi', 'http://www.w3.org/2001/XMLSchema-instance')
        
        root = ET.Element(f'{{{self.NAMESPACE}}}CUSTOM_CONTEXT')
        root.set('version', '1.0')
        root.set(
            f'{{{ET.QName("http://www.w3.org/2001/XMLSchema-instance", "schemaLocation")}}}',
            f'{self.NAMESPACE} custom_context.xsd'
        )
        
        meta = ET.SubElement(root, f'{{{self.NAMESPACE}}}META')
        meta.set('generatedAt', datetime.now().isoformat())
        meta.set('tool', self.tool_name)
        meta.set('count', str(len(snippets)))
        
        for snippet in snippets:
            self._add_vulnerability(root, snippet)
        
        self._save_pretty_xml(root, output_path)
        
        logger.info(f"Generated CUSTOM_CONTEXT.xml: {output_path}")
        return output_path
    
    def _add_vulnerability(self, parent: ET.Element, snippet: BaseSnippet):

        vuln_id = f"{snippet.path}:{snippet.start_line}-{snippet.end_line}"
        
        vuln = ET.SubElement(parent, f'{{{self.NAMESPACE}}}VULNERABILITY')
        vuln.set('id', vuln_id)

        file_elem = ET.SubElement(vuln, f'{{{self.NAMESPACE}}}FILE')
        file_elem.set('path', snippet.path)
        
        range_elem = ET.SubElement(vuln, f'{{{self.NAMESPACE}}}RANGE')
        range_elem.set('start', str(snippet.start_line))
        range_elem.set('end', str(snippet.end_line))
        
        bit_severity = getattr(snippet, 'bit_severity', None) or snippet.severity or 'UNKNOWN'
        severity_elem = ET.SubElement(vuln, f'{{{self.NAMESPACE}}}SEVERITY')
        severity_elem.set('overall', snippet.severity or 'UNKNOWN')
        severity_elem.set('bit', bit_severity)
        
        # MESSAGE
        message_elem = ET.SubElement(vuln, f'{{{self.NAMESPACE}}}MESSAGE')
        #message_elem.text = snippet.message or ''
        
        # SNIPPET
        snippet_elem = ET.SubElement(vuln, f'{{{self.NAMESPACE}}}SNIPPET')
        #snippet_elem.text = snippet.snippet or ''
        snippet_elem.text = saxutils.escape(snippet.snippet or '')
        message_elem.text = saxutils.escape(snippet.message or '')
        
        # BIT
        if hasattr(snippet, 'bit_trigger') and snippet.bit_trigger:
            self._add_bit(vuln, snippet)
    
    def _add_bit(self, parent: ET.Element, snippet: BaseSnippet):
        bit = ET.SubElement(parent, f'{{{self.NAMESPACE}}}BIT')
        
        # TRIGGER
        trigger = ET.SubElement(bit, f'{{{self.NAMESPACE}}}TRIGGER')
        trigger.text = getattr(snippet, 'bit_trigger', None) or ''
        
        # STEPS
        if hasattr(snippet, 'bit_steps') and snippet.bit_steps:
            steps = ET.SubElement(bit, f'{{{self.NAMESPACE}}}STEPS')
            for step_text in snippet.bit_steps:
                step = ET.SubElement(steps, f'{{{self.NAMESPACE}}}STEP')
                step.text = step_text
        
        # REPRODUCTION
        reproduction = ET.SubElement(bit, f'{{{self.NAMESPACE}}}REPRODUCTION')
        reproduction.text = getattr(snippet, 'bit_reproduction', None) or ''
        
        # BIT_SEVERITY
        bit_severity = ET.SubElement(bit, f'{{{self.NAMESPACE}}}BIT_SEVERITY')
        bit_severity.text = getattr(snippet, 'bit_severity', None) or 'UNKNOWN'
    
    def _save_pretty_xml(self, root: ET.Element, output_path: Path):
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        xml_str = ET.tostring(root, encoding='unicode')
        dom = minidom.parseString(xml_str)
        pretty_xml = dom.toprettyxml(indent='  ', encoding='UTF-8')
        
        with open(output_path, 'wb') as f:
            f.write(pretty_xml)
