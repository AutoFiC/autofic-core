import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List
from autofic_core.sast.snippet import BaseSnippet
from errors import XMLExportError

class ContextGenerator:
    NAMESPACE = 'urn:autofic:custom-context'
    
    def __init__(self, tool_name: str = "AutoFiC"):
        self.tool_name = tool_name
    
    def generate(self, snippets: List[BaseSnippet], output_path: Path) -> Path:
        try:
            ET.register_namespace('', self.NAMESPACE)
            ET.register_namespace('xsi', 'http://www.w3.org/2001/XMLSchema-instance')
            
            root = ET.Element(f'{{{self.NAMESPACE}}}CUSTOM_CONTEXT')
            root.set('version', '1.0')
            meta = ET.SubElement(root, f'{{{self.NAMESPACE}}}META')
            meta.set('tool', self.tool_name)
            meta.set('count', str(len(snippets)))
            
            for snippet in snippets:
                self._add_vuln(root, snippet)
            
            tree = ET.ElementTree(root)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            tree.write(output_path, encoding="utf-8", xml_declaration=True)
            return output_path

        except Exception as e:
            print(f"[ERROR] CUSTOM_CONTEXT.xml export failed: {e}")
            raise XMLExportError(str(e))

    def _add_vuln(self, parent: ET.Element, snippet: BaseSnippet):
        ns = self.NAMESPACE
        vuln = ET.SubElement(parent, f'{{{ns}}}VULNERABILITY')
        vuln.set('id', f"{snippet.path}:{snippet.start_line}-{snippet.end_line}")
        file_elem = ET.SubElement(vuln, f'{{{ns}}}FILE')
        file_elem.set('path', snippet.path)
        range_elem = ET.SubElement(vuln, f'{{{ns}}}RANGE')
        range_elem.set('start', str(snippet.start_line))
        range_elem.set('end', str(snippet.end_line))
        sev_elem = ET.SubElement(vuln, f'{{{ns}}}SEVERITY')
        sev_elem.set('overall', snippet.severity or 'UNKNOWN')
        msg_elem = ET.SubElement(vuln, f'{{{ns}}}MESSAGE')
        msg_elem.text = snippet.message or ''
        snip_elem = ET.SubElement(vuln, f'{{{ns}}}SNIPPET')
        snip_elem.text = snippet.snippet or ''