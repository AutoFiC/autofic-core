import json
import os
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional
import logging

from .models import ParsedVuln, CodeSnippet

logger = logging.getLogger(__name__)


class SidecarGenerator:
    
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate(self, vulns: List[ParsedVuln], snippets: Dict[str, CodeSnippet]) -> Path:

        if not vulns:
            raise ValueError("No vulnerabilities to generate sidecar for")
        
        file_path = vulns[0].path
        safe_filename = file_path.replace('/', '_').replace('\\', '_')
        output_file = self.output_dir / f"{safe_filename}.ann.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        sidecar_data = {
            "file": file_path,
            "annotations": [
                self._create_annotation(vuln, snippets.get(vuln.id))
                for vuln in vulns
            ]
        }
        
        self._atomic_write(output_file, sidecar_data)
        
        logger.info(f"Generated sidecar: {output_file}")
        return output_file
    
    def _create_annotation(self, vuln: ParsedVuln, code_snippet: Optional[CodeSnippet]) -> Dict[str, Any]:

        annotation = {
            "id": vuln.id,
            "range": {
                "start": vuln.start_line,
                "end": vuln.end_line
            },
            "rule": vuln.rule,
            "tool": vuln.tool,
            "confidence": vuln.confidence,
            "severity": vuln.severity,
            "message": vuln.message,
            "unmapped": vuln.unmapped
        }
        
        if code_snippet:
            annotation["snippet"] = {
                "before": code_snippet.before,
                "match": code_snippet.match,
                "after": code_snippet.after
            }
        
        if vuln.bit:
            annotation["bit"] = {
                "trigger": vuln.bit.trigger,
                "reproduction": vuln.bit.reproduction,
                "recommendation": vuln.bit.recommendation,
                "severity": vuln.bit.severity,
                "steps": [
                    {
                        "type": step.type.value,
                        "description": step.description,
                        "order": step.order,
                        "code_snippet": step.code_snippet
                    }
                    for step in vuln.bit.steps
                ]
            }
        
        if vuln.merged_from:
            annotation["merged_from"] = vuln.merged_from
        
        return annotation
    
    def _atomic_write(self, filepath: Path, data: Dict[str, Any]):
        fd, temp_path = tempfile.mkstemp(
            dir=filepath.parent,
            prefix=f".{filepath.name}~",
            suffix=".tmp"
        )
        
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            
            os.replace(temp_path, filepath)
            
        except Exception as e:
            try:
                os.remove(temp_path)
            except:
                pass
            raise e