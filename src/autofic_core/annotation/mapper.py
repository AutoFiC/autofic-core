
import os
from pathlib import Path
from typing import List, Tuple, Optional
import difflib
import logging
import chardet

from .models import ParsedVuln, CodeSnippet

logger = logging.getLogger(__name__)


class LineMapper:
    
    def __init__(self, repo_root: Path, context_lines: int = 3, fuzzy_threshold: float = 0.8):
        self.repo_root = repo_root
        self.context_lines = context_lines
        self.fuzzy_threshold = fuzzy_threshold
    
    def remap_lines(self, vuln: ParsedVuln) -> ParsedVuln:
        file_path = self.repo_root / vuln.path
        
        if not file_path.exists():
            logger.warning(f"File not found: {file_path}")
            vuln.unmapped = True
            return vuln
        
        lines = self._read_file_with_encoding(file_path)
        if lines is None:
            vuln.unmapped = True
            return vuln
        
        if vuln.start_line <= 0 or vuln.end_line > len(lines):
            logger.warning(f"Line range out of bounds for {vuln.path}: {vuln.start_line}-{vuln.end_line}")
            new_range = self._find_snippet_location(vuln.snippet, lines)
            if new_range:
                vuln.start_line, vuln.end_line = new_range
                logger.info(f"Remapped lines for {vuln.id}: {vuln.start_line}-{vuln.end_line}")
            else:
                vuln.unmapped = True
        
        return vuln
    
    def extract_snippet(self, vuln: ParsedVuln) -> Optional[CodeSnippet]:
        file_path = self.repo_root / vuln.path
        
        if not file_path.exists():
            return None
        
        lines = self._read_file_with_encoding(file_path)
        if lines is None:
            return None
        
        start = max(0, vuln.start_line - 1) 
        end = min(len(lines), vuln.end_line)
        
        before_start = max(0, start - self.context_lines)
        after_end = min(len(lines), end + self.context_lines)
        
        return CodeSnippet(
            before=self._normalize_lines(lines[before_start:start]),
            match=self._normalize_lines(lines[start:end]),
            after=self._normalize_lines(lines[end:after_end])
        )
    
    def _read_file_with_encoding(self, file_path: Path) -> Optional[List[str]]:
        try:
            with open(file_path, 'rb') as f:
                raw_data = f.read()
                result = chardet.detect(raw_data)
                encoding = result['encoding'] or 'utf-8'
            
            with open(file_path, 'r', encoding=encoding, errors='replace') as f:
                return f.readlines()
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return None
    
    def _normalize_lines(self, lines: List[str]) -> List[str]:
        return [line.rstrip() for line in lines]
    
    def _find_snippet_location(self, snippet: Optional[str], lines: List[str]) -> Optional[Tuple[int, int]]:
        if not snippet:
            return None
        
        snippet_lines = snippet.strip().split('\n')
        
        exact_match = self._exact_match(snippet_lines, lines)
        if exact_match:
            return exact_match
        
        normalized_match = self._normalized_match(snippet_lines, lines)
        if normalized_match:
            return normalized_match

        fuzzy_match = self._fuzzy_match(snippet_lines, lines)
        if fuzzy_match:
            return fuzzy_match
        
        return None
    
    def _exact_match(self, snippet_lines: List[str], file_lines: List[str]) -> Optional[Tuple[int, int]]:

        snippet_text = '\n'.join(snippet_lines)
        
        for i in range(len(file_lines) - len(snippet_lines) + 1):
            candidate = '\n'.join(file_lines[i:i+len(snippet_lines)])
            if candidate == snippet_text:
                return (i + 1, i + len(snippet_lines))  # 1-based
        
        return None
    
    def _normalized_match(self, snippet_lines: List[str], file_lines: List[str]) -> Optional[Tuple[int, int]]:

        normalize = lambda s: ' '.join(s.split())
        snippet_normalized = [normalize(line) for line in snippet_lines]
        
        for i in range(len(file_lines) - len(snippet_lines) + 1):
            candidate_normalized = [normalize(file_lines[j]) for j in range(i, i+len(snippet_lines))]
            if candidate_normalized == snippet_normalized:
                return (i + 1, i + len(snippet_lines))
        
        return None
    
    def _fuzzy_match(self, snippet_lines: List[str], file_lines: List[str]) -> Optional[Tuple[int, int]]:

        snippet_text = '\n'.join(snippet_lines)
        best_match = None
        best_ratio = 0.0
        
        for i in range(len(file_lines) - len(snippet_lines) + 1):
            candidate = '\n'.join(file_lines[i:i+len(snippet_lines)])
            ratio = difflib.SequenceMatcher(None, snippet_text, candidate).ratio()
            
            if ratio > best_ratio and ratio >= self.fuzzy_threshold:
                best_ratio = ratio
                best_match = (i + 1, i + len(snippet_lines))
        
        if best_match:
            logger.info(f"Fuzzy match found with ratio {best_ratio:.2f}")
        
        return best_match