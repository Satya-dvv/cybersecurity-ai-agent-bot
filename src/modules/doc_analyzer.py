"""
Document Analyzer Module - Security analyzer for documents with pattern detection
"""

import logging
import re
from typing import Dict, Any, Optional, List
from datetime import datetime

from ..config.settings import get_settings

class DocumentAnalyzer:
    """
    Document security analyzer with pattern detection
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or get_settings()
        self.logger = logging.getLogger(__name__)
        self.patterns = self._init_patterns()
        
    def _init_patterns(self) -> Dict[str, str]:
        """
        Initialize security patterns
        
        Returns:
            Dictionary of regex patterns
        """
        return {
            'api_key': r'(?i)(api[_-]?key|apikey)[\s:=]+["\']?([a-zA-Z0-9_\-]{20,})["\']?',
            'password': r'(?i)(password|passwd|pwd)[\s:=]+["\']?([^\s"\';]+)["\']?',
            'ip_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'private_key': r'-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----',
            'aws_key': r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
        }
    
    async def analyze_document(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze document for security issues
        
        Args:
            file_path: Path to document file
            
        Returns:
            Analysis results
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            findings = []
            for pattern_name, pattern in self.patterns.items():
                matches = re.findall(pattern, content)
                if matches:
                    findings.append({
                        'type': pattern_name,
                        'count': len(matches),
                        'severity': 'high' if pattern_name in ['api_key', 'password', 'private_key', 'aws_key'] else 'medium'
                    })
            
            return {
                'file_path': file_path,
                'analyzed_at': datetime.now().isoformat(),
                'total_findings': len(findings),
                'findings': findings,
                'risk_level': self._calculate_risk(findings)
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing document: {str(e)}")
            return {'error': str(e)}
    
    def _calculate_risk(self, findings: List[Dict]) -> str:
        """
        Calculate overall risk level
        
        Args:
            findings: List of findings
            
        Returns:
            Risk level string
        """
        if not findings:
            return 'low'
        
        high_count = sum(1 for f in findings if f.get('severity') == 'high')
        
        if high_count > 0:
            return 'critical'
        elif len(findings) > 3:
            return 'high'
        else:
            return 'medium'
    
    def get_status(self) -> Dict[str, Any]:
        return {'service': 'doc_analyzer', 'status': 'active'}
    
    async def cleanup(self):
        self.logger.info("Document analyzer cleaned up")
