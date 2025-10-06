"""
Vulnerability Scanner Module - Domain vulnerability scanning with port scanning and SSL analysis
"""

import asyncio
import socket
import ssl
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
import subprocess

from ..utils.validators import validate_domain, validate_ip
from ..config.settings import get_settings

class VulnScanner:
    """
    Vulnerability scanner for domains and IPs
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or get_settings()
        self.logger = logging.getLogger(__name__)
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]
        
    async def scan_target(self, target: str) -> Dict[str, Any]:
        """
        Scan a target for vulnerabilities
        
        Args:
            target: Domain or IP address
            
        Returns:
            Scan results
        """
        if not (validate_domain(target) or validate_ip(target)):
            raise ValueError(f"Invalid target: {target}")
        
        results = {
            'target': target,
            'scan_time': datetime.now().isoformat(),
            'ports': await self._scan_ports(target),
            'ssl': await self._check_ssl(target),
            'dns': await self._check_dns(target)
        }
        
        return results
    
    async def _scan_ports(self, target: str) -> List[Dict[str, Any]]:
        """
        Scan common ports on target
        
        Args:
            target: Target host
            
        Returns:
            List of open ports with details
        """
        open_ports = []
        
        for port in self.common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                
                if result == 0:
                    service = socket.getservbyport(port) if port < 1024 else 'unknown'
                    open_ports.append({
                        'port': port,
                        'state': 'open',
                        'service': service
                    })
                
                sock.close()
                
            except Exception as e:
                self.logger.debug(f"Error scanning port {port}: {str(e)}")
        
        return open_ports
    
    async def _check_ssl(self, target: str) -> Dict[str, Any]:
        """
        Check SSL/TLS configuration
        
        Args:
            target: Target host
            
        Returns:
            SSL/TLS information
        """
        try:
            context = ssl.create_default_context()
            with socket.create_connection((target, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'enabled': True,
                        'version': ssock.version(),
                        'cipher': ssock.cipher(),
                        'certificate': {
                            'subject': cert.get('subject'),
                            'issuer': cert.get('issuer'),
                            'valid_from': cert.get('notBefore'),
                            'valid_until': cert.get('notAfter')
                        }
                    }
        except Exception as e:
            return {'enabled': False, 'error': str(e)}
    
    async def _check_dns(self, target: str) -> Dict[str, Any]:
        """
        Check DNS configuration
        
        Args:
            target: Target domain
            
        Returns:
            DNS information
        """
        try:
            ip_address = socket.gethostbyname(target)
            hostname = socket.gethostbyaddr(ip_address)
            
            return {
                'ip_address': ip_address,
                'hostname': hostname[0],
                'aliases': hostname[1]
            }
        except Exception as e:
            return {'error': str(e)}
    
    def get_status(self) -> Dict[str, Any]:
        return {'service': 'vuln_scanner', 'status': 'active'}
    
    async def cleanup(self):
        self.logger.info("Vulnerability scanner cleaned up")
