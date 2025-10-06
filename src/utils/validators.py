"""
Validators Module - Input validation functions
"""

import re
from typing import Any

def validate_cve_id(cve_id: str) -> bool:
    """Validate CVE ID format"""
    pattern = r'^CVE-\d{4}-\d{4,}$'
    return bool(re.match(pattern, cve_id, re.IGNORECASE))

def validate_domain(domain: str) -> bool:
    """Validate domain name format"""
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

def validate_ip(ip: str) -> bool:
    """Validate IP address format"""
    pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return bool(re.match(pattern, ip))

def validate_input(text: str, max_length: int = 10000) -> bool:
    """Validate general text input"""
    if not text or not isinstance(text, str):
        return False
    if len(text) > max_length:
        return False
    return True
