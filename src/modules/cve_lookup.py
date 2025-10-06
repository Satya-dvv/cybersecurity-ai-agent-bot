"""
CVE Lookup Module - Integrates with NVD and CIRCL CVE databases
"""

import asyncio
import aiohttp
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
import json

from ..utils.api_client import SecureHTTPClient
from ..utils.validators import validate_cve_id
from ..config.settings import get_settings

class CVELookup:
    """
    CVE database lookup service integrating multiple sources
    """
    
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CIRCL_API_BASE = "https://cve.circl.lu/api"
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize CVE lookup service
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or get_settings()
        self.logger = logging.getLogger(__name__)
        self.http_client = SecureHTTPClient()
        self.cache = {}
        self.cache_ttl = self.config.get('cve_cache_ttl', 3600)
        
    async def lookup_cve(self, cve_id: str) -> Dict[str, Any]:
        """
        Lookup CVE information from multiple sources
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2023-1234)
            
        Returns:
            Dictionary containing CVE information
        """
        # Validate CVE ID
        if not validate_cve_id(cve_id):
            raise ValueError(f"Invalid CVE ID format: {cve_id}")
        
        cve_id = cve_id.upper()
        
        # Check cache
        if cve_id in self.cache:
            cached_data, timestamp = self.cache[cve_id]
            if (datetime.now().timestamp() - timestamp) < self.cache_ttl:
                self.logger.info(f"Returning cached data for {cve_id}")
                return cached_data
        
        # Fetch from multiple sources
        results = await asyncio.gather(
            self._fetch_from_nvd(cve_id),
            self._fetch_from_circl(cve_id),
            return_exceptions=True
        )
        
        # Merge results
        merged_data = self._merge_cve_data(cve_id, results)
        
        # Cache result
        self.cache[cve_id] = (merged_data, datetime.now().timestamp())
        
        return merged_data
    
    async def _fetch_from_nvd(self, cve_id: str) -> Dict[str, Any]:
        """
        Fetch CVE data from NVD
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            NVD CVE data
        """
        try:
            url = f"{self.NVD_API_BASE}?cveId={cve_id}"
            headers = {}
            
            # Add API key if available
            api_key = self.config.get('nvd_api_key')
            if api_key:
                headers['apiKey'] = api_key
            
            response = await self.http_client.get(url, headers=headers)
            
            if response and 'vulnerabilities' in response:
                if response['vulnerabilities']:
                    vuln = response['vulnerabilities'][0]
                    return self._parse_nvd_response(vuln)
            
            return {'source': 'nvd', 'found': False}
            
        except Exception as e:
            self.logger.error(f"Error fetching from NVD: {str(e)}")
            return {'source': 'nvd', 'error': str(e)}
    
    async def _fetch_from_circl(self, cve_id: str) -> Dict[str, Any]:
        """
        Fetch CVE data from CIRCL
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            CIRCL CVE data
        """
        try:
            url = f"{self.CIRCL_API_BASE}/cve/{cve_id}"
            response = await self.http_client.get(url)
            
            if response:
                return self._parse_circl_response(response)
            
            return {'source': 'circl', 'found': False}
            
        except Exception as e:
            self.logger.error(f"Error fetching from CIRCL: {str(e)}")
            return {'source': 'circl', 'error': str(e)}
    
    def _parse_nvd_response(self, vuln_data: Dict) -> Dict[str, Any]:
        """
        Parse NVD API response
        
        Args:
            vuln_data: Raw NVD vulnerability data
            
        Returns:
            Parsed CVE information
        """
        cve = vuln_data.get('cve', {})
        
        # Extract CVSS scores
        metrics = cve.get('metrics', {})
        cvss_v3 = None
        cvss_v2 = None
        
        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
            cvss_v3 = metrics['cvssMetricV31'][0].get('cvssData', {})
        elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
            cvss_v3 = metrics['cvssMetricV30'][0].get('cvssData', {})
        
        if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
            cvss_v2 = metrics['cvssMetricV2'][0].get('cvssData', {})
        
        # Extract descriptions
        descriptions = cve.get('descriptions', [])
        description = next((d['value'] for d in descriptions if d.get('lang') == 'en'), '')
        
        # Extract references
        references = cve.get('references', [])
        ref_urls = [ref.get('url') for ref in references]
        
        return {
            'source': 'nvd',
            'found': True,
            'id': cve.get('id'),
            'description': description,
            'published': cve.get('published'),
            'last_modified': cve.get('lastModified'),
            'cvss_v3': cvss_v3,
            'cvss_v2': cvss_v2,
            'references': ref_urls[:10],  # Limit to 10 references
            'cwe': self._extract_cwe(cve)
        }
    
    def _parse_circl_response(self, cve_data: Dict) -> Dict[str, Any]:
        """
        Parse CIRCL API response
        
        Args:
            cve_data: Raw CIRCL CVE data
            
        Returns:
            Parsed CVE information
        """
        return {
            'source': 'circl',
            'found': True,
            'id': cve_data.get('id'),
            'summary': cve_data.get('summary'),
            'published': cve_data.get('Published'),
            'modified': cve_data.get('Modified'),
            'cvss': cve_data.get('cvss'),
            'cwe': cve_data.get('cwe'),
            'references': cve_data.get('references', [])[:10]
        }
    
    def _extract_cwe(self, cve_data: Dict) -> Optional[List[str]]:
        """
        Extract CWE identifiers from CVE data
        
        Args:
            cve_data: CVE data dictionary
            
        Returns:
            List of CWE IDs
        """
        weaknesses = cve_data.get('weaknesses', [])
        cwe_ids = []
        
        for weakness in weaknesses:
            descriptions = weakness.get('description', [])
            for desc in descriptions:
                if desc.get('value', '').startswith('CWE-'):
                    cwe_ids.append(desc['value'])
        
        return cwe_ids if cwe_ids else None
    
    def _merge_cve_data(self, cve_id: str, results: List[Dict]) -> Dict[str, Any]:
        """
        Merge CVE data from multiple sources
        
        Args:
            cve_id: CVE identifier
            results: List of results from different sources
            
        Returns:
            Merged CVE information
        """
        merged = {
            'cve_id': cve_id,
            'sources': [],
            'data': {}
        }
        
        for result in results:
            if isinstance(result, dict) and result.get('found'):
                source = result.get('source')
                merged['sources'].append(source)
                
                if source == 'nvd':
                    merged['data']['nvd'] = result
                    # Prefer NVD data for primary fields
                    if 'description' not in merged['data']:
                        merged['data']['description'] = result.get('description')
                    merged['data']['cvss_v3'] = result.get('cvss_v3')
                    merged['data']['cvss_v2'] = result.get('cvss_v2')
                    merged['data']['published'] = result.get('published')
                    merged['data']['references'] = result.get('references', [])
                    merged['data']['cwe'] = result.get('cwe')
                    
                elif source == 'circl':
                    merged['data']['circl'] = result
                    if 'description' not in merged['data']:
                        merged['data']['description'] = result.get('summary')
        
        merged['data']['last_updated'] = datetime.now().isoformat()
        
        return merged
    
    async def search_cves(self, 
                          keyword: Optional[str] = None,
                          vendor: Optional[str] = None,
                          product: Optional[str] = None,
                          severity: Optional[str] = None,
                          limit: int = 20) -> List[Dict[str, Any]]:
        """
        Search for CVEs based on criteria
        
        Args:
            keyword: Search keyword
            vendor: Vendor name
            product: Product name
            severity: Severity level (LOW, MEDIUM, HIGH, CRITICAL)
            limit: Maximum number of results
            
        Returns:
            List of matching CVEs
        """
        # This would implement CVE search functionality
        # Placeholder for now
        self.logger.info(f"Searching CVEs with keyword={keyword}, vendor={vendor}, product={product}")
        return []
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get service status
        
        Returns:
            Status information
        """
        return {
            'service': 'cve_lookup',
            'status': 'active',
            'cache_size': len(self.cache),
            'sources': ['nvd', 'circl']
        }
    
    async def cleanup(self):
        """
        Cleanup resources
        """
        self.cache.clear()
        await self.http_client.close()
        self.logger.info("CVE Lookup service cleaned up")
