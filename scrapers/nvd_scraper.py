"""NVD (National Vulnerability Database) scraper using the official NVD API v2."""

import requests
import time
from typing import Dict, List, Optional, Any
from datetime import datetime


class NVDScraper:
    """Scraper for NVD API v2 - modern and rate-limit aware."""
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    RATE_LIMIT_DELAY = 0.6  # NVD allows 50 requests per 30 seconds (0.6s between requests)
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize NVD scraper.
        
        Args:
            api_key: Optional NVD API key for higher rate limits (get from https://nvd.nist.gov/developers/request-an-api-key)
        """
        self.api_key = api_key
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({'apiKey': api_key})
        self.last_request_time = 0
    
    def _rate_limit(self):
        """Enforce rate limiting between requests."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.RATE_LIMIT_DELAY:
            time.sleep(self.RATE_LIMIT_DELAY - elapsed)
        self.last_request_time = time.time()
    
    def get_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch CVE data from NVD API v2.
        
        Args:
            cve_id: CVE identifier (e.g., 'CVE-2025-5591')
            
        Returns:
            Dictionary containing CVE data or None if not found
        """
        self._rate_limit()
        
        url = f"{self.BASE_URL}?cveId={cve_id}"
        
        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            if data.get('vulnerabilities') and len(data['vulnerabilities']) > 0:
                return data['vulnerabilities'][0]['cve']
            return None
            
        except requests.exceptions.RequestException as e:
            print(f"Error fetching CVE {cve_id} from NVD: {e}")
            return None
    
    def extract_cpe_list(self, cve_data: Dict[str, Any]) -> List[str]:
        """
        Extract CPE identifiers from CVE data.
        
        Args:
            cve_data: CVE data dictionary from NVD API
            
        Returns:
            List of CPE strings
        """
        cpes = []
        
        if 'configurations' in cve_data:
            for config in cve_data['configurations']:
                if 'nodes' in config:
                    for node in config['nodes']:
                        if 'cpeMatch' in node:
                            for cpe_match in node['cpeMatch']:
                                if 'criteria' in cpe_match:
                                    cpes.append(cpe_match['criteria'])
        
        return list(set(cpes))  # Remove duplicates
    
    def extract_version_ranges(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract version information from CVE data including build numbers from CPE strings.
        
        Args:
            cve_data: CVE data dictionary from NVD API
            
        Returns:
            Dictionary with version information including build numbers
        """
        version_info = {
            'vulnerable_versions': [],
            'fixed_versions': [],
            'cpe_details': [],
            'build_numbers': [],
            'version_ranges': []
        }
        
        if 'configurations' in cve_data:
            for config in cve_data['configurations']:
                if 'nodes' in config:
                    for node in config['nodes']:
                        if 'cpeMatch' in node:
                            for cpe_match in node['cpeMatch']:
                                cpe_str = cpe_match.get('criteria', '')
                                
                                # Extract version from CPE string
                                version = None
                                build_number = None
                                if cpe_str.startswith('cpe:2.3:'):
                                    parts = cpe_str.split(':')
                                    if len(parts) >= 6:
                                        version = parts[5] if parts[5] != '*' else None
                                        # Build number might be in update field (parts[6])
                                        if len(parts) >= 7 and parts[6] != '*':
                                            build_number = parts[6]
                                
                                cpe_info = {
                                    'cpe': cpe_str,
                                    'vulnerable': cpe_match.get('vulnerable', False),
                                    'version': version,
                                    'build_number': build_number,
                                    'versionStartIncluding': cpe_match.get('versionStartIncluding'),
                                    'versionStartExcluding': cpe_match.get('versionStartExcluding'),
                                    'versionEndIncluding': cpe_match.get('versionEndIncluding'),
                                    'versionEndExcluding': cpe_match.get('versionEndExcluding'),
                                }
                                
                                # Build version range string if applicable
                                if cpe_info['versionStartIncluding'] or cpe_info['versionEndIncluding']:
                                    range_parts = []
                                    if cpe_info['versionStartIncluding']:
                                        range_parts.append(f">={cpe_info['versionStartIncluding']}")
                                    if cpe_info['versionEndIncluding']:
                                        range_parts.append(f"<={cpe_info['versionEndIncluding']}")
                                    if range_parts:
                                        version_info['version_ranges'].append(' '.join(range_parts))
                                
                                version_info['cpe_details'].append(cpe_info)
                                
                                if build_number:
                                    version_info['build_numbers'].append(build_number)
                                
                                if cpe_info['vulnerable']:
                                    version_info['vulnerable_versions'].append(cpe_info)
                                else:
                                    version_info['fixed_versions'].append(cpe_info)
        
        # Remove duplicates
        version_info['build_numbers'] = list(set(version_info['build_numbers']))
        version_info['version_ranges'] = list(set(version_info['version_ranges']))
        
        return version_info
    
    def get_references(self, cve_data: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Extract references from CVE data.
        
        Args:
            cve_data: CVE data dictionary from NVD API
            
        Returns:
            List of reference dictionaries with 'url' and 'source' keys
        """
        references = []
        
        if 'references' in cve_data:
            for ref in cve_data['references']:
                references.append({
                    'url': ref.get('url', ''),
                    'source': ref.get('source', ''),
                    'tags': ref.get('tags', [])
                })
        
        return references
    
    def get_cwe(self, cve_data: Dict[str, Any]) -> Optional[str]:
        """
        Extract CWE (Common Weakness Enumeration) from CVE data.
        
        Args:
            cve_data: CVE data dictionary from NVD API
            
        Returns:
            CWE identifier or None
        """
        if 'weaknesses' in cve_data:
            for weakness in cve_data['weaknesses']:
                if 'description' in weakness and len(weakness['description']) > 0:
                    return weakness['description'][0].get('value')
        return None
