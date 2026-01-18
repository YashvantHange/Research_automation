"""GitHub Security Advisories scraper using GitHub API."""

import requests
from typing import Dict, List, Optional, Any
import re


class GitHubScraper:
    """Scraper for GitHub Security Advisories (GHSA) and repository information."""
    
    BASE_URL = "https://api.github.com"
    
    def __init__(self, token: Optional[str] = None):
        """
        Initialize GitHub scraper.
        
        Args:
            token: Optional GitHub personal access token for higher rate limits
        """
        self.token = token
        self.session = requests.Session()
        if token:
            self.session.headers.update({
                'Authorization': f'token {token}',
                'Accept': 'application/vnd.github.v3+json'
            })
        else:
            self.session.headers.update({
                'Accept': 'application/vnd.github.v3+json'
            })
    
    def get_ghsa(self, ghsa_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch GitHub Security Advisory by GHSA ID.
        
        Args:
            ghsa_id: GHSA identifier (e.g., 'GHSA-c5cp-vx83-jhqx')
            
        Returns:
            Dictionary containing GHSA data or None if not found
        """
        url = f"{self.BASE_URL}/advisories/{ghsa_id}"
        
        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching GHSA {ghsa_id}: {e}")
            return None
    
    def get_advisory_by_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Search for GitHub Security Advisory by CVE ID.
        
        Args:
            cve_id: CVE identifier (e.g., 'CVE-2025-5591')
            
        Returns:
            Dictionary containing GHSA data or None if not found
        """
        url = f"{self.BASE_URL}/advisories"
        params = {'cve_id': cve_id}
        
        try:
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            if isinstance(data, dict) and 'advisories' in data:
                advisories = data['advisories']
                if advisories and len(advisories) > 0:
                    return advisories[0]
            elif isinstance(data, list) and len(data) > 0:
                return data[0]
            
            return None
        except requests.exceptions.RequestException as e:
            print(f"Error searching GHSA for CVE {cve_id}: {e}")
            return None
    
    def extract_version_info(self, ghsa_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract version information from GHSA data.
        
        Args:
            ghsa_data: GHSA data dictionary
            
        Returns:
            Dictionary with version information
        """
        version_info = {
            'vulnerable_versions': [],
            'patched_versions': [],
            'description': ghsa_data.get('summary', ''),
            'severity': ghsa_data.get('severity', ''),
            'cvss_score': None
        }
        
        # Extract CVSS if available
        if 'cvss' in ghsa_data:
            version_info['cvss_score'] = ghsa_data['cvss'].get('score')
        
        # Parse vulnerable and patched versions from description
        description = ghsa_data.get('description', '')
        
        # Look for version patterns like "Prior to version X" or "before version X"
        patched_patterns = [
            r'prior to version ([0-9.]+)',
            r'before version ([0-9.]+)',
            r'version ([0-9.]+) contains a patch',
            r'version ([0-9.]+) fixes',
            r'fixed in version ([0-9.]+)',
            r'patched in version ([0-9.]+)',
        ]
        
        for pattern in patched_patterns:
            matches = re.findall(pattern, description, re.IGNORECASE)
            if matches:
                version_info['patched_versions'].extend(matches)
        
        # Look for vulnerable version ranges
        vulnerable_patterns = [
            r'versions? ([0-9.]+) through ([0-9.]+)',
            r'versions? ([0-9.]+) to ([0-9.]+)',
            r'all versions? (?:before|prior to|up to) ([0-9.]+)',
        ]
        
        for pattern in vulnerable_patterns:
            matches = re.findall(pattern, description, re.IGNORECASE)
            if matches:
                version_info['vulnerable_versions'].extend(matches)
        
        # Remove duplicates
        version_info['patched_versions'] = list(set(version_info['patched_versions']))
        version_info['vulnerable_versions'] = list(set(version_info['vulnerable_versions']))
        
        return version_info
    
    def get_repository_info(self, repo_owner: str, repo_name: str) -> Optional[Dict[str, Any]]:
        """
        Get repository information.
        
        Args:
            repo_owner: Repository owner/organization
            repo_name: Repository name
            
        Returns:
            Dictionary containing repository information
        """
        url = f"{self.BASE_URL}/repos/{repo_owner}/{repo_name}"
        
        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching repository {repo_owner}/{repo_name}: {e}")
            return None
    
    def search_releases(self, repo_owner: str, repo_name: str, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get recent releases from a repository.
        
        Args:
            repo_owner: Repository owner/organization
            repo_name: Repository name
            limit: Maximum number of releases to fetch
            
        Returns:
            List of release dictionaries
        """
        url = f"{self.BASE_URL}/repos/{repo_owner}/{repo_name}/releases"
        params = {'per_page': min(limit, 100)}
        
        try:
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()
            return response.json()[:limit]
        except requests.exceptions.RequestException as e:
            print(f"Error fetching releases for {repo_owner}/{repo_name}: {e}")
            return []
