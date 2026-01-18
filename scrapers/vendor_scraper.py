"""Generic vendor advisory scraper using web scraping."""

import requests
from bs4 import BeautifulSoup
from typing import Dict, List, Optional, Any
import re
from urllib.parse import urlparse


class VendorScraper:
    """Generic scraper for vendor security advisories and release notes."""
    
    def __init__(self):
        """Initialize vendor scraper."""
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
    
    def scrape_advisory(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Scrape vendor advisory page.
        
        Args:
            url: URL of the vendor advisory
            
        Returns:
            Dictionary containing scraped data or None if failed
        """
        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract text content
            text = soup.get_text(separator=' ', strip=True)
            
            # Try to find title
            title = None
            if soup.title:
                title = soup.title.string
            elif soup.find('h1'):
                title = soup.find('h1').get_text(strip=True)
            
            # Extract version information
            version_info = self._extract_versions(text)
            
            # Extract CVE references
            cve_refs = re.findall(r'CVE-\d{4}-\d{4,}', text)
            
            return {
                'url': url,
                'title': title,
                'content': text[:5000],  # Limit content size
                'versions': version_info,
                'cve_references': list(set(cve_refs)),
                'domain': urlparse(url).netloc
            }
            
        except requests.exceptions.RequestException as e:
            print(f"Error scraping advisory {url}: {e}")
            return None
    
    def _extract_versions(self, text: str) -> Dict[str, List[str]]:
        """
        Extract version information from text with enhanced patterns including build numbers.
        
        Args:
            text: Text content to parse
            
        Returns:
            Dictionary with version lists including build numbers
        """
        versions = {
            'vulnerable': [],
            'fixed': [],
            'patched': [],
            'build_numbers': [],
            'version_ranges': []
        }
        
        # Enhanced patterns for fixed/patched versions
        fixed_patterns = [
            r'fixed in (?:version|v|release)?\s*([0-9.]+(?:\.[0-9]+)*(?:-[a-z0-9]+)?)',
            r'patched in (?:version|v|release)?\s*([0-9.]+(?:\.[0-9]+)*(?:-[a-z0-9]+)?)',
            r'(?:version|v|release)\s*([0-9.]+(?:\.[0-9]+)*(?:-[a-z0-9]+)?)\s+fixes',
            r'(?:version|v|release)\s*([0-9.]+(?:\.[0-9]+)*(?:-[a-z0-9]+)?)\s+contains a patch',
            r'resolved in (?:version|v|release)?\s*([0-9.]+(?:\.[0-9]+)*(?:-[a-z0-9]+)?)',
            r'upgrade to (?:version|v|release)?\s*([0-9.]+(?:\.[0-9]+)*(?:-[a-z0-9]+)?)',
            r'update to (?:version|v|release)?\s*([0-9.]+(?:\.[0-9]+)*(?:-[a-z0-9]+)?)',
        ]
        
        # Enhanced patterns for vulnerable versions
        vulnerable_patterns = [
            r'versions?\s+([0-9.]+(?:\.[0-9]+)*)\s+through\s+([0-9.]+(?:\.[0-9]+)*)',
            r'versions?\s+([0-9.]+(?:\.[0-9]+)*)\s+to\s+([0-9.]+(?:\.[0-9]+)*)',
            r'all versions?\s+(?:before|prior to|up to|until)\s+([0-9.]+(?:\.[0-9]+)*(?:-[a-z0-9]+)?)',
            r'versions?\s+(?:before|prior to|up to|until)\s+([0-9.]+(?:\.[0-9]+)*(?:-[a-z0-9]+)?)',
            r'<=\s*([0-9.]+(?:\.[0-9]+)*(?:-[a-z0-9]+)?)',
            r'<\s*([0-9.]+(?:\.[0-9]+)*(?:-[a-z0-9]+)?)',
            r'affected versions?\s+([0-9.]+(?:\.[0-9]+)*(?:-[a-z0-9]+)?)',
        ]
        
        # Build number patterns
        build_patterns = [
            r'build\s+(?:number\s+)?([0-9]+)',
            r'\(build\s+([0-9]+)\)',
            r'version\s+[0-9.]+\s+build\s+([0-9]+)',
            r'b([0-9]+)',  # Common abbreviation like "b1234"
            r'build\s+([0-9a-f]+)',  # Hex build numbers
        ]
        
        for pattern in fixed_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            versions['fixed'].extend([m if isinstance(m, str) else m[0] for m in matches])
            versions['patched'].extend([m if isinstance(m, str) else m[0] for m in matches])
        
        for pattern in vulnerable_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches and len(matches[0]) == 2:
                # Range match
                versions['version_ranges'].append(f"{matches[0][0]} to {matches[0][1]}")
            else:
                versions['vulnerable'].extend([m if isinstance(m, str) else m[0] for m in matches])
        
        for pattern in build_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            versions['build_numbers'].extend([m if isinstance(m, str) else str(m[0]) for m in matches])
        
        # Remove duplicates
        for key in versions:
            versions[key] = list(set(versions[key]))
        
        return versions
    
    def scrape_release_notes(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Scrape release notes or changelog.
        
        Args:
            url: URL of the release notes page
            
        Returns:
            Dictionary containing release notes data
        """
        return self.scrape_advisory(url)  # Same method works for release notes
