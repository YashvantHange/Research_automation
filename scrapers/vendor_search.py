"""Intelligent vendor site search scraper."""

import requests
from bs4 import BeautifulSoup
from typing import Dict, List, Optional, Any
import re
from urllib.parse import urlparse, urljoin, quote
import time


class VendorSiteSearcher:
    """Intelligent scraper for searching vendor sites for CVE information."""
    
    def __init__(self):
        """Initialize vendor site searcher."""
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        self.search_patterns = self._load_search_patterns()
    
    def _load_search_patterns(self) -> Dict[str, Dict]:
        """Load search patterns for common vendor sites."""
        return {
            'github.com': {
                'search_url': 'https://github.com/search',
                'params': {'q': '{query}', 'type': 'Advisories'},
                'method': 'get'
            },
            'gitlab.com': {
                'search_url': 'https://gitlab.com/search',
                'params': {'search': '{query}'},
                'method': 'get'
            },
            'apache.org': {
                'search_url': 'https://www.apache.org/security/',
                'method': 'scrape_list'
            },
            'microsoft.com': {
                'search_url': 'https://msrc.microsoft.com/update-guide/vulnerability',
                'method': 'search_form'
            },
            'oracle.com': {
                'search_url': 'https://www.oracle.com/security-alerts/',
                'method': 'scrape_list'
            },
            'adobe.com': {
                'search_url': 'https://helpx.adobe.com/security.html',
                'method': 'scrape_list'
            }
        }
    
    def search_vendor_site(self, domain: str, cve_id: str, product: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Search a vendor site for CVE information.
        
        Args:
            domain: Vendor domain
            cve_id: CVE identifier
            product: Optional product name
            
        Returns:
            List of found URLs and metadata
        """
        results = []
        
        # Try direct CVE URL patterns
        direct_urls = self._try_direct_urls(domain, cve_id, product)
        results.extend(direct_urls)
        
        # Try site-specific search
        if domain in self.search_patterns:
            pattern = self.search_patterns[domain]
            if pattern['method'] == 'get':
                search_results = self._search_with_get(domain, cve_id, pattern)
                results.extend(search_results)
            elif pattern['method'] == 'scrape_list':
                scrape_results = self._scrape_security_page(domain, cve_id, pattern)
                results.extend(scrape_results)
        
        # Generic search fallback
        if not results:
            generic_results = self._generic_search(domain, cve_id)
            results.extend(generic_results)
        
        return results
    
    def _try_direct_urls(self, domain: str, cve_id: str, product: Optional[str] = None) -> List[Dict[str, Any]]:
        """Try common direct URL patterns."""
        results = []
        base_domain = domain.replace('www.', '')
        
        # Common patterns
        patterns = [
            f"https://{base_domain}/security/{cve_id}",
            f"https://{base_domain}/security-advisories/{cve_id}",
            f"https://{base_domain}/advisories/{cve_id}",
            f"https://{base_domain}/security/{cve_id.lower()}",
            f"https://{base_domain}/cve/{cve_id}",
            f"https://{base_domain}/security/{cve_id.replace('-', '')}",
        ]
        
        if product:
            product_slug = product.lower().replace(' ', '-')
            patterns.extend([
                f"https://{base_domain}/security/{product_slug}/{cve_id}",
                f"https://{base_domain}/{product_slug}/security/{cve_id}",
            ])
        
        for url in patterns:
            if self._check_url_exists(url):
                results.append({
                    'url': url,
                    'method': 'direct',
                    'confidence': 'high'
                })
        
        return results
    
    def _check_url_exists(self, url: str) -> bool:
        """Check if URL exists and contains CVE information."""
        try:
            response = self.session.head(url, timeout=10, allow_redirects=True)
            if response.status_code == 200:
                # Also check if page content mentions CVE
                content_response = self.session.get(url, timeout=10)
                if cve_id.lower() in content_response.text.lower():
                    return True
        except:
            pass
        return False
    
    def _search_with_get(self, domain: str, cve_id: str, pattern: Dict) -> List[Dict[str, Any]]:
        """Search using GET request with query parameters."""
        results = []
        try:
            query = f"{cve_id}"
            if 'params' in pattern:
                params = {k: v.format(query=query) for k, v in pattern['params'].items()}
                response = self.session.get(pattern['search_url'], params=params, timeout=15)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.content, 'html.parser')
                    # Extract links
                    links = soup.find_all('a', href=True)
                    for link in links:
                        href = link.get('href', '')
                        text = link.get_text(strip=True)
                        if cve_id.lower() in (href.lower() + text.lower()):
                            full_url = urljoin(pattern['search_url'], href)
                            results.append({
                                'url': full_url,
                                'method': 'search',
                                'confidence': 'medium',
                                'title': text
                            })
        except Exception as e:
            print(f"Error searching {domain}: {e}")
        
        return results[:5]  # Limit results
    
    def _scrape_security_page(self, domain: str, cve_id: str, pattern: Dict) -> List[Dict[str, Any]]:
        """Scrape security advisory listing page."""
        results = []
        try:
            response = self.session.get(pattern['search_url'], timeout=15)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                # Look for CVE mentions
                text_content = soup.get_text()
                if cve_id.lower() in text_content.lower():
                    # Find links that might contain CVE
                    links = soup.find_all('a', href=True)
                    for link in links:
                        href = link.get('href', '')
                        text = link.get_text(strip=True)
                        if cve_id.lower() in (href.lower() + text.lower()):
                            full_url = urljoin(pattern['search_url'], href)
                            results.append({
                                'url': full_url,
                                'method': 'scrape',
                                'confidence': 'medium',
                                'title': text
                            })
        except Exception as e:
            print(f"Error scraping {domain}: {e}")
        
        return results[:5]
    
    def _generic_search(self, domain: str, cve_id: str) -> List[Dict[str, Any]]:
        """Generic search fallback using site search."""
        results = []
        base_domain = domain.replace('www.', '')
        
        # Try common search endpoints
        search_endpoints = [
            f"https://{base_domain}/search?q={quote(cve_id)}",
            f"https://{base_domain}/search?query={quote(cve_id)}",
            f"https://{base_domain}/?s={quote(cve_id)}",
        ]
        
        for search_url in search_endpoints:
            try:
                response = self.session.get(search_url, timeout=10)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.content, 'html.parser')
                    # Look for CVE in links
                    links = soup.find_all('a', href=True)
                    for link in links[:20]:  # Limit search
                        href = link.get('href', '')
                        text = link.get_text(strip=True)
                        if cve_id.lower() in (href.lower() + text.lower()):
                            full_url = urljoin(search_url, href)
                            results.append({
                                'url': full_url,
                                'method': 'generic_search',
                                'confidence': 'low',
                                'title': text
                            })
            except:
                continue
        
        return results[:3]  # Limit results
