"""Vendor URL database and cache system."""

import json
import pickle
from pathlib import Path
from typing import Dict, List, Set, Optional
from collections import defaultdict
from urllib.parse import urlparse
import hashlib
import os


class VendorDatabase:
    """Database for storing and querying vendor URLs extracted from OVAL XML."""
    
    def __init__(self, db_path: str = "data/vendor_db.json"):
        """
        Initialize vendor database.
        
        Args:
            db_path: Path to database file
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.pattern_memory_path = Path("data/vendor_pattern_memory.json")
        self.data = {
            'products': {},  # product -> vendor info
            'domains': {},   # domain -> products
            'urls': {},      # url -> metadata
            'cve_mappings': defaultdict(list)  # cve_id -> vendor urls
        }
        self._load()
        self.pattern_memory = self._load_pattern_memory()
    
    def _load(self):
        """Load database from file."""
        if self.db_path.exists():
            try:
                with open(self.db_path, 'r', encoding='utf-8') as f:
                    self.data = json.load(f)
                    # Convert defaultdict back
                    self.data['cve_mappings'] = defaultdict(list, self.data.get('cve_mappings', {}))
            except Exception as e:
                print(f"Warning: Could not load vendor database: {e}")
                self.data = {
                    'products': {},
                    'domains': {},
                    'urls': {},
                    'cve_mappings': defaultdict(list)
                }
    
    def save(self):
        """Save database to file."""
        try:
            with open(self.db_path, 'w', encoding='utf-8') as f:
                # Convert defaultdict to dict for JSON serialization
                data_to_save = self.data.copy()
                data_to_save['cve_mappings'] = dict(data_to_save['cve_mappings'])
                json.dump(data_to_save, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Error saving vendor database: {e}")

    def _load_pattern_memory(self) -> Dict:
        """Load vendor pattern memory from disk."""
        try:
            if self.pattern_memory_path.exists():
                with open(self.pattern_memory_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def _save_pattern_memory(self) -> None:
        """Persist vendor pattern memory to disk."""
        self.pattern_memory_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.pattern_memory_path, 'w', encoding='utf-8') as f:
            json.dump(self.pattern_memory, f, indent=2, ensure_ascii=False)

    def get_pattern_memory(self) -> Dict:
        """Return pattern memory."""
        return self.pattern_memory or {}

    def update_pattern_memory(self, domain: str, url_path: str, version_patterns: List[str]) -> None:
        """Update pattern memory for a vendor domain."""
        if not domain:
            return
        domain = domain.lower()
        entry = self.pattern_memory.get(domain, {'url_paths': [], 'version_patterns': []})
        if url_path and url_path not in entry['url_paths']:
            entry['url_paths'].append(url_path)
        for pattern in version_patterns:
            if pattern and pattern not in entry['version_patterns']:
                entry['version_patterns'].append(pattern)
        self.pattern_memory[domain] = entry
        self._save_pattern_memory()
    
    def add_vendor_urls(self, vendor_data: Dict[str, Dict]):
        """
        Add vendor URLs from OVAL parser output.
        
        Args:
            vendor_data: Dictionary from OVALParser.extract_vendor_urls()
        """
        for product, url_info in vendor_data.items():
            if product not in self.data['products']:
                self.data['products'][product] = {
                    'domains': {},
                    'urls': [],
                    'total_count': 0
                }
            
            # Add domains
            for domain, urls in url_info['domains'].items():
                if domain not in self.data['products'][product]['domains']:
                    self.data['products'][product]['domains'][domain] = []
                
                for url_entry in urls:
                    url = url_entry['url']
                    # Add to product URLs
                    if url not in self.data['products'][product]['urls']:
                        self.data['products'][product]['urls'].append(url)
                    
                    # Add to global URL index
                    if url not in self.data['urls']:
                        self.data['urls'][url] = {
                            'product': product,
                            'domain': domain,
                            'source': url_entry['source'],
                            'cve_ids': url_entry.get('cve_ids', []),
                            'ref_id': url_entry.get('ref_id', '')
                        }
                    
                    # Map CVE IDs to URLs
                    for cve_id in url_entry.get('cve_ids', []):
                        if url not in self.data['cve_mappings'][cve_id]:
                            self.data['cve_mappings'][cve_id].append(url)
                    
                    # Add to domain index
                    if domain not in self.data['domains']:
                        self.data['domains'][domain] = []
                    if product not in self.data['domains'][domain]:
                        self.data['domains'][domain].append(product)
            
            self.data['products'][product]['total_count'] = len(self.data['products'][product]['urls'])
        
        self.save()
    
    def get_vendor_urls_for_product(self, product: str) -> List[str]:
        """
        Get all vendor URLs for a product.
        
        Args:
            product: Product name
            
        Returns:
            List of vendor URLs
        """
        if product in self.data['products']:
            return self.data['products'][product]['urls']
        return []
    
    def get_vendor_domains_for_product(self, product: str) -> List[str]:
        """
        Get all vendor domains for a product.
        
        Args:
            product: Product name
            
        Returns:
            List of vendor domains
        """
        if product in self.data['products']:
            return list(self.data['products'][product]['domains'].keys())
        return []
    
    def get_urls_for_cve(self, cve_id: str) -> List[str]:
        """
        Get vendor URLs associated with a CVE.
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            List of vendor URLs
        """
        return self.data['cve_mappings'].get(cve_id, [])
    
    def search_products_by_domain(self, domain: str) -> List[str]:
        """
        Find products associated with a domain.
        
        Args:
            domain: Domain name
            
        Returns:
            List of product names
        """
        return self.data['domains'].get(domain, [])
    
    def get_all_domains(self) -> Set[str]:
        """Get all unique vendor domains."""
        return set(self.data['domains'].keys())
    
    def get_all_products(self) -> List[str]:
        """Get all products in database."""
        return list(self.data['products'].keys())
    
    def get_statistics(self) -> Dict:
        """Get database statistics."""
        return {
            'total_products': len(self.data['products']),
            'total_domains': len(self.data['domains']),
            'total_urls': len(self.data['urls']),
            'total_cve_mappings': len(self.data['cve_mappings']),
            'top_domains': sorted(
                [(domain, len(products)) for domain, products in self.data['domains'].items()],
                key=lambda x: x[1],
                reverse=True
            )[:10]
        }
