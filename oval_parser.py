"""Enhanced OVAL XML parser with deep pattern extraction."""

import xml.etree.ElementTree as ET
from typing import Dict, List, Set, Optional, Any, Tuple
from collections import defaultdict
import re
from urllib.parse import urlparse
import logging

# Set up logging
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)


class OVALParser:
    """Enhanced parser to extract comprehensive learnings from merged OVAL XML files."""
    
    def __init__(self, xml_path: str):
        """
        Initialize OVAL parser.
        
        Args:
            xml_path: Path to OVAL XML file
        """
        self.xml_path = xml_path
        self.tree = None
        self.root = None
        self.namespace = '{http://oval.mitre.org/XMLSchema/oval-definitions-5}'
        
    def parse(self):
        """Parse the OVAL XML file efficiently."""
        try:
            # Use iterparse for large files to avoid loading everything into memory
            self.tree = ET.parse(self.xml_path)
            self.root = self.tree.getroot()
        except ET.ParseError as e:
            print(f"Error parsing OVAL XML: {e}")
            raise
        except FileNotFoundError as e:
            print(f"OVAL XML file not found: {e}")
            raise
    
    def extract_cpe_patterns(self) -> Dict[str, List[str]]:
        """Extract CPE patterns from OVAL definitions."""
        cpe_patterns = defaultdict(list)
        
        if self.tree is None:
            self.parse()
        
        # Find all CPE references - improved method
        for definition in self.root.findall(f'.//{self.namespace}definition'):
            # Find product in this definition
            product_elem = definition.find(f'.//{self.namespace}product')
            product = product_elem.text if product_elem is not None else None
            
            # Find CPE references in this definition
            cpe_refs = definition.findall(f'.//{self.namespace}reference[@source="CPE"]')
            for ref in cpe_refs:
                cpe_id = ref.get('ref_id', '')
                if cpe_id and product:
                    cpe_patterns[product].append(cpe_id)
        
        return dict(cpe_patterns)
    
    def extract_version_patterns(self) -> List[Dict[str, Any]]:
        """Extract comprehensive version check patterns from test comments."""
        version_patterns = []
        
        if self.tree is None:
            self.parse()
        
        # Find all criterion comments that mention versions
        for criterion in self.root.findall(f'.//{self.namespace}criterion'):
            comment = criterion.get('comment', '')
            if 'version' in comment.lower():
                # Extract version pattern - multiple formats
                patterns = [
                    (r'less than ([0-9.]+)', 'less_than'),
                    (r'greater than ([0-9.]+)', 'greater_than'),
                    (r'equal to ([0-9.]+)', 'equal_to'),
                    (r'version ([0-9.]+)', 'version'),
                ]
                
                for pattern, pattern_type in patterns:
                    version_match = re.search(pattern, comment, re.IGNORECASE)
                    if version_match:
                        version = version_match.group(1)
                        test_ref = criterion.get('test_ref', '')
                        
                        # Extract installation method from comment
                        install_method = None
                        if 'exe' in comment.lower() or '.exe' in comment.lower():
                            install_method = 'exe'
                        elif 'pip' in comment.lower():
                            install_method = 'pip'
                        elif 'microsoft store' in comment.lower() or 'ms.store' in comment.lower():
                            install_method = 'microsoft_store'
                        
                        version_patterns.append({
                            'pattern': version,
                            'pattern_type': pattern_type,
                            'comment': comment,
                            'format': self._classify_version_format(version),
                            'test_ref': test_ref,
                            'install_method': install_method
                        })
                        break  # Only match first pattern
        
        return version_patterns
    
    def _classify_version_format(self, version: str) -> str:
        """Classify version format (semantic, date-based, etc.)."""
        # Remove common prefixes
        version = re.sub(r'^v', '', version, flags=re.IGNORECASE)
        version = version.strip()
        
        if re.match(r'^\d+\.\d+\.\d+', version):
            return 'semantic'
        elif re.match(r'^\d+\.\d+', version):
            return 'major.minor'
        elif re.match(r'^\d+$', version):
            return 'integer'
        elif re.match(r'^\d+\.\d+\.\d+\.\d+', version):
            return 'four_part'
        else:
            return 'custom'
    
    def extract_product_naming(self) -> Dict[str, List[str]]:
        """Extract product naming conventions with variants."""
        product_names = defaultdict(set)
        
        if self.tree is None:
            self.parse()
        
        # Extract product names from definitions
        for product_elem in self.root.findall(f'.//{self.namespace}product'):
            product = product_elem.text
            if product:
                normalized = self._normalize_product_name(product)
                product_names[normalized].add(product)
        
        return {k: sorted(list(v)) for k, v in product_names.items()}
    
    def _normalize_product_name(self, name: str) -> str:
        """Normalize product name for comparison."""
        # Convert to lowercase, remove special chars
        normalized = re.sub(r'[^a-z0-9]', '', name.lower())
        return normalized
    
    def extract_required_fields(self) -> Dict[str, List[str]]:
        """Extract required fields from metadata."""
        required_fields = {
            'metadata': [],
            'references': [],
            'platforms': []
        }
        
        if self.tree is None:
            self.parse()
        
        # Check what fields are consistently present
        for definition in self.root.findall(f'.//{self.namespace}definition'):
            metadata = definition.find(f'.//{self.namespace}metadata')
            if metadata is not None:
                # Check for title
                if metadata.find(f'.//{self.namespace}title') is not None:
                    if 'title' not in required_fields['metadata']:
                        required_fields['metadata'].append('title')
                
                # Check for description
                if metadata.find(f'.//{self.namespace}description') is not None:
                    if 'description' not in required_fields['metadata']:
                        required_fields['metadata'].append('description')
                
                # Check for references
                refs = metadata.findall(f'.//{self.namespace}reference')
                if refs:
                    for ref in refs:
                        source = ref.get('source', '')
                        if source and source not in required_fields['references']:
                            required_fields['references'].append(source)
        
        return required_fields
    
    def extract_description_patterns(self) -> Dict[str, Any]:
        """Extract patterns from vulnerability descriptions."""
        patterns = {
            'version_mentions': [],
            'prior_to_patterns': [],
            'fixed_in_patterns': [],
            'common_phrases': []
        }
        
        if self.tree is None:
            self.parse()
        
        for desc_elem in self.root.findall(f'.//{self.namespace}description'):
            desc_text = desc_elem.text or ''
            
            # Extract "Prior to version X" patterns
            prior_matches = re.findall(r'prior to version ([0-9.]+)', desc_text, re.IGNORECASE)
            patterns['prior_to_patterns'].extend(prior_matches)
            
            # Extract "fixed in version X" patterns
            fixed_matches = re.findall(r'(?:fixed|patched|resolved) in version ([0-9.]+)', desc_text, re.IGNORECASE)
            patterns['fixed_in_patterns'].extend(fixed_matches)
            
            # Extract version mentions
            version_matches = re.findall(r'version ([0-9.]+)', desc_text, re.IGNORECASE)
            patterns['version_mentions'].extend(version_matches)
        
        # Remove duplicates
        for key in patterns:
            patterns[key] = list(set(patterns[key]))
        
        return patterns
    
    def extract_criteria_patterns(self) -> Dict[str, Any]:
        """Extract patterns from criteria structures."""
        patterns = {
            'inventory_extend': [],
            'version_check_methods': defaultdict(list),
            'operator_patterns': defaultdict(int)
        }
        
        if self.tree is None:
            self.parse()
        
        for definition in self.root.findall(f'.//{self.namespace}definition'):
            criteria = definition.find(f'.//{self.namespace}criteria')
            if criteria is not None:
                operator = criteria.get('operator', '')
                patterns['operator_patterns'][operator] += 1
                
                # Check for extend_definition (inventory check)
                extend_defs = criteria.findall(f'.//{self.namespace}extend_definition')
                for ext_def in extend_defs:
                    def_ref = ext_def.get('definition_ref', '')
                    patterns['inventory_extend'].append(def_ref)
                
                # Check for version criteria with OR operator (multiple methods)
                version_criteria = criteria.findall(f'.//{self.namespace}criteria[@operator="OR"]')
                for vc in version_criteria:
                    comment = vc.get('comment', '')
                    if 'version' in comment.lower() or 'installed' in comment.lower():
                        methods = []
                        if 'exe' in comment.lower():
                            methods.append('exe')
                        if 'pip' in comment.lower():
                            methods.append('pip')
                        if 'microsoft store' in comment.lower() or 'ms.store' in comment.lower():
                            methods.append('microsoft_store')
                        
                        if methods:
                            product = self._extract_product_from_definition(definition)
                            patterns['version_check_methods'][product].extend(methods)
        
        # Remove duplicates
        for product in patterns['version_check_methods']:
            patterns['version_check_methods'][product] = list(set(patterns['version_check_methods'][product]))
        
        return patterns
    
    def _extract_product_from_definition(self, definition) -> str:
        """Extract product name from definition."""
        product_elem = definition.find(f'.//{self.namespace}product')
        return product_elem.text if product_elem is not None else "Unknown"
    
    def extract_vendor_urls(self) -> Dict[str, Dict[str, Any]]:
        """Extract all vendor URLs from OVAL definitions with enhanced metadata."""
        vendor_urls = defaultdict(list)
        
        if self.tree is None:
            self.parse()
        
        # Find all definitions
        for definition in self.root.findall(f'.//{self.namespace}definition'):
            metadata = definition.find(f'.//{self.namespace}metadata')
            if metadata is not None:
                # Extract product name
                product_elem = metadata.find(f'.//{self.namespace}product')
                product = product_elem.text if product_elem is not None else "Unknown"
                
                # Extract CVE ID if available
                cve_refs = metadata.findall(f'.//{self.namespace}reference[@source="CVE"]')
                cve_ids = [ref.get('ref_id', '') for ref in cve_refs]
                
                # Extract definition class (inventory vs vulnerability)
                def_class = definition.get('class', 'unknown')
                
                # Extract all references (VENDOR, MISC, etc.)
                all_refs = metadata.findall(f'.//{self.namespace}reference')
                for ref in all_refs:
                    source = ref.get('source', '')
                    ref_url = ref.get('ref_url', '')
                    ref_id = ref.get('ref_id', '')
                    
                    # Focus on vendor-related sources
                    if source in ['VENDOR', 'MISC', 'CONFIRM', 'BUGTRAQ', 'SECUNIA'] and ref_url:
                        domain = urlparse(ref_url).netloc
                        
                        vendor_urls[product].append({
                            'url': ref_url,
                            'source': source,
                            'domain': domain,
                            'cve_ids': cve_ids,
                            'ref_id': ref_id,
                            'definition_class': def_class
                        })
        
        # Remove duplicates and organize by domain
        organized = {}
        for product, urls in vendor_urls.items():
            by_domain = defaultdict(list)
            seen_urls = set()
            
            for url_info in urls:
                url = url_info['url']
                if url not in seen_urls:
                    seen_urls.add(url)
                    by_domain[url_info['domain']].append(url_info)
            
            organized[product] = {
                'domains': dict(by_domain),
                'all_urls': list(seen_urls),
                'total_count': len(seen_urls),
                'cve_coverage': len(set(cve_id for url_info in urls for cve_id in url_info['cve_ids']))
            }
        
        return organized
    
    def extract_learnings(self) -> Dict[str, Any]:
        """Extract comprehensive learnings from the OVAL XML file."""
        if self.tree is None:
            self.parse()
        
        learnings = {
            'cpe_patterns': self.extract_cpe_patterns(),
            'version_patterns': self.extract_version_patterns(),
            'product_naming': self.extract_product_naming(),
            'required_fields': self.extract_required_fields(),
            'description_patterns': self.extract_description_patterns(),
            'criteria_patterns': self.extract_criteria_patterns(),
            'version_mistakes': self._identify_version_mistakes(),
            'common_cpe_formats': self._extract_common_cpe_formats(),
            'best_practices': self._extract_best_practices()
        }
        
        return learnings
    
    def _identify_version_mistakes(self) -> List[str]:
        """Identify common version mistakes from patterns."""
        mistakes = []
        
        version_patterns = self.extract_version_patterns()
        
        # Check for inconsistent formats
        formats = [p['format'] for p in version_patterns]
        if len(set(formats)) > 1:
            mistakes.append("Mixed version formats detected - ensure consistency within product")
        
        # Check for version ranges that might be off-by-one
        for pattern in version_patterns:
            version = pattern['pattern']
            if '.' in version:
                parts = version.split('.')
                if len(parts) == 3:
                    # Check if patch version is 0 (might indicate off-by-one)
                    if parts[2] == '0':
                        mistakes.append(f"Version {version} ends in .0 - verify if this is correct or off-by-one")
        
        # Check for dev versions (e.g., 1.7.0.dev45)
        for pattern in version_patterns:
            if 'dev' in pattern['pattern'].lower() or 'alpha' in pattern['pattern'].lower() or 'beta' in pattern['pattern'].lower():
                mistakes.append(f"Development version detected ({pattern['pattern']}) - verify if this is the correct fixed version")
        
        return mistakes
    
    def _extract_common_cpe_formats(self) -> List[str]:
        """Extract common CPE format patterns."""
        cpe_patterns = self.extract_cpe_patterns()
        formats = []
        
        for product, cpes in cpe_patterns.items():
            for cpe in cpes:
                if cpe.startswith('cpe:2.3:'):
                    parts = cpe.split(':')
                    if len(parts) >= 5:
                        format_pattern = f"cpe:2.3:{parts[2]}:{parts[3]}:{parts[4]}:*:*:*:*:*:*:*"
                        if format_pattern not in formats:
                            formats.append(format_pattern)
        
        return formats[:20]
    
    def _extract_best_practices(self) -> Dict[str, Any]:
        """Extract best practices from successful OVAL definitions."""
        practices = {
            'inventory_first': True,  # Inventory definitions come before vulnerability definitions
            'extend_inventory': True,  # Vulnerability definitions extend inventory definitions
            'multiple_methods': [],  # Products with multiple installation methods
            'reference_sources': defaultdict(int),  # Most common reference sources
            'description_length': []  # Description lengths
        }
        
        if self.tree is None:
            self.parse()
        
        # Analyze definition order
        definitions = self.root.findall(f'.//{self.namespace}definition')
        inventory_count = 0
        vulnerability_count = 0
        
        for def_elem in definitions:
            def_class = def_elem.get('class', '')
            if def_class == 'inventory':
                inventory_count += 1
            elif def_class == 'vulnerability':
                vulnerability_count += 1
                
                # Check if it extends an inventory definition
                criteria = def_elem.find(f'.//{self.namespace}criteria')
                if criteria is not None:
                    extend_defs = criteria.findall(f'.//{self.namespace}extend_definition')
                    if extend_defs:
                        practices['extend_inventory'] = True
        
        # Analyze reference sources
        for ref in self.root.findall(f'.//{self.namespace}reference'):
            source = ref.get('source', '')
            if source:
                practices['reference_sources'][source] += 1
        
        # Analyze description lengths
        for desc in self.root.findall(f'.//{self.namespace}description'):
            if desc.text:
                practices['description_length'].append(len(desc.text))
        
        practices['avg_description_length'] = (
            sum(practices['description_length']) / len(practices['description_length'])
            if practices['description_length'] else 0
        )
        
        return practices
