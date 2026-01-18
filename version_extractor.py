"""Enhanced version extraction from multiple sources."""

import re
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse


class VersionExtractor:
    """Extract and format version information from various sources."""
    
    def __init__(self):
        """Initialize version extractor."""
        self.version_patterns = [
            r'version\s+([0-9.]+)',
            r'v([0-9.]+)',
            r'([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:\.[0-9]+)?)',
            r'(\d+\.\d+\.\d+)',
            r'(\d+\.\d+)',
        ]
    
    def extract_from_nvd_cpe(self, cpe_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract version information from NVD CPE data.
        
        Args:
            cpe_data: CPE match data from NVD
            
        Returns:
            Dictionary with version information
        """
        version_info = {
            'vulnerable': cpe_data.get('vulnerable', False),
            'version': None,
            'version_range': None,
            'cpe': cpe_data.get('cpe', '')
        }
        
        # Extract version from CPE string
        cpe_str = cpe_data.get('criteria', '') or cpe_data.get('cpe', '')
        if cpe_str.startswith('cpe:2.3:'):
            parts = cpe_str.split(':')
            if len(parts) >= 6:
                version = parts[5]
                if version and version != '*':
                    version_info['version'] = version
        
        # Extract version ranges
        version_start_inc = cpe_data.get('versionStartIncluding')
        version_start_exc = cpe_data.get('versionStartExcluding')
        version_end_inc = cpe_data.get('versionEndIncluding')
        version_end_exc = cpe_data.get('versionEndExcluding')
        
        if version_start_inc or version_start_exc or version_end_inc or version_end_exc:
            range_parts = []
            if version_start_inc:
                range_parts.append(f">={version_start_inc}")
            elif version_start_exc:
                range_parts.append(f">{version_start_exc}")
            
            if version_end_inc:
                range_parts.append(f"<={version_end_inc}")
            elif version_end_exc:
                range_parts.append(f"<{version_end_exc}")
            
            if range_parts:
                version_info['version_range'] = ' '.join(range_parts)
        
        return version_info
    
    def extract_from_text(self, text: str) -> Dict[str, Any]:
        """
        Extract version information from text using patterns.
        
        Args:
            text: Text to search for versions
            
        Returns:
            Dictionary with extracted versions
        """
        versions = {
            'vulnerable_versions': [],
            'fixed_versions': [],
            'all_versions': []
        }
        
        # Common patterns
        patterns = [
            (r'prior to version ([0-9.]+)', 'vulnerable'),
            (r'before version ([0-9.]+)', 'vulnerable'),
            (r'version ([0-9.]+) and earlier', 'vulnerable'),
            (r'versions? ([0-9.]+) through ([0-9.]+)', 'vulnerable_range'),
            (r'versions? ([0-9.]+) to ([0-9.]+)', 'vulnerable_range'),
            (r'fixed in version ([0-9.]+)', 'fixed'),
            (r'patched in version ([0-9.]+)', 'fixed'),
            (r'version ([0-9.]+) fixes', 'fixed'),
            (r'version ([0-9.]+) contains a patch', 'fixed'),
            (r'resolved in version ([0-9.]+)', 'fixed'),
            (r'upgrade to version ([0-9.]+)', 'fixed'),
        ]
        
        for pattern, version_type in patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                if version_type == 'vulnerable_range' and len(match.groups()) == 2:
                    versions['vulnerable_versions'].append(f"{match.group(1)} to {match.group(2)}")
                elif version_type == 'vulnerable':
                    versions['vulnerable_versions'].append(f"< {match.group(1)}")
                elif version_type == 'fixed':
                    versions['fixed_versions'].append(match.group(1))
                
                versions['all_versions'].extend(match.groups())
        
        # Remove duplicates
        for key in versions:
            versions[key] = list(set(versions[key]))
        
        return versions
    
    def format_version_info(self, nvd_data: Optional[Dict], vendor_data: List[Dict], 
                           github_data: Optional[Dict], collected_data: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Format comprehensive version information from all sources.
        
        Args:
            nvd_data: NVD data dictionary (raw NVD API response)
            vendor_data: List of vendor data dictionaries
            github_data: GitHub data dictionary
            
        Returns:
            Comprehensive version information dictionary
        """
        version_info = {
            'vulnerable_versions': [],
            'fixed_versions': [],
            'version_ranges': [],
            'affected_products': [],
            'sources': []
        }
        
        # Extract from NVD - handle both raw NVD data and processed data
        nvd_configs = None
        if nvd_data:
            if 'configurations' in nvd_data:
                nvd_configs = nvd_data['configurations']
            elif isinstance(nvd_data, dict) and 'data' in nvd_data:
                # Handle processed NVD data structure
                if 'configurations' in nvd_data.get('data', {}):
                    nvd_configs = nvd_data['data']['configurations']
        
        if nvd_configs:
            for config in nvd_data['configurations']:
                if 'nodes' in config:
                    for node in config['nodes']:
                        if 'cpeMatch' in node:
                            for cpe_match in node['cpeMatch']:
                                cpe_info = self.extract_from_nvd_cpe(cpe_match)
                                
                                # Extract product from CPE
                                cpe_str = cpe_info['cpe']
                                if cpe_str.startswith('cpe:2.3:'):
                                    parts = cpe_str.split(':')
                                    if len(parts) >= 5:
                                        vendor = parts[3]
                                        product = parts[4]
                                        version = parts[5] if len(parts) > 5 else None
                                        
                                        # Use version from CPE if available
                                        if version and version != '*' and version != '-':
                                            cpe_info['version'] = version
                                        
                                        product_info = {
                                            'vendor': vendor,
                                            'product': product,
                                            'vulnerable': cpe_info['vulnerable'],
                                            'version': cpe_info.get('version'),
                                            'version_range': cpe_info.get('version_range'),
                                            'cpe': cpe_str,
                                            'source': 'NVD'
                                        }
                                        
                                        version_info['affected_products'].append(product_info)
                                        
                                        if cpe_info['vulnerable']:
                                            if cpe_info.get('version'):
                                                version_info['vulnerable_versions'].append(cpe_info['version'])
                                            if cpe_info.get('version_range'):
                                                version_info['version_ranges'].append({
                                                    'range': cpe_info['version_range'],
                                                    'product': product,
                                                    'source': 'NVD'
                                                })
                                        else:
                                            if cpe_info.get('version'):
                                                version_info['fixed_versions'].append(cpe_info['version'])
        
        # Extract from vendor sources
        for vendor_source in vendor_data:
            content = vendor_source.get('content', '')
            if content:
                text_versions = self.extract_from_text(content)
                version_info['vulnerable_versions'].extend(text_versions.get('vulnerable_versions', []))
                version_info['fixed_versions'].extend(text_versions.get('fixed_versions', []))
                version_info['sources'].append({
                    'source': 'vendor_advisory',
                    'url': vendor_source.get('url'),
                    'versions_found': len(text_versions.get('all_versions', []))
                })
            
            # PRIORITY: Use LLM version interpretation (converts natural language to proper ranges)
            if 'llm_version_interpretation' in vendor_source:
                llm_interp = vendor_source['llm_version_interpretation']
                
                # Extract vulnerable ranges (e.g., ">= 3.0.0 < 3.88.0")
                for range_info in llm_interp.get('vulnerable_ranges', []):
                    range_str = range_info.get('range', '') if isinstance(range_info, dict) else str(range_info)
                    if range_str:
                        version_info['version_ranges'].append({
                            'range': range_str,
                            'product': vendor_source.get('title', 'Unknown'),
                            'source': 'llm_interpretation',
                            'confidence': range_info.get('confidence', 'medium') if isinstance(range_info, dict) else 'medium',
                            'description': range_info.get('description', '') if isinstance(range_info, dict) else ''
                        })
                        # Also add to vulnerable_versions for backward compatibility
                        version_info['vulnerable_versions'].append(range_str)
                
                # Extract fixed ranges
                for fixed_range in llm_interp.get('fixed_ranges', []):
                    if fixed_range:
                        version_info['version_ranges'].append({
                            'range': fixed_range,
                            'product': vendor_source.get('title', 'Unknown'),
                            'source': 'llm_interpretation_fixed',
                            'confidence': llm_interp.get('confidence', 'medium')
                        })
                
                # Extract fixed versions
                for fixed_ver in llm_interp.get('fixed_versions', []):
                    if fixed_ver:
                        version_info['fixed_versions'].append(fixed_ver)
                
                # Extract workaround versions
                for workaround_ver in llm_interp.get('workaround_versions', []):
                    if workaround_ver:
                        version_info['fixed_versions'].append(f"{workaround_ver} (workaround)")
                
                version_info['sources'].append({
                    'source': 'llm_interpretation',
                    'url': vendor_source.get('url'),
                    'confidence': llm_interp.get('confidence', 'medium'),
                    'notes': llm_interp.get('notes', '')
                })
            
            # Fallback: Check LLM extracted versions (if interpretation not available)
            elif 'llm_extracted_versions' in vendor_source:
                llm_versions = vendor_source['llm_extracted_versions']
                version_info['vulnerable_versions'].extend(llm_versions.get('vulnerable_versions', []))
                version_info['fixed_versions'].extend(llm_versions.get('fixed_versions', []))
                version_info['sources'].append({
                    'source': 'llm_extraction',
                    'url': vendor_source.get('url'),
                    'confidence': llm_versions.get('confidence', 'unknown')
                })
        
        # Extract from GitHub
        if github_data and 'version_info' in github_data:
            gh_versions = github_data['version_info']
            version_info['vulnerable_versions'].extend(gh_versions.get('vulnerable_versions', []))
            version_info['fixed_versions'].extend(gh_versions.get('patched_versions', []))
            version_info['sources'].append({
                'source': 'github',
                'ghsa_id': github_data.get('data', {}).get('ghsa_id'),
                'versions_found': len(gh_versions.get('vulnerable_versions', [])) + len(gh_versions.get('patched_versions', []))
            })
        
        # Extract from NVD LLM interpretation (if available)
        if collected_data and 'nvd_llm_interpretation' in collected_data:
            nvd_interp = collected_data['nvd_llm_interpretation']
            for range_info in nvd_interp.get('vulnerable_ranges', []):
                range_str = range_info.get('range', '') if isinstance(range_info, dict) else str(range_info)
                if range_str:
                    version_info['version_ranges'].append({
                        'range': range_str,
                        'product': 'NVD Description',
                        'source': 'nvd_llm_interpretation',
                        'confidence': range_info.get('confidence', 'medium') if isinstance(range_info, dict) else 'medium',
                        'description': range_info.get('description', '') if isinstance(range_info, dict) else ''
                    })
                    version_info['vulnerable_versions'].append(range_str)
            
            for fixed_range in nvd_interp.get('fixed_ranges', []):
                if fixed_range:
                    version_info['version_ranges'].append({
                        'range': fixed_range,
                        'product': 'NVD Description',
                        'source': 'nvd_llm_interpretation_fixed',
                        'confidence': nvd_interp.get('confidence', 'medium')
                    })
            
            for fixed_ver in nvd_interp.get('fixed_versions', []):
                if fixed_ver:
                    version_info['fixed_versions'].append(fixed_ver)
        
        # Extract from GitHub LLM interpretation (if available)
        if collected_data and 'github_llm_interpretation' in collected_data:
            gh_interp = collected_data['github_llm_interpretation']
            for range_info in gh_interp.get('vulnerable_ranges', []):
                range_str = range_info.get('range', '') if isinstance(range_info, dict) else str(range_info)
                if range_str:
                    version_info['version_ranges'].append({
                        'range': range_str,
                        'product': 'GitHub Description',
                        'source': 'github_llm_interpretation',
                        'confidence': range_info.get('confidence', 'medium') if isinstance(range_info, dict) else 'medium',
                        'description': range_info.get('description', '') if isinstance(range_info, dict) else ''
                    })
                    version_info['vulnerable_versions'].append(range_str)
            
            for fixed_range in gh_interp.get('fixed_ranges', []):
                if fixed_range:
                    version_info['version_ranges'].append({
                        'range': fixed_range,
                        'product': 'GitHub Description',
                        'source': 'github_llm_interpretation_fixed',
                        'confidence': gh_interp.get('confidence', 'medium')
                    })
            
            for fixed_ver in gh_interp.get('fixed_versions', []):
                if fixed_ver:
                    version_info['fixed_versions'].append(fixed_ver)
        
        # Remove duplicates and filter out pre-release versions
        from tools.version_tools import VersionTools
        
        # Filter fixed versions - prefer stable releases over beta/alpha
        all_fixed = list(set(version_info['fixed_versions']))
        version_info['fixed_versions'] = VersionTools.filter_stable_versions(all_fixed, prefer_stable=True)
        
        # Keep vulnerable versions as-is (they might include pre-releases for accuracy)
        version_info['vulnerable_versions'] = sorted(list(set(version_info['vulnerable_versions'])))
        version_info['fixed_versions'] = sorted(version_info['fixed_versions'])
        
        return version_info
