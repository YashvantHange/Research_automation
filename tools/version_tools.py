"""Version comparison and validation tools."""

import re
from typing import List, Optional, Tuple
from packaging import version


class VersionTools:
    """Tools for version comparison and validation."""
    
    @staticmethod
    def normalize_version(version_str: str) -> str:
        """
        Normalize version string for comparison.
        
        Args:
            version_str: Version string to normalize
            
        Returns:
            Normalized version string
        """
        # Remove common prefixes/suffixes
        version_str = version_str.strip()
        version_str = re.sub(r'^v', '', version_str, flags=re.IGNORECASE)
        version_str = re.sub(r'^version\s*', '', version_str, flags=re.IGNORECASE)
        
        return version_str
    
    @staticmethod
    def compare_versions(v1: str, v2: str) -> int:
        """
        Compare two version strings.
        
        Args:
            v1: First version
            v2: Second version
            
        Returns:
            -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
        """
        try:
            v1_norm = VersionTools.normalize_version(v1)
            v2_norm = VersionTools.normalize_version(v2)
            
            # Try using packaging library
            try:
                if version.parse(v1_norm) < version.parse(v2_norm):
                    return -1
                elif version.parse(v1_norm) > version.parse(v2_norm):
                    return 1
                else:
                    return 0
            except:
                # Fallback to string comparison
                return (v1_norm > v2_norm) - (v1_norm < v2_norm)
        except:
            return 0
    
    @staticmethod
    def parse_version_range(range_str: str) -> Optional[Tuple[str, str, bool, bool]]:
        """
        Parse version range string.
        
        Args:
            range_str: Version range (e.g., "< 2.4.59", ">=1.2.0 <1.2.9")
            
        Returns:
            Tuple of (operator1, version1, operator2, version2) or None
        """
        # Pattern for version ranges
        patterns = [
            r'<=\s*([0-9.]+)',
            r'>=\s*([0-9.]+)',
            r'<\s*([0-9.]+)',
            r'>\s*([0-9.]+)',
            r'=\s*([0-9.]+)',
            r'([0-9.]+)\s+to\s+([0-9.]+)',
            r'([0-9.]+)\s+through\s+([0-9.]+)',
        ]
        
        range_str = range_str.strip()
        
        # Try to match patterns
        for pattern in patterns:
            match = re.search(pattern, range_str, re.IGNORECASE)
            if match:
                if len(match.groups()) == 1:
                    return (range_str[:match.start()].strip(), match.group(1), None, None)
                elif len(match.groups()) == 2:
                    return (match.group(1), match.group(2), None, None)
        
        return None
    
    @staticmethod
    def is_version_in_range(version_str: str, range_str: str) -> bool:
        """
        Check if version is within range.
        
        Args:
            version_str: Version to check
            range_str: Version range
            
        Returns:
            True if version is in range
        """
        parsed = VersionTools.parse_version_range(range_str)
        if not parsed:
            return False
        
        v_norm = VersionTools.normalize_version(version_str)
        
        # Simple comparison for now
        if '<' in range_str:
            max_version = re.search(r'<\s*([0-9.]+)', range_str)
            if max_version:
                return VersionTools.compare_versions(v_norm, max_version.group(1)) < 0
        
        return False
    
    @staticmethod
    def extract_versions_from_text(text: str) -> List[str]:
        """
        Extract version numbers from text.
        
        Args:
            text: Text to search
            
        Returns:
            List of version strings found
        """
        # Common version patterns
        patterns = [
            r'\b\d+\.\d+\.\d+(?:\.\d+)?',  # Semantic versioning
            r'\b\d+\.\d+',  # Major.minor
            r'version\s+([0-9.]+)',  # "version X.Y.Z"
            r'v([0-9.]+)',  # "vX.Y.Z"
        ]
        
        versions = []
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            versions.extend(matches)
        
        # Remove duplicates and normalize
        unique_versions = []
        seen = set()
        for v in versions:
            v_norm = VersionTools.normalize_version(v)
            if v_norm not in seen:
                seen.add(v_norm)
                unique_versions.append(v_norm)
        
        return unique_versions
    
    @staticmethod
    def is_pre_release_version(version_str: str) -> bool:
        """
        Check if version is a pre-release (beta, alpha, rc, dev, etc.).
        
        Args:
            version_str: Version string to check
            
        Returns:
            True if version is a pre-release
        """
        version_lower = version_str.lower()
        pre_release_indicators = [
            'alpha', 'beta', 'rc', 'dev', 'pre', 'snapshot', 
            '-a', '-b', '-rc', '-dev', '-pre', '-snapshot',
            'a1', 'b1', 'rc1', 'dev1'
        ]
        return any(indicator in version_lower for indicator in pre_release_indicators)
    
    @staticmethod
    def filter_stable_versions(versions: List[str], prefer_stable: bool = True) -> List[str]:
        """
        Filter out pre-release versions, keeping only stable releases.
        If a beta version exists but a stable version exists after it, prefer the stable one.
        
        Args:
            versions: List of version strings
            prefer_stable: If True, prefer stable versions over pre-releases
            
        Returns:
            Filtered list of stable versions
        """
        if not versions:
            return []
        
        stable_versions = []
        pre_release_versions = []
        
        # Separate stable and pre-release versions
        for v in versions:
            if VersionTools.is_pre_release_version(v):
                pre_release_versions.append(v)
            else:
                stable_versions.append(v)
        
        # If we have stable versions, use only those
        if prefer_stable and stable_versions:
            return stable_versions
        
        # If no stable versions, check if pre-releases can be converted to stable
        # (e.g., if we have 5.0.1-beta and 5.0.2, use 5.0.2)
        if pre_release_versions and stable_versions:
            # Compare versions - if stable version is newer, use it
            filtered = []
            for pre_v in pre_release_versions:
                # Extract base version (remove pre-release suffix)
                base_version = re.sub(r'[-_](alpha|beta|rc|dev|pre|snapshot).*$', '', pre_v, flags=re.IGNORECASE)
                base_version = re.sub(r'[a-z]+.*$', '', base_version, flags=re.IGNORECASE)
                
                # Check if there's a stable version that's >= base version
                has_newer_stable = any(
                    VersionTools.compare_versions(stable_v, base_version) >= 0 
                    for stable_v in stable_versions
                )
                
                if not has_newer_stable:
                    # No stable version covers this, keep the pre-release
                    filtered.append(pre_v)
            
            return stable_versions + filtered
        
        # Return what we have
        return stable_versions if stable_versions else pre_release_versions
