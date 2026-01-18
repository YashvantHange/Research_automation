"""CPE validation and normalization tools."""

import re
from typing import Dict, List, Optional, Tuple


class CPEValidator:
    """CPE validation and normalization tools."""
    
    CPE_PATTERN = re.compile(
        r'^cpe:2\.3:[aho\*\-]:([a-zA-Z0-9\-_\.]+|\*):([a-zA-Z0-9\-_\.]+|\*):([a-zA-Z0-9\-_\.]+|\*):'
        r'([a-zA-Z0-9\-_\.]+|\*):([a-zA-Z0-9\-_\.]+|\*):([a-zA-Z0-9\-_\.]+|\*):'
        r'([a-zA-Z0-9\-_\.]+|\*):([a-zA-Z0-9\-_\.]+|\*):([a-zA-Z0-9\-_\.]+|\*):([a-zA-Z0-9\-_\.]+|\*)$'
    )
    
    @staticmethod
    def validate_cpe(cpe: str) -> Tuple[bool, Optional[str]]:
        """
        Validate CPE format.
        
        Args:
            cpe: CPE string to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not cpe.startswith('cpe:2.3:'):
            return False, "CPE must start with 'cpe:2.3:'"
        
        if not CPEValidator.CPE_PATTERN.match(cpe):
            return False, "CPE format is invalid"
        
        parts = cpe.split(':')
        if len(parts) != 13:
            return False, f"CPE must have 13 parts, got {len(parts)}"
        
        # Check part type (a=application, h=hardware, o=OS)
        part_type = parts[2]
        if part_type not in ['a', 'h', 'o', '*']:
            return False, f"Invalid part type: {part_type}"
        
        return True, None
    
    @staticmethod
    def normalize_vendor_product(vendor: str, product: str) -> Tuple[str, str]:
        """
        Normalize vendor and product names for CPE.
        
        Args:
            vendor: Vendor name
            product: Product name
            
        Returns:
            Tuple of (normalized_vendor, normalized_product)
        """
        # Common normalization rules
        def normalize(name: str) -> str:
            # Convert to lowercase
            name = name.lower()
            # Replace spaces with underscores
            name = name.replace(' ', '_')
            # Remove special characters except hyphens and underscores
            name = re.sub(r'[^a-z0-9_\-]', '', name)
            # Remove multiple underscores
            name = re.sub(r'_+', '_', name)
            # Remove leading/trailing underscores
            name = name.strip('_')
            return name
        
        return normalize(vendor), normalize(product)
    
    @staticmethod
    def build_cpe(part_type: str, vendor: str, product: str, version: str = '*',
                  update: str = '*', edition: str = '*', language: str = '*',
                  sw_edition: str = '*', target_sw: str = '*', target_hw: str = '*',
                  other: str = '*') -> str:
        """
        Build a CPE string from components.
        
        Args:
            part_type: Part type (a, h, o)
            vendor: Vendor name
            product: Product name
            version: Version
            update: Update
            edition: Edition
            language: Language
            sw_edition: Software edition
            target_sw: Target software
            target_hw: Target hardware
            other: Other
            
        Returns:
            CPE string
        """
        vendor_norm, product_norm = CPEValidator.normalize_vendor_product(vendor, product)
        
        cpe = f"cpe:2.3:{part_type}:{vendor_norm}:{product_norm}:{version}:{update}:{edition}:{language}:{sw_edition}:{target_sw}:{target_hw}:{other}"
        
        is_valid, error = CPEValidator.validate_cpe(cpe)
        if not is_valid:
            raise ValueError(f"Invalid CPE generated: {error}")
        
        return cpe
    
    @staticmethod
    def parse_cpe(cpe: str) -> Optional[Dict[str, str]]:
        """
        Parse CPE string into components.
        
        Args:
            cpe: CPE string
            
        Returns:
            Dictionary with CPE components or None if invalid
        """
        is_valid, _ = CPEValidator.validate_cpe(cpe)
        if not is_valid:
            return None
        
        parts = cpe.split(':')
        return {
            'part_type': parts[2],
            'vendor': parts[3],
            'product': parts[4],
            'version': parts[5],
            'update': parts[6],
            'edition': parts[7],
            'language': parts[8],
            'sw_edition': parts[9],
            'target_sw': parts[10],
            'target_hw': parts[11],
            'other': parts[12]
        }
    
    @staticmethod
    def suggest_cpe_corrections(cpe: str, product_name: str) -> List[str]:
        """
        Suggest CPE corrections based on product name.
        
        Args:
            cpe: Original CPE
            product_name: Product name for context
            
        Returns:
            List of suggested CPEs
        """
        suggestions = []
        
        parsed = CPEValidator.parse_cpe(cpe)
        if not parsed:
            return suggestions
        
        # Try to fix common issues
        vendor_norm, product_norm = CPEValidator.normalize_vendor_product(
            parsed['vendor'],
            parsed['product']
        )
        
        # If product name differs significantly, suggest correction
        product_name_norm = CPEValidator.normalize_vendor_product(product_name, product_name)[1]
        if product_norm != product_name_norm:
            suggested = CPEValidator.build_cpe(
                parsed['part_type'],
                parsed['vendor'],
                product_name,
                parsed['version'],
                parsed['update'],
                parsed['edition'],
                parsed['language'],
                parsed['sw_edition'],
                parsed['target_sw'],
                parsed['target_hw'],
                parsed['other']
            )
            suggestions.append(suggested)
        
        return suggestions
