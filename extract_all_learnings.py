"""Extract ALL vendor advisories and learnings from OVAL XML before removal."""

import json
import argparse
from pathlib import Path
from datetime import datetime
from oval_parser import OVALParser
from vendor_database import VendorDatabase


def extract_all_learnings(oval_xml_path: str, output_dir: str = "learnings", 
                         vendor_db_path: str = "data/vendor_db.json"):
    """
    Extract ALL learnings and vendor advisories from OVAL XML.
    This function combines extraction of learnings and vendor URLs.
    
    Args:
        oval_xml_path: Path to OVAL XML file
        output_dir: Output directory for extracted learnings
        vendor_db_path: Path to vendor database file (optional)
    """
    print("="*60)
    print("Extracting ALL Learnings and Vendor URLs from OVAL XML")
    print("="*60)
    print(f"\nOVAL XML: {oval_xml_path}")
    print(f"Output Directory: {output_dir}")
    print(f"Vendor Database: {vendor_db_path}\n")
    
    # Initialize parser
    parser = OVALParser(oval_xml_path)
    parser.parse()
    
    # Extract all learnings
    print("Extracting comprehensive learnings...")
    learnings = parser.extract_learnings()
    
    # Extract vendor URLs
    print("Extracting vendor URLs...")
    vendor_urls = parser.extract_vendor_urls()
    
    # Extract vendor domains from vendor URLs
    print("Extracting vendor domains...")
    vendor_domains = {}
    for product, url_data in vendor_urls.items():
        vendor_domains[product] = set(url_data['domains'].keys())
    
    # Create output directory
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Save comprehensive learnings
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # 1. Save all learnings
    learnings_file = output_path / f"oval_learnings_{timestamp}.json"
    with open(learnings_file, 'w', encoding='utf-8') as f:
        json.dump(learnings, f, indent=2, ensure_ascii=False)
    print(f"\n[OK] Learnings saved to: {learnings_file}")
    
    # 2. Save vendor URLs
    vendor_urls_file = output_path / f"vendor_urls_{timestamp}.json"
    with open(vendor_urls_file, 'w', encoding='utf-8') as f:
        json.dump(vendor_urls, f, indent=2, ensure_ascii=False)
    print(f"[OK] Vendor URLs saved to: {vendor_urls_file}")
    
    # 3. Save vendor domains
    vendor_domains_file = output_path / f"vendor_domains_{timestamp}.json"
    # Convert sets to lists for JSON
    vendor_domains_json = {k: list(v) for k, v in vendor_domains.items()}
    with open(vendor_domains_file, 'w', encoding='utf-8') as f:
        json.dump(vendor_domains_json, f, indent=2, ensure_ascii=False)
    print(f"[OK] Vendor domains saved to: {vendor_domains_file}")
    
    # 4. Save comprehensive summary
    summary = {
        'extraction_date': datetime.now().isoformat(),
        'oval_xml_path': oval_xml_path,
        'statistics': {
            'total_products': len(vendor_urls),
            'total_vendor_urls': sum(data['total_count'] for data in vendor_urls.values()),
            'total_domains': len(set(domain for domains in vendor_domains.values() for domain in domains)),
            'version_patterns': len(learnings.get('version_patterns', [])),
            'cpe_patterns': len(learnings.get('cpe_patterns', {})),
            'product_naming_variants': len(learnings.get('product_naming', {})),
            'description_patterns': {
                'prior_to_versions': len(learnings.get('description_patterns', {}).get('prior_to_patterns', [])),
                'fixed_in_versions': len(learnings.get('description_patterns', {}).get('fixed_in_patterns', []))
            }
        },
        'top_products': sorted(
            [(product, data['total_count']) for product, data in vendor_urls.items()],
            key=lambda x: x[1],
            reverse=True
        )[:20],
        'top_domains': sorted(
            [(domain, len(products)) for domain, products in vendor_domains.items()],
            key=lambda x: x[1],
            reverse=True
        )[:20],
        'version_format_distribution': {},
        'common_cpe_formats': learnings.get('common_cpe_formats', [])[:10],
        'best_practices': learnings.get('best_practices', {}),
        'version_mistakes': learnings.get('version_mistakes', [])
    }
    
    # Calculate version format distribution
    if learnings.get('version_patterns'):
        formats = {}
        for pattern in learnings['version_patterns']:
            fmt = pattern.get('format', 'unknown')
            formats[fmt] = formats.get(fmt, 0) + 1
        summary['statistics']['version_format_distribution'] = formats
    
    summary_file = output_path / f"extraction_summary_{timestamp}.json"
    with open(summary_file, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"[OK] Summary saved to: {summary_file}")
    
    # Print statistics
    print("\n" + "="*60)
    print("Extraction Statistics")
    print("="*60)
    print(f"Total Products: {summary['statistics']['total_products']}")
    print(f"Total Vendor URLs: {summary['statistics']['total_vendor_urls']}")
    print(f"Total Domains: {summary['statistics']['total_domains']}")
    print(f"Version Patterns: {summary['statistics']['version_patterns']}")
    print(f"CPE Patterns: {summary['statistics']['cpe_patterns']}")
    print(f"Product Naming Variants: {summary['statistics']['product_naming_variants']}")
    print(f"\nTop 5 Products by URL Count:")
    for product, count in summary['top_products'][:5]:
        print(f"  - {product}: {count} URLs")
    print(f"\nTop 5 Domains:")
    for domain, count in summary['top_domains'][:5]:
        print(f"  - {domain}: {count} products")
    
    print("\n" + "="*60)
    print("Extraction Complete!")
    print("="*60)
    print(f"\nAll learnings saved to: {output_path}")
    
    return summary


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Extract ALL learnings from OVAL XML')
    parser.add_argument('--oval-xml',
                       default=r'C:\Users\Yashvant\OneDrive\Documents\OVAL_WINDOWS.xml',
                       help='Path to OVAL XML file')
    parser.add_argument('--output-dir',
                       default='learnings',
                       help='Output directory for extracted learnings')
    parser.add_argument('--vendor-db',
                       default='data/vendor_db.json',
                       help='Path to vendor database file (optional)')
    
    args = parser.parse_args()
    
    extract_all_learnings(args.oval_xml, args.output_dir, args.vendor_db)


if __name__ == '__main__':
    main()
