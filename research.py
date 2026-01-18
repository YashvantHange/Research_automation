#!/usr/bin/env python3
"""
Unified Research Agent - Single Command Entry Point

This script handles everything automatically:
- Auto-extracts vendor URLs if database doesn't exist
- Researches CVEs with enhanced workflow
- Provides a simple, unified interface
"""

import sys
import warnings
import argparse
import json
from pathlib import Path

# Suppress trio RuntimeWarning about excepthook
warnings.filterwarnings('ignore', message='.*sys.excepthook.*', category=RuntimeWarning)
try:
    from research_agent_enhanced import EnhancedResearchAgent as ResearchAgent
except ImportError:
    from research_agent import ResearchAgent


def check_and_init_vendor_db(oval_xml_path: str, vendor_db_path: str) -> bool:
    """
    Check if vendor database exists, if not, extract vendor URLs.
    
    Returns:
        True if database exists or was created successfully
    """
    db_path = Path(vendor_db_path)
    
    if db_path.exists():
        print(f"[OK] Vendor database found: {vendor_db_path}")
        return True
    
    print(f"[WARN] Vendor database not found. Extracting vendor URLs from OVAL XML...")
    print(f"  This may take a few minutes for large XML files...\n")
    
    try:
        from oval_parser import OVALParser
        from vendor_database import VendorDatabase
        
        parser = OVALParser(oval_xml_path)
        parser.parse()
        
        vendor_urls = parser.extract_vendor_urls()
        
        if not vendor_urls:
            print("[WARN] No vendor URLs found in OVAL XML.")
            return False
        
        print(f"[OK] Found vendor URLs for {len(vendor_urls)} products")
        
        db = VendorDatabase(vendor_db_path)
        db.add_vendor_urls(vendor_urls)
        
        stats = db.get_statistics()
        print(f"[OK] Vendor database created: {stats['total_products']} products, "
              f"{stats['total_urls']} URLs, {stats['total_domains']} domains\n")
        
        return True
        
    except Exception as e:
        print(f"✗ Error creating vendor database: {e}")
        print("  Continuing without vendor database...")
        return False


def main():
    """Main entry point - handles everything automatically."""
    parser = argparse.ArgumentParser(
        description='OVAL XML Research Agent - Single Command Interface',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Research a single CVE
  python research.py CVE-2025-5591
  
  # Research with custom OVAL XML path
  python research.py CVE-2025-5591 --oval-xml "path/to/OVAL_WINDOWS.xml"
  
  # Research with additional vendor URLs
  python research.py CVE-2025-5591 --urls "https://vendor.com/advisory"
  
  # Use different Ollama model
  python research.py CVE-2025-5591 --model llama3.1
  
  # Research multiple CVEs
  python research.py CVE-2025-5591 CVE-2025-5592 CVE-2025-5593
        """
    )
    
    parser.add_argument('cve_ids', 
                       nargs='+',
                       help='CVE ID(s) to research (e.g., CVE-2025-5591)')
    parser.add_argument('--oval-xml', 
                       default=r'C:\Users\Yashvant\OneDrive\Documents\OVAL_WINDOWS.xml',
                       help='Path to OVAL XML file')
    parser.add_argument('--ollama-model', 
                       default='llama3.2',
                       help='Ollama model to use')
    parser.add_argument('--nvd-api-key', 
                       help='NVD API key (optional, for higher rate limits)')
    parser.add_argument('--github-token',
                       help='GitHub token (optional, for higher rate limits)')
    parser.add_argument('--urls', 
                       nargs='+',
                       help='Additional vendor advisory URLs to scrape')
    parser.add_argument('--output-dir',
                       default='outputs',
                       help='Output directory for research files')
    parser.add_argument('--vendor-db',
                       default='data/vendor_db.json',
                       help='Path to vendor database file')
    parser.add_argument('--skip-init',
                       action='store_true',
                       help='Skip vendor database initialization check')
    
    args = parser.parse_args()
    
    # Check and initialize vendor database if needed
    if not args.skip_init:
        print("="*60)
        print("Research Agent - Initialization Check")
        print("="*60)
        check_and_init_vendor_db(args.oval_xml, args.vendor_db)
        print()
    
    # Initialize research agent
    print("="*60)
    print("Initializing Research Agent")
    print("="*60)
    agent = None
    try:
        agent = ResearchAgent(
            oval_xml_path=args.oval_xml,
            ollama_model=args.ollama_model,
            nvd_api_key=args.nvd_api_key,
            github_token=args.github_token,
            vendor_db_path=args.vendor_db
        )
        print("[OK] Research agent initialized\n")
    except Exception as e:
        print(f"[ERROR] Error initializing research agent: {e}")
        sys.exit(1)
    
    # Research each CVE
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    results = []
    combined_outputs = {}
    
    for i, cve_id in enumerate(args.cve_ids, 1):
        print("\n" + "="*60)
        print(f"Researching CVE {i}/{len(args.cve_ids)}: {cve_id}")
        print("="*60)
        
        try:
            # Research CVE
            output = agent.research_cve(cve_id, args.urls)
            
            # Save output as JSON (always JSON format)
            output_path = output_dir / f"{cve_id}.json"
            agent.save_output(output, str(output_path))
            
            # Also show summary if available
            if 'collected_data' in output:
                cd = output['collected_data']
                print(f"\n[INFO] Collected Data Summary:")
                print(f"  - NVD Data: {'Yes' if cd.get('nvd_data') else 'No'}")
                print(f"  - Vendor Sources: {len(cd.get('vendor_data', []))}")
                print(f"  - GitHub Data: {'Yes' if cd.get('github_data') else 'No'}")
                print(f"  - Total Sources: {len(cd.get('sources', []))}")
            
            results.append({
                'cve_id': cve_id,
                'status': 'success',
                'output_path': str(output_path)
            })

            # Store output for combined JSON
            combined_outputs[cve_id] = output
            
        except Exception as e:
            print(f"\n[ERROR] Error researching {cve_id}: {e}")
            results.append({
                'cve_id': cve_id,
                'status': 'error',
                'error': str(e)
            })
            combined_outputs[cve_id] = {'error': str(e), 'cve_id': cve_id}
    
    # Write combined JSON output when multiple CVEs are requested
    if len(args.cve_ids) > 1:
        combined_path = output_dir / "combined_results.json"
        combined_payload = {
            'summary': {
                'total': len(results),
                'successful': len([r for r in results if r['status'] == 'success']),
                'failed': len([r for r in results if r['status'] == 'error'])
            },
            'results': results,
            'cves': combined_outputs
        }
        with open(combined_path, 'w', encoding='utf-8') as f:
            json.dump(combined_payload, f, indent=2, ensure_ascii=False)
        print(f"\n[OK] Combined output saved: {combined_path}")

    # Summary
    print("\n" + "="*60)
    print("Research Summary")
    print("="*60)
    
    successful = [r for r in results if r['status'] == 'success']
    failed = [r for r in results if r['status'] == 'error']
    
    print(f"\n[OK] Successful: {len(successful)}/{len(results)}")
    for result in successful:
        print(f"  - {result['cve_id']}: {result['output_path']}")
    
    if failed:
        print(f"\n[ERROR] Failed: {len(failed)}/{len(results)}")
        for result in failed:
            print(f"  - {result['cve_id']}: {result.get('error', 'Unknown error')}")
    
    print("\n" + "="*60)
    print("Research Complete!")
    print("="*60)
    
    # Exit with error code if any failed
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
