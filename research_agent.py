"""Enhanced research agent with vendor URL database and intelligent search."""

import json
import os
from typing import Dict, List, Optional, Any
from pathlib import Path

from scrapers.nvd_scraper import NVDScraper
from scrapers.github_scraper import GitHubScraper
from scrapers.vendor_scraper import VendorScraper
from scrapers.vendor_search import VendorSiteSearcher
from oval_parser import OVALParser
from vendor_database import VendorDatabase
from llm_assistant import LLMAssistant

try:
    import ollama
except ImportError:
    print("Warning: ollama package not found. Install with: pip install ollama")
    ollama = None


class ResearchAgent:
    """Enhanced research agent for OVAL XML build with vendor URL database."""
    
    def __init__(self, 
                 oval_xml_path: str,
                 ollama_model: str = "llama3.2",
                 nvd_api_key: Optional[str] = None,
                 github_token: Optional[str] = None,
                 vendor_db_path: str = "data/vendor_db.json"):
        """
        Initialize research agent.
        
        Args:
            oval_xml_path: Path to merged OVAL XML file
            ollama_model: Name of Ollama model to use
            nvd_api_key: Optional NVD API key
            github_token: Optional GitHub token
            vendor_db_path: Path to vendor database file
        """
        self.oval_xml_path = oval_xml_path
        self.ollama_model = ollama_model
        
        # Initialize scrapers
        self.nvd_scraper = NVDScraper(api_key=nvd_api_key)
        self.github_scraper = GitHubScraper(token=github_token)
        self.vendor_scraper = VendorScraper()
        self.vendor_searcher = VendorSiteSearcher()
        
        # Initialize vendor database
        self.vendor_db = VendorDatabase(vendor_db_path)
        
        # Initialize LLM assistant
        self.llm_assistant = LLMAssistant(model=ollama_model)
        
        # Load OVAL learnings and vendor URLs
        self.oval_parser = OVALParser(oval_xml_path)
        self.learnings = None
        self._load_learnings()
        self._load_vendor_urls()
        
        # Load prompt template
        self.prompt_template = self._load_prompt_template()
    
    def _load_learnings(self):
        """Load learnings from OVAL XML file."""
        try:
            print(f"Loading learnings from {self.oval_xml_path}...")
            self.learnings = self.oval_parser.extract_learnings()
            print("OVAL learnings loaded successfully.")
        except Exception as e:
            print(f"Warning: Could not load OVAL learnings: {e}")
            self.learnings = {}
    
    def _load_vendor_urls(self):
        """Extract and load vendor URLs from OVAL XML into database."""
        try:
            print("Extracting vendor URLs from OVAL XML...")
            vendor_urls = self.oval_parser.extract_vendor_urls()
            
            if vendor_urls:
                self.vendor_db.add_vendor_urls(vendor_urls)
                stats = self.vendor_db.get_statistics()
                print(f"Vendor database loaded: {stats['total_products']} products, "
                      f"{stats['total_urls']} URLs, {stats['total_domains']} domains")
            else:
                print("No vendor URLs found in OVAL XML.")
        except Exception as e:
            print(f"Warning: Could not load vendor URLs: {e}")
    
    def _load_prompt_template(self) -> str:
        """Load the research agent prompt template."""
        prompt_path = Path(__file__).parent / "prompts" / "oval_xml_research_agent.md"
        try:
            with open(prompt_path, 'r', encoding='utf-8') as f:
                return f.read()
        except FileNotFoundError:
            print(f"Warning: Prompt template not found at {prompt_path}")
            return ""
    
    def research_cve(self, cve_id: str, additional_urls: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Research a CVE using enhanced workflow:
        1. Search NVD
        2. Extract vendor URLs from NVD references
        3. Prioritize vendor sources
        4. If nothing found, search vendor sites from database
        5. Use LLM for error handling and intelligence
        
        Args:
            cve_id: CVE identifier (e.g., 'CVE-2025-5591')
            additional_urls: Optional list of additional URLs to scrape
            
        Returns:
            Dictionary containing structured research data
        """
        print(f"\n{'='*60}")
        print(f"Researching {cve_id}")
        print(f"{'='*60}\n")
        
        # Step 1: Search NVD
        print("Step 1: Searching NVD...")
        nvd_data = self._search_nvd(cve_id)
        
        # Step 2: Extract vendor URLs from NVD references
        print("\nStep 2: Extracting vendor URLs from NVD references...")
        vendor_urls_from_nvd = self._extract_vendor_urls_from_nvd(nvd_data)
        
        # Step 3: Check vendor database for known URLs
        print("\nStep 3: Checking vendor database...")
        vendor_urls_from_db = self.vendor_db.get_urls_for_cve(cve_id)
        
        # Step 4: Prioritize and scrape vendor sources
        print("\nStep 4: Prioritizing and scraping vendor sources...")
        all_vendor_urls = list(set(vendor_urls_from_nvd + vendor_urls_from_db + (additional_urls or [])))
        vendor_data = self._scrape_vendor_sources(all_vendor_urls, cve_id)
        
        # Step 5: If insufficient data, search vendor sites
        if not vendor_data and nvd_data:
            print("\nStep 5: Searching vendor sites (fallback)...")
            product_info = self._extract_product_from_nvd(nvd_data)
            vendor_site_results = self._search_vendor_sites(cve_id, product_info)
            vendor_data.extend(vendor_site_results)
        
        # Step 6: Collect GitHub data
        print("\nStep 6: Searching GitHub Security Advisories...")
        github_data = self._search_github(cve_id)
        
        # Step 7: Prioritize sources using LLM
        print("\nStep 7: Prioritizing sources with LLM...")
        all_sources = self._combine_sources(nvd_data, vendor_data, github_data)
        prioritized_sources = self.llm_assistant.prioritize_sources(all_sources)
        
        # Step 8: Format data for LLM
        print("\nStep 8: Formatting data for final analysis...")
        formatted_context = self._format_context(prioritized_sources)
        
        # Step 9: Generate structured output using Ollama
        print("\nStep 9: Generating structured output with Ollama...")
        structured_output = self._generate_output(cve_id, formatted_context)
        
        return structured_output
    
    def _search_nvd(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Search NVD for CVE data."""
        try:
            nvd_data = self.nvd_scraper.get_cve(cve_id)
            if nvd_data:
                print(f"  ✓ Found in NVD")
                return {
                    'source': 'NVD',
                    'data': nvd_data,
                    'cpes': self.nvd_scraper.extract_cpe_list(nvd_data),
                    'version_ranges': self.nvd_scraper.extract_version_ranges(nvd_data),
                    'references': self.nvd_scraper.get_references(nvd_data),
                    'cwe': self.nvd_scraper.get_cwe(nvd_data),
                    'description': self._extract_nvd_description(nvd_data),
                    'cvss': self._extract_cvss(nvd_data),
                    'priority': 3  # Lower priority than vendor
                }
            else:
                print(f"  ✗ Not found in NVD")
                return None
        except Exception as e:
            print(f"  ✗ Error searching NVD: {e}")
            # Use LLM for error handling
            suggestion = self.llm_assistant.handle_scraping_error(e, {'source': 'NVD', 'cve_id': cve_id})
            print(f"  LLM suggestion: {suggestion.get('suggestion', 'Retry')}")
            return None
    
    def _extract_vendor_urls_from_nvd(self, nvd_data: Optional[Dict[str, Any]]) -> List[str]:
        """Extract vendor URLs from NVD references."""
        vendor_urls = []
        
        if not nvd_data or 'references' not in nvd_data:
            return vendor_urls
        
        for ref in nvd_data.get('references', []):
            url = ref.get('url', '')
            source = ref.get('source', '').upper()
            tags = ref.get('tags', [])
            
            # Prioritize vendor-related sources
            if source in ['VENDOR', 'VENDOR_ADVISORY'] or 'Vendor Advisory' in tags:
                vendor_urls.append(url)
            elif any(tag in ['Patch', 'Third Party Advisory'] for tag in tags):
                vendor_urls.append(url)
        
        return vendor_urls
    
    def _extract_product_from_nvd(self, nvd_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract product information from NVD data."""
        if not nvd_data:
            return {}
        
        # Try to extract product from CPEs
        cpes = self.nvd_scraper.extract_cpe_list(nvd_data)
        products = set()
        vendors = set()
        
        for cpe in cpes[:5]:  # Limit to first 5
            if cpe.startswith('cpe:2.3:'):
                parts = cpe.split(':')
                if len(parts) >= 5:
                    vendors.add(parts[3])
                    products.add(parts[4])
        
        return {
            'vendors': list(vendors),
            'products': list(products),
            'cpes': cpes[:3]  # Top 3 CPEs
        }
    
    def _scrape_vendor_sources(self, vendor_urls: List[str], cve_id: str) -> List[Dict[str, Any]]:
        """Scrape vendor advisory sources."""
        vendor_data = []
        
        for url in vendor_urls:
            try:
                print(f"  - Scraping: {url}")
                data = self.vendor_scraper.scrape_advisory(url)
                if data:
                    # Use LLM to extract version info if needed
                    if not data.get('versions', {}).get('fixed'):
                        llm_version_info = self.llm_assistant.extract_version_info(
                            data.get('content', ''),
                            cve_id
                        )
                        if llm_version_info:
                            data['llm_extracted_versions'] = llm_version_info
                    
                    data['source'] = 'vendor_advisory'
                    data['priority'] = 1  # Highest priority
                    vendor_data.append(data)
            except Exception as e:
                print(f"  ✗ Error scraping {url}: {e}")
                # Use LLM for error handling
                suggestion = self.llm_assistant.handle_scraping_error(
                    e,
                    {'url': url, 'cve_id': cve_id}
                )
                if suggestion.get('retry', False):
                    print(f"  → Retrying based on LLM suggestion...")
                    # Could implement retry logic here
        
        return vendor_data
    
    def _search_vendor_sites(self, cve_id: str, product_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Search vendor sites from database."""
        results = []
        
        # Get domains from product info
        domains_to_search = []
        if product_info.get('vendors'):
            # Try to find domains for these vendors
            for vendor in product_info['vendors']:
                # Search database for products with similar vendor names
                all_products = self.vendor_db.get_all_products()
                for product in all_products:
                    domains = self.vendor_db.get_vendor_domains_for_product(product)
                    domains_to_search.extend(domains)
        
        # Also get all known domains
        all_domains = self.vendor_db.get_all_domains()
        domains_to_search.extend(list(all_domains)[:10])  # Limit to top 10
        
        # Remove duplicates
        domains_to_search = list(set(domains_to_search))
        
        # Search each domain
        for domain in domains_to_search[:5]:  # Limit searches
            try:
                print(f"  - Searching {domain}...")
                search_results = self.vendor_searcher.search_vendor_site(
                    domain,
                    cve_id,
                    product_info.get('products', [None])[0] if product_info.get('products') else None
                )
                
                for result in search_results:
                    # Scrape found URLs
                    if result.get('url'):
                        scraped = self.vendor_scraper.scrape_advisory(result['url'])
                        if scraped:
                            scraped['source'] = 'vendor_site_search'
                            scraped['priority'] = 2  # Medium-high priority
                            scraped['search_confidence'] = result.get('confidence', 'low')
                            results.append(scraped)
            except Exception as e:
                print(f"  ✗ Error searching {domain}: {e}")
        
        return results
    
    def _search_github(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Search GitHub Security Advisories."""
        try:
            ghsa_data = self.github_scraper.get_advisory_by_cve(cve_id)
            if ghsa_data:
                print(f"  ✓ Found in GitHub")
                version_info = self.github_scraper.extract_version_info(ghsa_data)
                return {
                    'source': 'github',
                    'data': ghsa_data,
                    'version_info': version_info,
                    'priority': 2  # Medium-high priority
                }
            else:
                print(f"  ✗ Not found in GitHub")
                return None
        except Exception as e:
            print(f"  ✗ Error searching GitHub: {e}")
            return None
    
    def _combine_sources(self, nvd_data: Optional[Dict], vendor_data: List[Dict], github_data: Optional[Dict]) -> List[Dict]:
        """Combine all sources into a single list."""
        sources = []
        
        if nvd_data:
            sources.append(nvd_data)
        
        sources.extend(vendor_data)
        
        if github_data:
            sources.append(github_data)
        
        return sources
    
    def _extract_nvd_description(self, nvd_data: Dict[str, Any]) -> str:
        """Extract description from NVD data."""
        if 'descriptions' in nvd_data:
            for desc in nvd_data['descriptions']:
                if desc.get('lang') == 'en':
                    return desc.get('value', '')
        return ''
    
    def _extract_cvss(self, nvd_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract CVSS scores from NVD data."""
        if 'metrics' in nvd_data:
            cvss_data = {}
            if 'cvssMetricV31' in nvd_data['metrics']:
                cvss31 = nvd_data['metrics']['cvssMetricV31'][0]
                cvss_data['v3.1'] = {
                    'baseScore': cvss31.get('cvssData', {}).get('baseScore'),
                    'baseSeverity': cvss31.get('cvssData', {}).get('baseSeverity')
                }
            if 'cvssMetricV30' in nvd_data['metrics']:
                cvss30 = nvd_data['metrics']['cvssMetricV30'][0]
                cvss_data['v3.0'] = {
                    'baseScore': cvss30.get('cvssData', {}).get('baseScore'),
                    'baseSeverity': cvss30.get('cvssData', {}).get('baseSeverity')
                }
            if 'cvssMetricV2' in nvd_data['metrics']:
                cvss2 = nvd_data['metrics']['cvssMetricV2'][0]
                cvss_data['v2'] = {
                    'baseScore': cvss2.get('cvssData', {}).get('baseScore'),
                    'baseSeverity': cvss2.get('cvssData', {}).get('baseSeverity')
                }
            return cvss_data if cvss_data else None
        return None
    
    def _format_context(self, sources: List[Dict[str, Any]]) -> str:
        """Format prioritized sources as context for LLM."""
        context_parts = []
        
        # Add sources in priority order
        for i, source in enumerate(sources, 1):
            source_type = source.get('source', 'unknown')
            priority = source.get('priority', 999)
            
            context_parts.append(f"\n## Source {i}: {source_type.upper()} (Priority: {priority})")
            
            if source_type == 'NVD':
                data = source.get('data', {})
                context_parts.append(f"Description: {source.get('description', 'N/A')}")
                context_parts.append(f"CWE: {source.get('cwe', 'N/A')}")
                if source.get('cpes'):
                    context_parts.append(f"CPEs: {', '.join(source['cpes'][:5])}")
                if source.get('references'):
                    refs = [r['url'] for r in source['references'][:5]]
                    context_parts.append(f"References: {', '.join(refs)}")
            
            elif source_type in ['vendor_advisory', 'vendor_site_search']:
                context_parts.append(f"URL: {source.get('url', 'N/A')}")
                context_parts.append(f"Title: {source.get('title', 'N/A')}")
                context_parts.append(f"Content: {source.get('content', '')[:500]}")
                if source.get('versions'):
                    context_parts.append(f"Versions: {json.dumps(source['versions'], indent=2)}")
                if source.get('llm_extracted_versions'):
                    context_parts.append(f"LLM Extracted Versions: {json.dumps(source['llm_extracted_versions'], indent=2)}")
            
            elif source_type == 'github':
                data = source.get('data', {})
                context_parts.append(f"GHSA ID: {data.get('ghsa_id', 'N/A')}")
                context_parts.append(f"Summary: {data.get('summary', 'N/A')}")
                if source.get('version_info'):
                    context_parts.append(f"Version Info: {json.dumps(source['version_info'], indent=2)}")
        
        # Add OVAL learnings
        if self.learnings:
            context_parts.append("\n## OVAL XML Learnings")
            if self.learnings.get('cpe_patterns'):
                context_parts.append(f"CPE patterns: {json.dumps(list(self.learnings['cpe_patterns'].items())[:5], indent=2)}")
            if self.learnings.get('version_patterns'):
                context_parts.append(f"Version patterns: {json.dumps(self.learnings['version_patterns'][:5], indent=2)}")
            if self.learnings.get('product_naming'):
                context_parts.append(f"Product naming: {json.dumps(list(self.learnings['product_naming'].items())[:5], indent=2)}")
            if self.learnings.get('version_mistakes'):
                context_parts.append(f"Version mistakes to avoid: {self.learnings['version_mistakes']}")
        
        return "\n".join(context_parts)
    
    def _generate_output(self, cve_id: str, context: str) -> Dict[str, Any]:
        """Generate structured output using Ollama."""
        if ollama is None:
            return {
                'error': 'Ollama package not installed',
                'message': 'Install with: pip install ollama'
            }
        
        user_prompt = f"""CVE ID: {cve_id}

{context}

Please analyze the above information and fill out the research template. Prioritize vendor advisory information over NVD when available. Use the OVAL learnings to ensure consistency with existing patterns."""
        
        try:
            print(f"  - Calling Ollama model: {self.ollama_model}")
            response = ollama.chat(
                model=self.ollama_model,
                messages=[
                    {
                        'role': 'system',
                        'content': self.prompt_template
                    },
                    {
                        'role': 'user',
                        'content': user_prompt
                    }
                ]
            )
            
            output_text = response['message']['content']
            return self._parse_output(output_text)
            
        except Exception as e:
            print(f"Error calling Ollama: {e}")
            print("Make sure Ollama is running and the model is available.")
            return {'error': str(e), 'raw_output': output_text if 'output_text' in locals() else None}
    
    def _parse_output(self, output_text: str) -> Dict[str, Any]:
        """Parse the structured output from LLM."""
        result = {}
        
        sections = {
            'CVE BASIC INFORMATION': ['CVE ID', 'Vulnerability Name', 'Vulnerability Type', 'Short Description'],
            'VENDOR & PRODUCT DETAILS': ['Vendor', 'Product', 'Component / Module', 'Product Category'],
            'AFFECTED VERSIONS': ['Vulnerable Versions', 'Fixed Versions', 'Backported Fixes', 'Unsupported but Affected Versions'],
            'PLATFORM SCOPE': ['Operating Systems', 'Distributions / Editions', 'Architectures'],
            'CPE IDENTIFIERS': ['Primary CPE(s)', 'Alternative / Variant CPE(s)', 'Notes on CPE ambiguity'],
            'MERGED OVAL XML LEARNINGS': ['Required fields learned from merges', 'Version mistakes to avoid', 'CPE patterns that worked', 'Product naming normalization rules'],
            'CONFIDENCE LEVEL': ['High / Medium / Low', 'Reason']
        }
        
        current_section = None
        for line in output_text.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            for section_name in sections.keys():
                if section_name.lower() in line.lower() and '##' in line:
                    current_section = section_name
                    result[current_section] = {}
                    break
            
            if current_section:
                for field in sections[current_section]:
                    if field.lower() in line.lower() and ':' in line:
                        value = line.split(':', 1)[1].strip()
                        result[current_section][field] = value
        
        result['_raw_output'] = output_text
        return result
    
    def save_output(self, output: Dict[str, Any], output_path: str):
        """Save output to file."""
        output_dir = Path(output_path).parent
        output_dir.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            if '_raw_output' in output:
                f.write(output['_raw_output'])
            else:
                json.dump(output, f, indent=2, ensure_ascii=False)
        
        print(f"\nOutput saved to: {output_path}")


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Enhanced OVAL XML Research Agent')
    parser.add_argument('cve_id', help='CVE ID to research (e.g., CVE-2025-5591)')
    parser.add_argument('--oval-xml', 
                       default=r'C:\Users\Yashvant\OneDrive\Documents\OVAL_WINDOWS.xml',
                       help='Path to OVAL XML file')
    parser.add_argument('--ollama-model', 
                       default='llama3.2',
                       help='Ollama model to use')
    parser.add_argument('--nvd-api-key', 
                       help='NVD API key (optional)')
    parser.add_argument('--github-token',
                       help='GitHub token (optional)')
    parser.add_argument('--urls', 
                       nargs='+',
                       help='Additional vendor advisory URLs to scrape')
    parser.add_argument('--output',
                       help='Output file path (default: outputs/{cve_id}.md)')
    parser.add_argument('--vendor-db',
                       default='data/vendor_db.json',
                       help='Path to vendor database file')
    
    args = parser.parse_args()
    
    # Initialize agent
    agent = ResearchAgent(
        oval_xml_path=args.oval_xml,
        ollama_model=args.ollama_model,
        nvd_api_key=args.nvd_api_key,
        github_token=args.github_token,
        vendor_db_path=args.vendor_db
    )
    
    # Research CVE
    output = agent.research_cve(args.cve_id, args.urls)
    
    # Save output
    if args.output:
        output_path = args.output
    else:
        output_path = f"outputs/{args.cve_id}.md"
    
    agent.save_output(output, output_path)
    
    print("\n" + "="*60)
    print("Research complete!")
    print("="*60)


if __name__ == '__main__':
    main()
