"""Enhanced research agent with improved error handling, validation, and efficiency."""

import json
import os
import time
import re
from typing import Dict, List, Optional, Any, Set
from pathlib import Path
from collections import defaultdict
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock, Semaphore
from urllib.parse import urlparse
from urllib.parse import urlparse

from scrapers.nvd_scraper import NVDScraper
from scrapers.github_scraper import GitHubScraper
from scrapers.vendor_scraper import VendorScraper
from scrapers.vendor_search import VendorSiteSearcher
from oval_parser import OVALParser
from vendor_database import VendorDatabase
from llm_assistant import LLMAssistant
from tools.version_tools import VersionTools
from tools.cpe_validator import CPEValidator
from version_extractor import VersionExtractor

try:
    import ollama
except ImportError:
    print("Warning: ollama package not found. Install with: pip install ollama")
    ollama = None

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class EnhancedResearchAgent:
    """Enhanced research agent with improved error handling, validation, and efficiency."""
    
    def __init__(self, 
                 oval_xml_path: str,
                 ollama_model: str = "llama3.2",
                 nvd_api_key: Optional[str] = None,
                 github_token: Optional[str] = None,
                 vendor_db_path: str = "data/vendor_db.json",
                 max_retries: int = 3,
                 timeout: int = 30):
        """
        Initialize enhanced research agent.
        
        Args:
            oval_xml_path: Path to merged OVAL XML file
            ollama_model: Name of Ollama model to use
            nvd_api_key: Optional NVD API key
            github_token: Optional GitHub token
            vendor_db_path: Path to vendor database file
            max_retries: Maximum retry attempts for failed operations
            timeout: Request timeout in seconds
        """
        self.oval_xml_path = oval_xml_path
        self.ollama_model = ollama_model
        self.max_retries = max_retries
        self.timeout = timeout
        self.parallel_workers = min(6, os.cpu_count() or 4)
        self._llm_semaphore = Semaphore(2)
        
        # Initialize scrapers with timeout
        self.nvd_scraper = NVDScraper(api_key=nvd_api_key)
        self.github_scraper = GitHubScraper(token=github_token)
        self.vendor_scraper = VendorScraper()
        self.vendor_searcher = VendorSiteSearcher()
        
        # Initialize vendor database
        self.vendor_db = VendorDatabase(vendor_db_path)
        
        # Initialize LLM assistant
        self.llm_assistant = LLMAssistant(model=ollama_model)
        
        # Initialize tools
        self.version_tools = VersionTools()
        self.cpe_validator = CPEValidator()
        self.version_extractor = VersionExtractor()
        
        # Load OVAL learnings and vendor URLs
        self.oval_parser = OVALParser(oval_xml_path)
        self.learnings = None
        self._load_learnings()
        self._load_vendor_urls()
        
        # Load prompt template
        self.prompt_template = self._load_prompt_template()
        
        # Cache for avoiding duplicate requests
        self._request_cache: Dict[str, Any] = {}
        self._cache_ttl = 3600  # 1 hour cache TTL
    
    def _load_learnings(self):
        """Load comprehensive learnings from OVAL XML file."""
        try:
            logger.info(f"Loading learnings from {self.oval_xml_path}...")
            self.learnings = self.oval_parser.extract_learnings()
            logger.info("OVAL learnings loaded successfully.")
            
            # Log key learnings
            if self.learnings.get('version_patterns'):
                logger.info(f"Found {len(self.learnings['version_patterns'])} version patterns")
            if self.learnings.get('cpe_patterns'):
                logger.info(f"Found {len(self.learnings['cpe_patterns'])} product CPE patterns")
        except Exception as e:
            logger.warning(f"Could not load OVAL learnings: {e}")
            self.learnings = {}
    
    def _load_vendor_urls(self):
        """Extract and load vendor URLs from OVAL XML into database."""
        try:
            logger.info("Extracting vendor URLs from OVAL XML...")
            vendor_urls = self.oval_parser.extract_vendor_urls()
            
            if vendor_urls:
                self.vendor_db.add_vendor_urls(vendor_urls)
                stats = self.vendor_db.get_statistics()
                logger.info(f"Vendor database: {stats['total_products']} products, "
                          f"{stats['total_urls']} URLs, {stats['total_domains']} domains")
            else:
                logger.warning("No vendor URLs found in OVAL XML.")
        except Exception as e:
            logger.warning(f"Could not load vendor URLs: {e}")
    
    def _load_prompt_template(self) -> str:
        """Load the research agent prompt template."""
        prompt_path = Path(__file__).parent / "prompts" / "oval_xml_research_agent.md"
        try:
            with open(prompt_path, 'r', encoding='utf-8') as f:
                return f.read()
        except FileNotFoundError:
            logger.warning(f"Prompt template not found at {prompt_path}")
            return ""
    
    def _retry_with_backoff(self, func, *args, **kwargs):
        """Retry a function with exponential backoff."""
        for attempt in range(self.max_retries):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if attempt == self.max_retries - 1:
                    raise
                wait_time = 2 ** attempt
                logger.warning(f"Attempt {attempt + 1} failed: {e}. Retrying in {wait_time}s...")
                time.sleep(wait_time)
        return None
    
    def research_cve(self, cve_id: str, additional_urls: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Research a CVE using enhanced workflow with validation and error handling.
        
        Args:
            cve_id: CVE identifier (e.g., 'CVE-2025-5591')
            additional_urls: Optional list of additional URLs to scrape
            
        Returns:
            Dictionary containing structured research data
        """
        # Validate CVE ID format
        if not self._validate_cve_id(cve_id):
            return {'error': f'Invalid CVE ID format: {cve_id}'}
        
        logger.info(f"Researching {cve_id}")
        
        # Check cache first
        cache_key = f"research_{cve_id}"
        if cache_key in self._request_cache:
            cached_time, cached_data = self._request_cache[cache_key]
            if time.time() - cached_time < self._cache_ttl:
                logger.info("Using cached research data")
                return cached_data
        
        try:
            collected_data = {'cve_id': cve_id}
            start_time = time.time()
            stage_timings: Dict[str, float] = {}

            def mark_stage(stage: str):
                stage_timings[stage] = round(time.time() - start_time, 2)
            
            # STEP 1: Check vendor database FIRST (highest priority - Vendor-first approach)
            logger.info("Step 1: Checking vendor database for known URLs (Vendor-first priority)...")
            vendor_urls_from_db = self.vendor_db.get_urls_for_cve(cve_id)
            collected_data['vendor_urls_from_db'] = vendor_urls_from_db
            logger.info(f"Found {len(vendor_urls_from_db)} vendor URLs from database")
            mark_stage("vendor_db")
            
            # STEP 2: Search NVD and GitHub in parallel (independent)
            logger.info("Step 2: Searching NVD and GitHub in parallel...")
            nvd_data = None
            github_data = None
            with ThreadPoolExecutor(max_workers=2) as executor:
                nvd_future = executor.submit(self._search_nvd_safe, cve_id)
                github_future = executor.submit(self._search_github_safe, cve_id)
                nvd_data = nvd_future.result()
                github_data = github_future.result()
            collected_data['nvd_data'] = nvd_data
            collected_data['github_data'] = github_data
            mark_stage("nvd_github_search")
            
            # Extract ALL URLs from NVD references (not just vendor URLs)
            urls_from_nvd = self._extract_all_urls_from_nvd(nvd_data) if nvd_data else []
            collected_data['urls_from_nvd'] = urls_from_nvd
            logger.info(f"Found {len(urls_from_nvd)} URLs from NVD references")
            mark_stage("nvd_url_extract")
            
            # STEP 2.5 & 3: Scrape NVD reference URLs and vendor URLs in parallel
            logger.info("Step 2.5/3: Scraping NVD references and vendor advisories in parallel...")
            nvd_scraped_data = []
            vendor_data = []

            all_vendor_urls = list(set(vendor_urls_from_db + (additional_urls or [])))
            # Don't re-scrape URLs we already got from NVD references
            all_vendor_urls = [url for url in all_vendor_urls if url not in set(urls_from_nvd)]

            # Prioritize vendor URLs using pattern memory (no functional change, just ordering)
            pattern_memory = self.vendor_db.get_pattern_memory()
            if pattern_memory:
                def _memory_rank(url: str) -> int:
                    domain = self._get_domain(url)
                    return 0 if domain in pattern_memory else 1
                all_vendor_urls = sorted(all_vendor_urls, key=_memory_rank)

            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = {}
                if urls_from_nvd:
                    futures['nvd'] = executor.submit(self._scrape_nvd_urls, urls_from_nvd, cve_id)
                if all_vendor_urls:
                    futures['vendor'] = executor.submit(self._scrape_vendor_sources_enhanced, all_vendor_urls, cve_id)

                for key, future in futures.items():
                    try:
                        result = future.result()
                        if key == 'nvd':
                            nvd_scraped_data = result or []
                        else:
                            vendor_data = result or []
                    except Exception as e:
                        logger.warning(f"Parallel scrape failed for {key}: {e}")

            # Combine NVD scraped data with other vendor data (NVD data has higher priority)
            vendor_data = nvd_scraped_data + vendor_data
            collected_data['vendor_data'] = vendor_data
            logger.info(f"Total scraped {len(vendor_data)} sources (including {len(nvd_scraped_data)} from NVD references)")
            mark_stage("scrape_urls")

            # Update pattern memory from vendor data
            for item in vendor_data:
                if not isinstance(item, dict):
                    continue
                url = item.get('url', '')
                domain = self._get_domain(url)
                path = urlparse(url).path if url else ''
                patterns = []
                vv = item.get('validated_versions', {})
                if isinstance(vv, dict):
                    patterns.extend([str(v) for v in vv.get('vulnerable', []) or []])
                    patterns.extend([str(v) for v in vv.get('fixed', []) or []])
                llm = item.get('llm_version_interpretation', {})
                if isinstance(llm, dict):
                    patterns.extend([str(v) for v in llm.get('vulnerable_ranges', []) or []])
                if patterns:
                    self.vendor_db.update_pattern_memory(domain, path, patterns)

            def _vendor_entry_has_versions(item: Dict[str, Any]) -> bool:
                if not isinstance(item, dict):
                    return False
                if item.get('validated_versions'):
                    vv = item['validated_versions'].get('vulnerable', []) or []
                    fv = item['validated_versions'].get('fixed', []) or []
                    if vv or fv:
                        return True
                if item.get('llm_version_interpretation'):
                    ranges = item['llm_version_interpretation'].get('vulnerable_ranges', []) or []
                    if ranges:
                        return True
                if item.get('versions'):
                    if item['versions'].get('vulnerable') or item['versions'].get('fixed'):
                        return True
                return False

            vendor_has_versions = any(_vendor_entry_has_versions(item) for item in vendor_data)
            vendor_has_trusted = any(self._is_trusted_vendor_domain(item.get('url', '')) for item in vendor_data)
            fast_path_vendor_search_ok = vendor_has_versions and vendor_has_trusted
            
            # STEP 4: If insufficient vendor data, perform intelligent vendor site search
            if not vendor_data or len(vendor_data) == 0:
                logger.info("Step 4: Performing deep vendor site search (insufficient vendor data)...")
                product_info = self._extract_product_info(cve_id, nvd_data)
                vendor_site_results = self._deep_vendor_search(cve_id, product_info)
                vendor_data.extend(vendor_site_results)
                collected_data['vendor_site_search_results'] = vendor_site_results
                logger.info(f"Found {len(vendor_site_results)} additional vendor sources")
                mark_stage("deep_vendor_search")
            elif fast_path_vendor_search_ok:
                logger.info("Fast-path: vendor data sufficient, skipping deep vendor site search.")
            
            # STEP 5: GitHub data already collected in parallel in Step 2
            
            # STEP 6: PARALLEL - Extract version information and LLM interpretation (can run in parallel)
            logger.info("Step 6: Parallel processing - Version extraction and LLM interpretation...")
            
            # Prepare descriptions for parallel LLM processing
            nvd_description = None
            gh_description = None
            
            if nvd_data:
                if 'descriptions' in nvd_data and len(nvd_data['descriptions']) > 0:
                    nvd_description = nvd_data['descriptions'][0].get('value', '')
                elif 'cve' in nvd_data and 'descriptions' in nvd_data['cve']:
                    desc_list = nvd_data['cve']['descriptions']
                    if desc_list and len(desc_list) > 0:
                        nvd_description = desc_list[0].get('value', '')
            
            if github_data:
                if 'data' in github_data:
                    gh_description = github_data['data'].get('description', '') or github_data['data'].get('summary', '')
            
            # Run LLM interpretations in parallel if both are available
            nvd_llm_interp = None
            gh_llm_interp = None
            
            if self.llm_assistant.available:
                with ThreadPoolExecutor(max_workers=2) as executor:
                    futures = {}
                    if nvd_description:
                        futures['nvd'] = executor.submit(
                            self.llm_assistant.interpret_version_wording, 
                            nvd_description, 
                            cve_id
                        )
                    if gh_description:
                        futures['github'] = executor.submit(
                            self.llm_assistant.interpret_version_wording,
                            gh_description,
                            cve_id
                        )
                    
                    # Collect results
                    for source, future in futures.items():
                        try:
                            result = future.result()
                            if source == 'nvd':
                                nvd_llm_interp = result
                            else:
                                gh_llm_interp = result
                        except Exception as e:
                            logger.warning(f"LLM interpretation failed for {source}: {e}")
                
                if nvd_llm_interp:
                    collected_data['nvd_llm_interpretation'] = nvd_llm_interp
                    logger.info(f"LLM extracted {len(nvd_llm_interp.get('vulnerable_ranges', []))} version ranges from NVD")
                if gh_llm_interp:
                    collected_data['github_llm_interpretation'] = gh_llm_interp
                    logger.info(f"LLM extracted {len(gh_llm_interp.get('vulnerable_ranges', []))} version ranges from GitHub")
                mark_stage("llm_interp")
            
            # Extract version information using version extractor (non-blocking, fast)
            logger.info("Step 7: Extracting comprehensive version information...")
            version_info = self.version_extractor.format_version_info(nvd_data, vendor_data, github_data, collected_data)
            collected_data['version_info'] = version_info
            logger.info(f"Extracted {len(version_info.get('vulnerable_versions', []))} vulnerable versions, "
                       f"{len(version_info.get('fixed_versions', []))} fixed versions")
            mark_stage("version_extract")

            fast_path_ok = self._vendor_fast_path_ok(vendor_data, nvd_data, github_data, version_info)
            
            # STEP 8: Deep LLM-assisted search if data is insufficient
            if self._is_data_insufficient(vendor_data, nvd_data, github_data, version_info):
                if fast_path_ok:
                    logger.info("Fast-path: sufficient vendor evidence, skipping deep LLM search.")
                else:
                    logger.info("Step 8: Performing deep LLM-assisted search (data insufficient)...")
                    deep_search_results = self._deep_llm_search(cve_id, collected_data)
                    vendor_data.extend(deep_search_results.get('vendor_data', []))
                    collected_data['deep_search_results'] = deep_search_results
                    logger.info("Deep LLM search completed")
                    mark_stage("deep_llm_search")
            
            # STEP 9: Prioritize sources using LLM (Vendor sources get highest priority)
            logger.info("Step 9: Prioritizing sources (Vendor-first approach)...")
            all_sources = self._combine_sources(nvd_data, vendor_data, github_data)
            prioritized_sources = self._prioritize_sources_vendor_first(all_sources)
            collected_data['prioritized_sources'] = prioritized_sources
            mark_stage("prioritize_sources")
            
            # STEP 10: Validate and enrich data using OVAL learnings
            logger.info("Step 10: Enriching with OVAL learnings...")
            enriched_sources = self._enrich_with_learnings(prioritized_sources, cve_id)
            collected_data['enriched_sources'] = enriched_sources
            mark_stage("enrich_learnings")
            
            # STEP 11: Format data for LLM
            formatted_context = self._format_context_enhanced(enriched_sources)
            collected_data['formatted_context'] = formatted_context
            mark_stage("format_context")
            
            # STEP 12: Generate structured output using Ollama
            logger.info("Step 12: Generating structured output with Ollama...")
            structured_output = self._generate_output_safe(cve_id, formatted_context, nvd_data, vendor_data, github_data, enriched_sources)
            mark_stage("llm_output")
            
            # Always include collected data and version info
            if 'collected_data' not in structured_output:
                structured_output['collected_data'] = {}
            
            structured_output['collected_data'].update(collected_data)
            
            # Add comprehensive version information
            structured_output['version_info'] = version_info
            
            # Add OVAL learnings used
            structured_output['oval_learnings_applied'] = {
                'version_patterns_count': len(self.learnings.get('version_patterns', [])),
                'cpe_patterns_count': len(self.learnings.get('cpe_patterns', {})),
                'product_naming_variants': len(self.learnings.get('product_naming', {})),
            }
            
            # Add metadata
            structured_output['metadata'] = {
                'cve_id': cve_id,
                'research_date': time.strftime('%Y-%m-%d %H:%M:%S'),
                'agent_version': '3.0',
                'oval_xml_path': self.oval_xml_path,
                'priority_order': 'Vendor-first',
                'workflow_steps_completed': 11,
                'timings_seconds': stage_timings,
                'fast_path_used': fast_path_ok
            }
            
            # Cache the result
            self._request_cache[cache_key] = (time.time(), structured_output)
            
            logger.info(f"Research completed for {cve_id}")
            return structured_output
            
        except Exception as e:
            logger.error(f"Error researching {cve_id}: {e}", exc_info=True)
            # Try to include version info even on error
            version_info = {}
            try:
                # Get any collected data from locals if available
                nvd_data_local = locals().get('nvd_data', None)
                vendor_data_local = locals().get('vendor_data', [])
                github_data_local = locals().get('github_data', None)
                version_info = self.version_extractor.format_version_info(
                    nvd_data_local,
                    vendor_data_local,
                    github_data_local
                )
            except:
                pass
            
            return {
                'error': str(e),
                'cve_id': cve_id,
                'version_info': version_info
            }
    
    def _validate_cve_id(self, cve_id: str) -> bool:
        """Validate CVE ID format."""
        import re
        pattern = r'^CVE-\d{4}-\d{4,}$'
        return bool(re.match(pattern, cve_id))

    def _get_domain(self, url: str) -> str:
        """Extract normalized domain from URL."""
        try:
            netloc = urlparse(url).netloc.lower()
            if netloc.startswith("www."):
                netloc = netloc[4:]
            return netloc
        except Exception:
            return ""

    def _is_trusted_vendor_domain(self, url: str) -> bool:
        """Check if URL domain is in vendor DB domains."""
        domain = self._get_domain(url)
        if not domain:
            return False
        for known in self.vendor_db.get_all_domains():
            known_domain = known.lower().lstrip(".")
            if domain == known_domain or domain.endswith(f".{known_domain}"):
                return True
        return False

    def _collect_version_strings(self, version_info: Dict[str, Any]) -> Set[str]:
        """Collect normalized version strings/ranges for conflict checks."""
        values = set()
        if not version_info:
            return values
        for key in ['vulnerable_versions', 'fixed_versions', 'vulnerable_version_ranges', 'version_ranges']:
            items = version_info.get(key, [])
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        val = item.get('range') or item.get('value') or ""
                    else:
                        val = str(item)
                    val = val.strip()
                    if val:
                        values.add(val)
        return values

    def _vendor_fast_path_ok(self, vendor_data: List[Dict[str, Any]],
                             nvd_data: Optional[Dict[str, Any]],
                             github_data: Optional[Dict[str, Any]],
                             version_info: Dict[str, Any]) -> bool:
        """Decide if vendor data is sufficient to skip deeper steps."""
        if not vendor_data:
            return False
        trusted = any(self._is_trusted_vendor_domain(item.get('url', '')) for item in vendor_data)
        if not trusted:
            return False

        vendor_versions = self._collect_version_strings(version_info)
        if not vendor_versions:
            return False

        other_versions = set()
        if nvd_data:
            other_versions |= self._collect_version_strings(
                self.version_extractor.format_version_info(nvd_data, [], None, {})
            )
        if github_data:
            other_versions |= self._collect_version_strings(
                self.version_extractor.format_version_info(None, [], github_data, {})
            )
        if other_versions and vendor_versions.isdisjoint(other_versions):
            return False

        return True

    def _get_domain(self, url: str) -> str:
        """Extract normalized domain from URL."""
        try:
            netloc = urlparse(url).netloc.lower()
            if netloc.startswith("www."):
                netloc = netloc[4:]
            return netloc
        except Exception:
            return ""

    def _is_trusted_vendor_domain(self, url: str) -> bool:
        """Check if URL domain is in vendor DB domains."""
        domain = self._get_domain(url)
        if not domain:
            return False
        for known in self.vendor_db.get_all_domains():
            known_domain = known.lower().lstrip(".")
            if domain == known_domain or domain.endswith(f".{known_domain}"):
                return True
        return False

    def _collect_version_strings(self, version_info: Dict[str, Any]) -> Set[str]:
        """Collect normalized version strings/ranges for conflict checks."""
        values = set()
        if not version_info:
            return values
        for key in ['vulnerable_versions', 'fixed_versions', 'vulnerable_version_ranges', 'version_ranges']:
            items = version_info.get(key, [])
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        val = item.get('range') or item.get('value') or ""
                    else:
                        val = str(item)
                    val = val.strip()
                    if val:
                        values.add(val)
        return values

    def _vendor_fast_path_ok(self, vendor_data: List[Dict[str, Any]],
                             nvd_data: Optional[Dict[str, Any]],
                             github_data: Optional[Dict[str, Any]],
                             version_info: Dict[str, Any]) -> bool:
        """Decide if vendor data is sufficient to skip deeper steps."""
        if not vendor_data:
            return False
        # Must have at least one trusted vendor URL
        trusted = any(self._is_trusted_vendor_domain(item.get('url', '')) for item in vendor_data)
        if not trusted:
            return False

        # Must have explicit vulnerable or fixed versions/ranges
        vendor_versions = self._collect_version_strings(version_info)
        if not vendor_versions:
            return False

        # If NVD/GitHub also have version info, require non-conflicting overlap
        other_versions = set()
        if nvd_data:
            other_versions |= self._collect_version_strings(
                self.version_extractor.format_version_info(nvd_data, [], None, {})
            )
        if github_data:
            other_versions |= self._collect_version_strings(
                self.version_extractor.format_version_info(None, [], github_data, {})
            )
        if other_versions and vendor_versions.isdisjoint(other_versions):
            # Conflict detected, do not fast-path
            return False

        return True
    
    def _search_nvd_safe(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Safely search NVD with retry logic."""
        try:
            return self._retry_with_backoff(self.nvd_scraper.get_cve, cve_id)
        except Exception as e:
            logger.error(f"Error searching NVD for {cve_id}: {e}")
            suggestion = self.llm_assistant.handle_scraping_error(e, {'source': 'NVD', 'cve_id': cve_id})
            logger.info(f"LLM suggestion: {suggestion.get('suggestion', 'N/A')}")
            return None
    
    def _search_github_safe(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Safely search GitHub with retry logic."""
        try:
            ghsa_data = self._retry_with_backoff(self.github_scraper.get_advisory_by_cve, cve_id)
            if ghsa_data:
                version_info = self.github_scraper.extract_version_info(ghsa_data)
                return {
                    'source': 'github',
                    'data': ghsa_data,
                    'version_info': version_info,
                    'priority': 2
                }
            return None
        except Exception as e:
            logger.error(f"Error searching GitHub for {cve_id}: {e}")
            return None
    
    def _scrape_vendor_sources_safe(self, vendor_urls: List[str], cve_id: str) -> List[Dict[str, Any]]:
        """Safely scrape vendor sources with retry logic."""
        return self._scrape_vendor_sources_enhanced(vendor_urls, cve_id)
    
    def _scrape_vendor_sources_enhanced(self, vendor_urls: List[str], cve_id: str) -> List[Dict[str, Any]]:
        """Enhanced vendor scraping with version/build info extraction and LLM interpretation."""
        vendor_data = []
        if not vendor_urls:
            return vendor_data

        def process_url(url: str) -> Optional[Dict[str, Any]]:
            try:
                data = self._retry_with_backoff(self.vendor_scraper.scrape_advisory, url)
                if not data:
                    return None
                content = data.get('content', '')

                # Enhanced version extraction (regex-based)
                data['versions'] = self._extract_enhanced_versions(content, url)

                # Extract build numbers if present
                data['build_info'] = self._extract_build_info(content)

                # ALWAYS use LLM to interpret version wording (by default, as requested)
                if self.llm_assistant.available and content:
                    logger.info(f"Using LLM to interpret version wording from {url}...")
                    with self._llm_semaphore:
                        llm_interpretation = self.llm_assistant.interpret_version_wording(content, cve_id)
                    if llm_interpretation:
                        data['llm_version_interpretation'] = llm_interpretation
                        logger.info(
                            f"LLM extracted {len(llm_interpretation.get('vulnerable_ranges', []))} "
                            f"version ranges from {url}"
                        )

                    # Also extract version info (fallback if interpretation doesn't work)
                    if not llm_interpretation or not llm_interpretation.get('vulnerable_ranges'):
                        with self._llm_semaphore:
                            llm_version_info = self.llm_assistant.extract_version_info(content, cve_id)
                        if llm_version_info:
                            data['llm_extracted_versions'] = llm_version_info

                # Validate versions using OVAL learnings
                data['validated_versions'] = self._validate_versions(
                    data.get('versions', {}),
                    data.get('llm_extracted_versions', {}),
                    data.get('llm_version_interpretation', {})
                )

                data['source'] = 'vendor_advisory'
                data['priority'] = 1  # Highest priority
                return data
            except Exception as e:
                logger.warning(f"Error scraping {url}: {e}")
                return None

        max_workers = min(self.parallel_workers, len(vendor_urls))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(process_url, url): url for url in vendor_urls}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    vendor_data.append(result)

        return vendor_data
    
    def _extract_enhanced_versions(self, text: str, url: str) -> Dict[str, Any]:
        """Enhanced version extraction with build numbers and ranges."""
        versions = {
            'vulnerable': [],
            'fixed': [],
            'patched': [],
            'build_numbers': [],
            'version_ranges': []
        }
        
        # Enhanced patterns for version extraction
        patterns = {
            'fixed': [
                r'fixed in (?:version|v|release)?\s*([0-9.]+(?:\.[0-9]+)*(?:-[a-z0-9]+)?)',
                r'patched in (?:version|v|release)?\s*([0-9.]+(?:\.[0-9]+)*(?:-[a-z0-9]+)?)',
                r'(?:version|v|release)\s*([0-9.]+(?:\.[0-9]+)*(?:-[a-z0-9]+)?)\s+fixes',
                r'resolved in (?:version|v|release)?\s*([0-9.]+(?:\.[0-9]+)*(?:-[a-z0-9]+)?)',
                r'upgrade to (?:version|v|release)?\s*([0-9.]+(?:\.[0-9]+)*(?:-[a-z0-9]+)?)',
                r'update to (?:version|v|release)?\s*([0-9.]+(?:\.[0-9]+)*(?:-[a-z0-9]+)?)',
            ],
            'vulnerable': [
                r'versions?\s+([0-9.]+(?:\.[0-9]+)*)\s+through\s+([0-9.]+(?:\.[0-9]+)*)',
                r'versions?\s+([0-9.]+(?:\.[0-9]+)*)\s+to\s+([0-9.]+(?:\.[0-9]+)*)',
                r'all versions?\s+(?:before|prior to|up to|until)\s+([0-9.]+(?:\.[0-9]+)*(?:-[a-z0-9]+)?)',
                r'versions?\s+(?:before|prior to|up to|until)\s+([0-9.]+(?:\.[0-9]+)*(?:-[a-z0-9]+)?)',
                r'<=\s*([0-9.]+(?:\.[0-9]+)*(?:-[a-z0-9]+)?)',
                r'<\s*([0-9.]+(?:\.[0-9]+)*(?:-[a-z0-9]+)?)',
            ],
            'build': [
                r'build\s+([0-9]+)',
                r'build\s+number\s+([0-9]+)',
                r'version\s+[0-9.]+\s+build\s+([0-9]+)',
                r'\(build\s+([0-9]+)\)',
            ]
        }
        
        for pattern_type, pattern_list in patterns.items():
            for pattern in pattern_list:
                matches = re.findall(pattern, text, re.IGNORECASE)
                if matches:
                    if pattern_type == 'vulnerable' and len(matches[0]) == 2:
                        # Range match
                        versions['version_ranges'].append(f"{matches[0][0]} to {matches[0][1]}")
                    elif pattern_type == 'build':
                        versions['build_numbers'].extend([m if isinstance(m, str) else str(m[0]) for m in matches])
                    else:
                        versions[pattern_type].extend([m if isinstance(m, str) else m[0] for m in matches])
        
        # Remove duplicates
        for key in versions:
            versions[key] = list(set(versions[key]))
        
        return versions
    
    def _extract_build_info(self, text: str) -> Dict[str, Any]:
        """Extract build number information."""
        build_info = {
            'build_numbers': [],
            'build_ranges': []
        }
        
        # Build number patterns
        build_patterns = [
            r'build\s+(?:number\s+)?([0-9]+)',
            r'\(build\s+([0-9]+)\)',
            r'version\s+[0-9.]+\s+build\s+([0-9]+)',
            r'b([0-9]+)',  # Common abbreviation
        ]
        
        for pattern in build_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            build_info['build_numbers'].extend(matches)
        
        build_info['build_numbers'] = list(set(build_info['build_numbers']))
        return build_info
    
    def _search_vendor_sites_safe(self, cve_id: str, product_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Safely search vendor sites with retry logic."""
        results = []

        # Get domains from product info
        domains_to_search = []
        if product_info.get('vendors'):
            for vendor in product_info['vendors']:
                all_products = self.vendor_db.get_all_products()
                for product in all_products:
                    domains = self.vendor_db.get_vendor_domains_for_product(product)
                    domains_to_search.extend(domains)

        all_domains = self.vendor_db.get_all_domains()
        domains_to_search.extend(list(all_domains)[:10])
        domains_to_search = list(set(domains_to_search))

        if not domains_to_search:
            return results

        product_name = product_info.get('products', [None])[0] if product_info.get('products') else None
        domains_to_search = domains_to_search[:8]

        # Step 1: Search vendor sites in parallel per domain
        domain_search_results = []
        max_workers = min(self.parallel_workers, len(domains_to_search))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(
                    self._retry_with_backoff,
                    self.vendor_searcher.search_vendor_site,
                    domain, cve_id, product_name
                ): domain for domain in domains_to_search
            }

            for future in as_completed(futures):
                domain = futures[future]
                try:
                    search_results = future.result() or []
                    for result in search_results:
                        if result.get('url'):
                            domain_search_results.append(result)
                except Exception as e:
                    logger.warning(f"Error searching {domain}: {e}")

        if not domain_search_results:
            return results

        # Deduplicate URLs
        seen_urls = set()
        unique_results = []
        for item in domain_search_results:
            url = item.get('url')
            if url and url not in seen_urls:
                seen_urls.add(url)
                unique_results.append(item)

        # Step 2: Scrape results in parallel
        def scrape_result(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
            url = item.get('url')
            if not url:
                return None
            try:
                scraped = self._retry_with_backoff(self.vendor_scraper.scrape_advisory, url)
                if scraped:
                    scraped['source'] = 'vendor_site_search'
                    scraped['priority'] = 2
                    scraped['search_confidence'] = item.get('confidence', 'low')
                    return scraped
            except Exception as e:
                logger.warning(f"Error scraping {url}: {e}")
            return None

        max_workers = min(self.parallel_workers, len(unique_results))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(scrape_result, item): item for item in unique_results}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)

        return results
    
    def _deep_vendor_search(self, cve_id: str, product_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Deep vendor site search with multiple strategies."""
        return self._search_vendor_sites_safe(cve_id, product_info)
    
    def _deep_llm_search(self, cve_id: str, collected_data: Dict[str, Any]) -> Dict[str, Any]:
        """Deep LLM-assisted search when initial data is insufficient."""
        if not ollama:
            return {}
        
        try:
            # Use LLM to suggest search strategies
            prompt = f"""CVE {cve_id} has insufficient information. Current data:
- Vendor sources: {len(collected_data.get('vendor_data', []))}
- NVD data: {'Yes' if collected_data.get('nvd_data') else 'No'}
- GitHub data: {'Yes' if collected_data.get('github_data') else 'No'}
- Version info: {len(collected_data.get('version_info', {}).get('vulnerable_versions', []))} vulnerable versions found

Suggest:
1. Additional vendor URLs to search
2. Alternative search terms
3. Related products/components to investigate
4. Version/build number patterns to look for

Respond in JSON:
{{
    "suggested_urls": ["url1", "url2"],
    "search_terms": ["term1", "term2"],
    "related_products": ["product1", "product2"],
    "version_patterns": ["pattern1", "pattern2"]
}}"""
            
            response = ollama.chat(
                model=self.ollama_model,
                messages=[{'role': 'user', 'content': prompt}]
            )
            
            suggestions = json.loads(response['message']['content'])
            
            # Execute suggested searches
            vendor_data = []
            for url in suggestions.get('suggested_urls', [])[:5]:
                try:
                    data = self.vendor_scraper.scrape_advisory(url)
                    if data:
                        vendor_data.append(data)
                except:
                    pass
            
            return {
                'vendor_data': vendor_data,
                'suggestions': suggestions
            }
        except Exception as e:
            logger.warning(f"Deep LLM search failed: {e}")
            return {}
    
    def _is_data_insufficient(self, vendor_data: List, nvd_data: Optional[Dict], 
                             github_data: Optional[Dict], version_info: Dict) -> bool:
        """Check if collected data is insufficient."""
        # Check if we have version information
        has_versions = (
            len(version_info.get('vulnerable_versions', [])) > 0 or
            len(version_info.get('fixed_versions', [])) > 0
        )
        
        # Check if we have vendor data
        has_vendor_data = len(vendor_data) > 0
        
        # Check if we have basic CVE info
        has_basic_info = nvd_data is not None
        
        # Data is insufficient if we don't have versions AND vendor data
        return not (has_versions and has_vendor_data) and has_basic_info
    
    def _prioritize_sources_vendor_first(self, sources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Prioritize sources with Vendor-first approach."""
        # Sort by priority: vendor (1) > github (2) > nvd (3) > other (4)
        priority_map = {
            'vendor_advisory': 1,
            'vendor_site_search': 2,
            'github': 3,
            'nvd': 4
        }
        
        def get_priority(source):
            source_type = source.get('source', 'unknown')
            return priority_map.get(source_type, 5)
        
        return sorted(sources, key=get_priority)
    
    def _extract_product_info(self, cve_id: str, nvd_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract product information from CVE ID and NVD data."""
        product_info = {
            'vendors': [],
            'products': [],
            'cpes': []
        }
        
        if nvd_data:
            cpes = self.nvd_scraper.extract_cpe_list(nvd_data)
            products = set()
            vendors = set()
            
            for cpe in cpes[:10]:
                if cpe.startswith('cpe:2.3:'):
                    parts = cpe.split(':')
                    if len(parts) >= 5:
                        vendors.add(parts[3])
                        products.add(parts[4])
            
            product_info['vendors'] = list(vendors)
            product_info['products'] = list(products)
            product_info['cpes'] = cpes[:5]
        
        return product_info
    
    def _validate_versions(self, versions: Dict, llm_versions: Dict, llm_interpretation: Optional[Dict] = None) -> Dict[str, Any]:
        """Validate version information using OVAL learnings."""
        validation = {
            'is_valid': True,
            'warnings': [],
            'suggestions': []
        }
        
        # Check version format consistency
        if self.learnings.get('version_patterns'):
            common_formats = [p['format'] for p in self.learnings['version_patterns']]
            if common_formats:
                most_common_format = max(set(common_formats), key=common_formats.count)
                
                # Check if extracted versions match common format
                for version_list in [versions.get('fixed', []), versions.get('vulnerable', [])]:
                    for version in version_list:
                        # Classify version format
                        import re
                        version_clean = re.sub(r'^v', '', str(version), flags=re.IGNORECASE).strip()
                        if re.match(r'^\d+\.\d+\.\d+', version_clean):
                            format_type = 'semantic'
                        elif re.match(r'^\d+\.\d+', version_clean):
                            format_type = 'major.minor'
                        elif re.match(r'^\d+$', version_clean):
                            format_type = 'integer'
                        else:
                            format_type = 'custom'
                        if format_type != most_common_format:
                            validation['warnings'].append(
                                f"Version {version} format ({format_type}) doesn't match common format ({most_common_format})"
                            )
        
        # Check for common mistakes
        if self.learnings.get('version_mistakes'):
            for mistake in self.learnings['version_mistakes']:
                validation['warnings'].append(f"Potential issue: {mistake}")
        
        if validation['warnings']:
            validation['is_valid'] = False
        
        return validation
    
    def _enrich_with_learnings(self, sources: List[Dict[str, Any]], cve_id: str) -> List[Dict[str, Any]]:
        """Enrich sources with OVAL learnings."""
        enriched = []
        
        for source in sources:
            enriched_source = source.copy()
            
            # Add CPE validation
            if source.get('cpes'):
                validated_cpes = []
                for cpe in source['cpes']:
                    is_valid, error = self.cpe_validator.validate_cpe(cpe)
                    if is_valid:
                        validated_cpes.append(cpe)
                    else:
                        logger.warning(f"Invalid CPE: {cpe} - {error}")
                
                enriched_source['validated_cpes'] = validated_cpes
            
            # Add product naming suggestions
            if source.get('products'):
                for product in source['products']:
                    # Normalize product name
                    import re
                    normalized = re.sub(r'[^a-z0-9]', '', str(product).lower())
                    if normalized in self.learnings.get('product_naming', {}):
                        variants = self.learnings['product_naming'][normalized]
                        enriched_source['product_variants'] = variants
            
            enriched.append(enriched_source)
        
        return enriched
    
    def _extract_all_urls_from_nvd(self, nvd_data: Optional[Dict[str, Any]]) -> List[str]:
        """Extract ALL URLs from NVD references (not just vendor URLs)."""
        all_urls = []
        
        if not nvd_data:
            return all_urls
        
        try:
            # NVD API v2 structure: references might be in different places
            # Try multiple possible locations
            references = []
            
            # Check if references is directly in nvd_data
            if 'references' in nvd_data:
                refs = nvd_data.get('references', [])
                if isinstance(refs, list):
                    references = refs
                elif isinstance(refs, dict) and 'reference_data' in refs:
                    references = refs.get('reference_data', [])
            
            # Also check in cve structure if present
            if not references and 'cve' in nvd_data:
                cve_data = nvd_data.get('cve', {})
                if 'references' in cve_data:
                    refs = cve_data.get('references', [])
                    if isinstance(refs, list):
                        references = refs
                    elif isinstance(refs, dict) and 'reference_data' in refs:
                        references = refs.get('reference_data', [])
            
            # Extract ALL URLs (excluding NVD and GitHub self-references)
            for ref in references:
                if isinstance(ref, dict):
                    url = ref.get('url', '')
                    if url:
                        # Skip NVD and GitHub self-references
                        if not url.startswith('https://nvd.nist.gov') and not url.startswith('https://github.com/advisories'):
                            all_urls.append(url)
        except Exception as e:
            logger.warning(f"Error extracting URLs from NVD: {e}")
        
        return all_urls
    
    def _scrape_single_url(self, url: str, cve_id: str, url_type: str = 'vendor') -> Optional[Dict[str, Any]]:
        """Scrape a single URL (helper for parallel execution)."""
        try:
            if url_type == 'nvd':
                return self.vendor_scraper.scrape_advisory(url)
            else:
                return self.vendor_scraper.scrape_advisory(url)
        except Exception as e:
            logger.warning(f"Error scraping {url}: {e}")
            return None
    
    def _scrape_nvd_urls(self, urls: List[str], cve_id: str) -> List[Dict[str, Any]]:
        """
        Scrape ALL URLs found in NVD references.
        
        Args:
            urls: List of URLs from NVD references
            cve_id: CVE identifier for context
            
        Returns:
            List of scraped data from URLs
        """
        scraped_data = []
        
        if not urls:
            return scraped_data
        
        logger.info(f"Scraping {len(urls)} URLs from NVD references...")
        
        def process_url(url: str) -> Optional[Dict[str, Any]]:
            try:
                scraped = self._retry_with_backoff(self.vendor_scraper.scrape_advisory, url)
                if not scraped:
                    logger.warning(f"Failed to scrape vendor advisory: {url}")
                    return None

                # Use LLM to interpret version wording
                content = scraped.get('content', '')
                if content and self.llm_assistant.available:
                    logger.info(f"Using LLM to interpret version wording from {url}...")
                    with self._llm_semaphore:
                        llm_interpretation = self.llm_assistant.interpret_version_wording(content, cve_id)
                    if llm_interpretation:
                        scraped['llm_version_interpretation'] = llm_interpretation
                        logger.info(
                            f"LLM extracted {len(llm_interpretation.get('vulnerable_ranges', []))} version ranges"
                        )

                scraped['source'] = 'nvd_reference'
                scraped['priority'] = 1  # High priority - from NVD references
                logger.info(f"Successfully scraped vendor advisory: {url}")
                return scraped
            except Exception as e:
                logger.warning(f"Error scraping vendor URL {url}: {e}")
                return None

        max_workers = min(self.parallel_workers, len(urls))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(process_url, url): url for url in urls}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    scraped_data.append(result)

        return scraped_data
    
    def _extract_product_from_nvd(self, nvd_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract product information from NVD data."""
        if not nvd_data:
            return {}
        
        cpes = self.nvd_scraper.extract_cpe_list(nvd_data)
        products = set()
        vendors = set()
        
        for cpe in cpes[:5]:
            if cpe.startswith('cpe:2.3:'):
                parts = cpe.split(':')
                if len(parts) >= 5:
                    vendors.add(parts[3])
                    products.add(parts[4])
        
        return {
            'vendors': list(vendors),
            'products': list(products),
            'cpes': cpes[:3]
        }
    
    def _combine_sources(self, nvd_data: Optional[Dict], vendor_data: List[Dict], github_data: Optional[Dict]) -> List[Dict]:
        """Combine all sources into a single list with proper structure."""
        sources = []
        
        if nvd_data:
            # Structure NVD data properly
            nvd_source = {
                'source': 'nvd',
                'data': nvd_data,
                'description': nvd_data.get('descriptions', [{}])[0].get('value', '') if nvd_data.get('descriptions') else '',
                'cwe': None,
                'cpes': self.nvd_scraper.extract_cpe_list(nvd_data) if nvd_data else [],
                'priority': 3
            }
            # Extract CWE from weaknesses
            if nvd_data.get('weaknesses'):
                for weakness in nvd_data['weaknesses']:
                    if weakness.get('description'):
                        for desc in weakness['description']:
                            if desc.get('value', '').startswith('CWE-'):
                                nvd_source['cwe'] = desc['value']
                                break
            sources.append(nvd_source)
        
        sources.extend(vendor_data)
        
        if github_data:
            # Structure GitHub data properly
            gh_source = {
                'source': 'github',
                'data': github_data.get('data', {}),
                'version_info': github_data.get('version_info', {}),
                'priority': 2
            }
            sources.append(gh_source)
        
        return sources
    
    def _format_context_enhanced(self, sources: List[Dict[str, Any]]) -> str:
        """Format prioritized sources as context with OVAL learnings."""
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
                if source.get('validated_cpes'):
                    context_parts.append(f"Validated CPEs: {', '.join(source['validated_cpes'][:5])}")
            
            elif source_type in ['vendor_advisory', 'vendor_site_search']:
                context_parts.append(f"URL: {source.get('url', 'N/A')}")
                context_parts.append(f"Title: {source.get('title', 'N/A')}")
                if source.get('validated_versions'):
                    val = source['validated_versions']
                    if val.get('warnings'):
                        context_parts.append(f"Version Validation Warnings: {val['warnings']}")
            
            elif source_type == 'github':
                data = source.get('data', {})
                context_parts.append(f"GHSA ID: {data.get('ghsa_id', 'N/A')}")
                if source.get('version_info'):
                    context_parts.append(f"Version Info: {json.dumps(source['version_info'], indent=2)}")
        
        # Add comprehensive OVAL learnings
        if self.learnings:
            context_parts.append("\n## OVAL XML Learnings")
            
            # Version patterns
            if self.learnings.get('version_patterns'):
                context_parts.append(f"\n### Version Patterns")
                for pattern in self.learnings['version_patterns'][:10]:
                    context_parts.append(f"- {pattern['pattern']} ({pattern['format']}) - {pattern.get('install_method', 'N/A')}")
            
            # CPE patterns
            if self.learnings.get('cpe_patterns'):
                context_parts.append(f"\n### CPE Patterns")
                for product, cpes in list(self.learnings['cpe_patterns'].items())[:5]:
                    context_parts.append(f"- {product}: {cpes[0] if cpes else 'N/A'}")
            
            # Description patterns
            if self.learnings.get('description_patterns'):
                desc_patterns = self.learnings['description_patterns']
                if desc_patterns.get('prior_to_patterns'):
                    context_parts.append(f"\n### Common 'Prior To' Versions")
                    context_parts.append(f"- {', '.join(desc_patterns['prior_to_patterns'][:5])}")
            
            # Best practices
            if self.learnings.get('best_practices'):
                bp = self.learnings['best_practices']
                context_parts.append(f"\n### Best Practices")
                context_parts.append(f"- Inventory definitions extend: {bp.get('extend_inventory', False)}")
                context_parts.append(f"- Average description length: {bp.get('avg_description_length', 0):.0f} chars")
        
        return "\n".join(context_parts)
    
    def _generate_output_safe(self, cve_id: str, context: str, nvd_data: Optional[Dict] = None, 
                             vendor_data: List = None, github_data: Optional[Dict] = None,
                             enriched_sources: List = None) -> Dict[str, Any]:
        """Safely generate structured output using Ollama."""
        if ollama is None:
            logger.warning("Ollama not available - will return collected data")
            return {
                'error': 'Ollama package not installed',
                'message': 'Install with: pip install ollama',
                'note': 'Data was collected but structured output generation requires Ollama',
                'cve_id': cve_id
            }
        
        user_prompt = f"""CVE ID: {cve_id}

{context}

Please analyze the above information and fill out the research template. Prioritize vendor advisory information over NVD when available. Use the OVAL learnings to ensure consistency with existing patterns."""
        
        try:
            response = self._retry_with_backoff(
                ollama.chat,
                model=self.ollama_model,
                messages=[
                    {'role': 'system', 'content': self.prompt_template},
                    {'role': 'user', 'content': user_prompt}
                ]
            )
            
            output_text = response['message']['content']
            return self._parse_output(output_text)
            
        except Exception as e:
            logger.error(f"Error calling Ollama: {e}")
            # Return collected data even if LLM generation fails
            return {
                'error': f'Ollama not available: {str(e)}',
                'cve_id': cve_id,
                'collected_data': {
                    'nvd_data': nvd_data or {},
                    'vendor_data': vendor_data or [],
                    'github_data': github_data or {},
                    'sources': enriched_sources or []
                },
                'message': 'Install Ollama for structured output generation: pip install ollama'
            }
    
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
        """Save output to file as formatted JSON."""
        output_dir = Path(output_path).parent
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Ensure JSON extension
        if not output_path.endswith('.json'):
            output_path = str(Path(output_path).with_suffix('.json'))
        
        try:
            # Clean output for JSON (remove non-serializable items)
            json_output = self._prepare_json_output(output)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(json_output, f, indent=2, ensure_ascii=False)
            logger.info(f"Output saved to: {output_path}")
        except Exception as e:
            logger.error(f"Error saving output: {e}")
            raise
    
    def _prepare_json_output(self, output: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare output for JSON serialization and clean up duplicates/verbose data."""
        json_output = {}
        
        for key, value in output.items():
            if key == '_raw_output':
                # Keep raw output as string
                json_output[key] = str(value)
            elif key == 'collected_data' and isinstance(value, dict):
                # Clean up collected_data to remove duplicates and verbose CVSS data
                cleaned_data = self._clean_collected_data(value)
                # Intelligently organize and consolidate the data using LLM
                json_output[key] = self._intelligently_organize_output(cleaned_data, output.get('cve_id', ''))
            elif isinstance(value, (dict, list, str, int, float, bool, type(None))):
                json_output[key] = value
            elif isinstance(value, set):
                json_output[key] = list(value)
            else:
                # Convert other types to string
                json_output[key] = str(value)
        
        # Enhance top-level template fields using collected data
        if 'collected_data' in json_output and isinstance(json_output['collected_data'], dict):
            collected = json_output['collected_data']
            version_info = collected.get('version_information', {}) or collected.get('version_info', {})

            # Normalize version ranges: use vulnerable_version_ranges for clarity
            if version_info:
                if not version_info.get('vulnerable_version_ranges') and version_info.get('version_ranges'):
                    version_info['vulnerable_version_ranges'] = version_info.get('version_ranges', [])
                # Keep version_ranges only if they differ from vulnerable_version_ranges
                if version_info.get('version_ranges') == version_info.get('vulnerable_version_ranges'):
                    version_info.pop('version_ranges', None)
                collected['version_information'] = version_info

            def _normalize_list(items: Any) -> List[str]:
                normalized = []
                if not items:
                    return normalized
                for item in items:
                    if isinstance(item, dict):
                        range_val = item.get('range', '') or item.get('value', '')
                        if range_val:
                            normalized.append(str(range_val).strip())
                    else:
                        item_str = str(item).strip()
                        if item_str:
                            normalized.append(item_str)
                return normalized

            def _format_versions() -> Dict[str, str]:
                vuln_list = _normalize_list(version_info.get('vulnerable_versions', []))
                range_list = _normalize_list(version_info.get('vulnerable_version_ranges', []))
                if not range_list:
                    range_list = _normalize_list(version_info.get('version_ranges', []))
                fixed_list = _normalize_list(version_info.get('fixed_versions', []))

                vulnerable_str = ", ".join([*range_list, *vuln_list]) if (vuln_list or range_list) else "Unknown"
                fixed_str = ", ".join(fixed_list) if fixed_list else "Unknown"
                return {
                    'Vulnerable Versions': vulnerable_str,
                    'Fixed Versions': fixed_str
                }

            # Update AFFECTED VERSIONS to use collected data
            if 'AFFECTED VERSIONS' in json_output and isinstance(json_output['AFFECTED VERSIONS'], dict):
                affected = json_output['AFFECTED VERSIONS']
                formatted = _format_versions()
                affected['Vulnerable Versions'] = formatted['Vulnerable Versions']
                affected['Fixed Versions'] = formatted['Fixed Versions']
                affected.setdefault('Backported Fixes', 'Unknown')
                affected.setdefault('Unsupported but Affected Versions', 'Unknown')
            else:
                json_output['AFFECTED VERSIONS'] = {
                    **_format_versions(),
                    'Backported Fixes': 'Unknown',
                    'Unsupported but Affected Versions': 'Unknown'
                }

            # Fill missing CVE ID if needed
            if 'CVE BASIC INFORMATION' in json_output and isinstance(json_output['CVE BASIC INFORMATION'], dict):
                cve_section = json_output['CVE BASIC INFORMATION']
                if not cve_section.get('CVE ID'):
                    cve_section['CVE ID'] = collected.get('summary', {}).get('cve_id', '') or output.get('cve_id', '')

            # Add a priority section for OVAL automation
            priority_output = {
                'vulnerability_specifics': collected.get('vulnerability_specifics', {}),
                'summary': collected.get('summary', {}),
                'version_information': version_info,
                'data_sources': collected.get('data_sources', {}),
                'references': collected.get('references', {})
            }
            json_output = {'PRIORITY_OUTPUT': priority_output, **json_output}

        # Normalize placeholder strings in top-level template fields
        placeholder_fragments = [
            "e.g.", "not specified", "product/component", "the specific library",
            "not applicable", "implied", "no specific", "unknown", "use of", "goal:",
            "focus on actionable", "product category", "component / module"
        ]

        def _normalize_value(value: Any) -> Any:
            if value is None:
                return "Unknown"
            if isinstance(value, str):
                stripped = value.strip()
                if not stripped:
                    return "Unknown"
                lowered = stripped.lower()
                if any(fragment in lowered for fragment in placeholder_fragments):
                    return "Unknown"
            return value

        for section_key, section_value in list(json_output.items()):
            if isinstance(section_value, dict) and section_key in [
                'CVE BASIC INFORMATION', 'VENDOR & PRODUCT DETAILS', 'AFFECTED VERSIONS',
                'PLATFORM SCOPE', 'CPE IDENTIFIERS', 'MERGED OVAL XML LEARNINGS', 'CONFIDENCE LEVEL'
            ]:
                json_output[section_key] = {
                    k: _normalize_value(v) for k, v in section_value.items()
                }

        return json_output
    
    def _clean_collected_data(self, collected_data: Dict[str, Any]) -> Dict[str, Any]:
        """Clean up collected data: remove duplicates and verbose CVSS metrics."""
        cleaned = {}
        
        # Clean NVD data - remove verbose CVSS metrics, keep only essential info
        if 'nvd_data' in collected_data:
            nvd_data = collected_data['nvd_data'].copy()
            
            # Clean up metrics - keep only essential CVSS info
            if 'metrics' in nvd_data:
                metrics = nvd_data['metrics']
                cleaned_metrics = {}
                
                # Keep only essential CVSS v4.0 data
                if 'cvssMetricV40' in metrics and metrics['cvssMetricV40']:
                    cvss_v40 = metrics['cvssMetricV40'][0]
                    if 'cvssData' in cvss_v40:
                        cvss_data = cvss_v40['cvssData']
                        # Keep only essential fields
                        cleaned_metrics['cvss_v40'] = {
                            'baseScore': cvss_data.get('baseScore'),
                            'baseSeverity': cvss_data.get('baseSeverity'),
                            'vectorString': cvss_data.get('vectorString')
                        }
                
                # Keep CVSS v3 if present
                if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                    cvss_v31 = metrics['cvssMetricV31'][0]
                    if 'cvssData' in cvss_v31:
                        cvss_data = cvss_v31['cvssData']
                        cleaned_metrics['cvss_v31'] = {
                            'baseScore': cvss_data.get('baseScore'),
                            'baseSeverity': cvss_data.get('baseSeverity'),
                            'vectorString': cvss_data.get('vectorString')
                        }
                
                if cleaned_metrics:
                    nvd_data['metrics'] = cleaned_metrics
                else:
                    nvd_data.pop('metrics', None)
            
            # Keep only essential NVD fields
            essential_nvd_fields = [
                'id', 'published', 'lastModified', 'vulnStatus', 'descriptions',
                'metrics', 'weaknesses', 'references'
            ]
            cleaned_nvd = {k: v for k, v in nvd_data.items() if k in essential_nvd_fields}
            cleaned['nvd_data'] = cleaned_nvd
        
        # Clean vendor data - remove duplicates
        if 'vendor_data' in collected_data:
            vendor_data = collected_data['vendor_data']
            # Remove duplicates based on URL
            seen_urls = set()
            unique_vendor_data = []
            for item in vendor_data:
                url = item.get('url', '')
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    unique_vendor_data.append(item)
                elif not url:  # Keep items without URLs (might be search results)
                    unique_vendor_data.append(item)
            cleaned['vendor_data'] = unique_vendor_data
        
        # Remove duplicate enriched_sources if present (they contain duplicate NVD data)
        if 'enriched_sources' in collected_data:
            enriched = collected_data['enriched_sources']
            # Remove duplicate NVD entries
            seen_nvd_ids = set()
            unique_enriched = []
            for source in enriched:
                source_type = source.get('source', '')
                source_id = source.get('id') or source.get('data', {}).get('id', '')
                
                # Skip duplicate NVD entries
                if source_type == 'nvd' and source_id:
                    if source_id in seen_nvd_ids:
                        continue
                    seen_nvd_ids.add(source_id)
                
                unique_enriched.append(source)
            cleaned['enriched_sources'] = unique_enriched
        
        # Clean GitHub data - remove duplicate CVSS data
        if 'github_data' in collected_data:
            gh_data = collected_data['github_data'].copy()
            if isinstance(gh_data, dict) and 'data' in gh_data:
                gh_data_dict = gh_data['data'].copy()
                
                # Clean up CVSS data in GitHub - keep only essential
                if 'cvss_severities' in gh_data_dict:
                    cvss_sev = gh_data_dict['cvss_severities']
                    cleaned_cvss = {}
                    if 'cvss_v4' in cvss_sev and cvss_sev['cvss_v4'].get('score', 0) > 0:
                        cleaned_cvss['cvss_v4'] = {
                            'score': cvss_sev['cvss_v4'].get('score'),
                            'vector_string': cvss_sev['cvss_v4'].get('vector_string')
                        }
                    if 'cvss_v3' in cvss_sev and cvss_sev['cvss_v3'].get('score', 0) > 0:
                        cleaned_cvss['cvss_v3'] = {
                            'score': cvss_sev['cvss_v3'].get('score'),
                            'vector_string': cvss_sev['cvss_v3'].get('vector_string')
                        }
                    if cleaned_cvss:
                        gh_data_dict['cvss_severities'] = cleaned_cvss
                    else:
                        gh_data_dict.pop('cvss_severities', None)
                
                # Remove duplicate CVSS field if it's empty/null
                if 'cvss' in gh_data_dict and (not gh_data_dict['cvss'] or 
                    (isinstance(gh_data_dict['cvss'], dict) and 
                     not gh_data_dict['cvss'].get('score') and 
                     not gh_data_dict['cvss'].get('vector_string'))):
                    gh_data_dict.pop('cvss', None)
                
                # Remove empty/null fields that add no value
                fields_to_remove = ['repository_advisory_url', 'source_code_location', 'credits']
                for field in fields_to_remove:
                    if field in gh_data_dict and (not gh_data_dict[field] or 
                        (isinstance(gh_data_dict[field], list) and len(gh_data_dict[field]) == 0)):
                        gh_data_dict.pop(field, None)
                
                gh_data['data'] = gh_data_dict
            cleaned['github_data'] = gh_data
        
        # Copy other fields as-is
        for key, value in collected_data.items():
            if key not in ['nvd_data', 'vendor_data', 'github_data']:
                cleaned[key] = value
        
        return cleaned
    
    def _intelligently_organize_output(self, collected_data: Dict[str, Any], cve_id: str) -> Dict[str, Any]:
        """
        Use LLM to intelligently organize and consolidate collected data.
        Removes redundancy, clearly shows data sources, and keeps only useful information.
        """
        if not self.llm_assistant.available:
            # Fallback: Basic organization without LLM
            return self._basic_organize_output(collected_data)
        
        try:
            logger.info("Using LLM to intelligently organize output data...")
            
            # Prepare data summary for LLM
            data_summary = {
                'cve_id': cve_id,
                'nvd_data': collected_data.get('nvd_data', {}),
                'vendor_data': collected_data.get('vendor_data', []),
                'github_data': collected_data.get('github_data', {}),
                'version_info': collected_data.get('version_info', {}),
                'urls_from_nvd': collected_data.get('urls_from_nvd', [])
            }
            
            prompt = f"""Analyze and organize this CVE research data for {cve_id}. Create a clean, organized structure that:

1. **Removes redundancy** - Don't repeat the same information from multiple sources
2. **Clearly shows data sources** - For each piece of information, indicate which source(s) provided it
3. **Keeps only useful data** - Remove verbose, empty, or irrelevant fields
4. **Consolidates information** - Merge similar information from different sources intelligently
5. **Organizes by relevance** - Put the most important information first
6. **Extract vulnerability specifics** - Identify affected components, features, or specific parts
7. **Extract workarounds** - Identify any workarounds or mitigations mentioned

IMPORTANT: Extract specific vulnerability details like:
- Which component/feature/module is affected
- Specific functionality that's vulnerable
- Workarounds or mitigations available
- Configuration changes needed

Current data structure:
{json.dumps(data_summary, indent=2)[:3000]}  # Limit to avoid token limits

Create a clean JSON structure with these sections (PUT VULNERABILITY_SPECIFICS AT THE TOP):
{{
    "vulnerability_specifics": {{
        "affected_components": ["list of specific components/features affected"],
        "affected_functionality": "description of what functionality is vulnerable",
        "workarounds": ["list of workarounds or mitigations if available"],
        "configuration_changes": ["any configuration changes needed"],
        "notes": "any other specific details about the vulnerability"
    }},
    "summary": {{
        "cve_id": "{cve_id}",
        "vulnerability_type": "extract from descriptions",
        "severity": "from CVSS scores",
        "affected_product": "product name",
        "brief_description": "concise description (1-2 sentences)"
    }},
    "version_information": {{
        "vulnerable_versions": ["consolidated list - MUST include all vulnerable versions"],
        "vulnerable_version_ranges": ["version ranges like >= 3.0.0 < 3.88.0"],
        "fixed_versions": ["consolidated list - ONLY stable releases, NO beta/alpha"],
        "version_ranges": ["consolidated ranges"],
        "sources": ["which sources provided version info"]
    }},
    "data_sources": {{
        "nvd": {{
            "url": "NVD URL if available",
            "provided": ["list of what NVD provided"],
            "key_findings": {{"field": "value"}}
        }},
        "vendor_advisories": [
            {{
                "url": "vendor URL",
                "domain": "domain name",
                "provided": ["what this source provided"],
                "key_findings": {{"field": "value"}}
            }}
        ],
        "github": {{
            "url": "GitHub advisory URL",
            "provided": ["what GitHub provided"],
            "key_findings": {{"field": "value"}}
        }}
    }},
    "references": {{
        "primary": ["most important URLs"],
        "all": ["all unique URLs from all sources"]
    }},
    "metadata": {{
        "research_date": "date",
        "sources_checked": ["list of sources"],
        "data_quality": "high/medium/low"
    }}
}}

IMPORTANT RULES:
- vulnerable_versions MUST include ALL vulnerable versions mentioned
- fixed_versions MUST exclude beta/alpha/pre-release versions - only stable releases
- If 5.0.1-beta fixes it but 5.0.2 is stable, use 5.0.2 as fixed version
- vulnerability_specifics should be at the TOP of the structure
- Extract workarounds and affected components from all sources

Respond ONLY with valid JSON, no markdown formatting."""
            
            response = ollama.chat(
                model=self.llm_assistant.model,
                messages=[{'role': 'user', 'content': prompt}]
            )
            
            result_text = response['message']['content']
            
            # Extract JSON from response (might be wrapped in markdown)
            if '```json' in result_text:
                result_text = result_text.split('```json')[1].split('```')[0].strip()
            elif '```' in result_text:
                result_text = result_text.split('```')[1].split('```')[0].strip()
            
            organized_data = json.loads(result_text)
            
            # Merge with essential raw data (keep some raw data for reference)
            organized_data['_raw_data'] = {
                'nvd_raw': {
                    'id': collected_data.get('nvd_data', {}).get('id'),
                    'published': collected_data.get('nvd_data', {}).get('published'),
                    'vulnStatus': collected_data.get('nvd_data', {}).get('vulnStatus')
                },
                'vendor_count': len(collected_data.get('vendor_data', [])),
                'github_ghsa_id': collected_data.get('github_data', {}).get('data', {}).get('ghsa_id')
            }
            
            logger.info("LLM organization completed successfully")
            return organized_data
            
        except Exception as e:
            logger.warning(f"LLM organization failed: {e}, using basic organization")
            return self._basic_organize_output(collected_data)
    
    def _basic_organize_output(self, collected_data: Dict[str, Any]) -> Dict[str, Any]:
        """Basic organization without LLM - fallback method."""
        organized = {
            'vulnerability_specifics': {
                'affected_components': [],
                'affected_functionality': '',
                'workarounds': [],
                'configuration_changes': [],
                'notes': ''
            },
            'summary': {
                'cve_id': collected_data.get('nvd_data', {}).get('id', ''),
                'vulnerability_type': '',
                'severity': '',
                'affected_product': '',
                'brief_description': ''
            },
            'data_sources': {},
            'version_information': {},
            'references': {
                'primary': [],
                'all': []
            },
            'metadata': {}
        }
        
        # Extract vulnerability specifics from descriptions
        all_text = []
        nvd_data = collected_data.get('nvd_data', {})
        if nvd_data.get('descriptions'):
            all_text.append(nvd_data['descriptions'][0].get('value', ''))
        
        vendor_data = collected_data.get('vendor_data', [])
        for vendor in vendor_data:
            if vendor.get('content'):
                all_text.append(vendor['content'][:1000])  # Limit length
        
        github_data = collected_data.get('github_data', {})
        if github_data.get('data', {}).get('description'):
            all_text.append(github_data['data']['description'])
        
        # Enhanced extraction of workarounds and specifics
        import re
        combined_text = ' '.join(all_text)
        combined_lower = combined_text.lower()
        
        # Extract workarounds
        workaround_patterns = [
            r'workaround[:\s]+([^\.]+)',
            r'mitigation[:\s]+([^\.]+)',
            r'can be mitigated by[:\s]+([^\.]+)',
            r'temporary fix[:\s]+([^\.]+)'
        ]
        workarounds = []
        for pattern in workaround_patterns:
            matches = re.findall(pattern, combined_text, re.IGNORECASE)
            workarounds.extend([m.strip() for m in matches if m.strip()])
        if workarounds:
            organized['vulnerability_specifics']['workarounds'] = list(set(workarounds))[:5]  # Limit to 5
        elif 'workaround' in combined_lower or 'mitigation' in combined_lower:
            organized['vulnerability_specifics']['workarounds'] = ['Workaround or mitigation mentioned - see vendor advisory for details']
        
        # Extract affected components/functionality
        if 'sql' in combined_lower and 'injection' in combined_lower:
            organized['vulnerability_specifics']['affected_components'].append('SQL query processing')
            organized['vulnerability_specifics']['affected_functionality'] = 'SQL command execution'
        if 'http' in combined_lower or 'https' in combined_lower:
            organized['vulnerability_specifics']['affected_components'].append('HTTP/HTTPS request handling')
        if 'authenticated' in combined_lower or 'admin' in combined_lower:
            organized['vulnerability_specifics']['notes'] = 'Requires authenticated access'
        
        # Extract from description patterns
        desc = nvd_data.get('descriptions', [{}])[0].get('value', '') if nvd_data else ''
        if desc:
            # Extract what functionality is affected
            if 'via' in desc.lower():
                via_part = desc.lower().split('via')[1].split('.')[0].strip()
                if via_part:
                    organized['vulnerability_specifics']['affected_functionality'] = via_part[:100]
        
        # Extract basic info from NVD
        nvd_data = collected_data.get('nvd_data', {})
        if nvd_data:
            desc = nvd_data.get('descriptions', [{}])[0].get('value', '')
            organized['summary']['brief_description'] = desc[:200] + '...' if len(desc) > 200 else desc
            organized['summary']['vulnerability_type'] = nvd_data.get('weaknesses', [{}])[0].get('description', [{}])[0].get('value', '')
            
            metrics = nvd_data.get('metrics', {})
            if metrics.get('cvss_v40'):
                organized['summary']['severity'] = metrics['cvss_v40'].get('baseSeverity', '')
            elif metrics.get('cvss_v31'):
                organized['summary']['severity'] = metrics['cvss_v31'].get('baseSeverity', '')
            
            organized['data_sources']['nvd'] = {
                'url': f"https://nvd.nist.gov/vuln/detail/{nvd_data.get('id', '')}",
                'provided': ['CVE details', 'CVSS scores', 'CWE information'],
                'key_findings': {
                    'status': nvd_data.get('vulnStatus', ''),
                    'published': nvd_data.get('published', '')
                }
            }
        
        # Extract vendor data and consolidate version info
        vendor_data = collected_data.get('vendor_data', [])
        organized['data_sources']['vendor_advisories'] = []
        all_fixed_versions = set()
        all_vulnerable_versions = set()
        
        for vendor in vendor_data:
            fixed_vers = vendor.get('versions', {}).get('fixed', [])
            vuln_vers = vendor.get('versions', {}).get('vulnerable', [])
            all_fixed_versions.update(fixed_vers)
            all_vulnerable_versions.update(vuln_vers)
            
            organized['data_sources']['vendor_advisories'].append({
                'url': vendor.get('url', ''),
                'domain': vendor.get('domain', ''),
                'provided': ['Vendor advisory', 'Version information'],
                'key_findings': {
                    'fixed_versions': fixed_vers,
                    'vulnerable_versions': vuln_vers
                }
            })
        
        # Update version information with consolidated data
        from tools.version_tools import VersionTools
        
        version_info = collected_data.get('version_info', {})
        
        # Filter fixed versions - exclude beta/alpha/pre-release
        if all_fixed_versions:
            filtered_fixed = VersionTools.filter_stable_versions(list(all_fixed_versions), prefer_stable=True)
            version_info['fixed_versions'] = sorted(filtered_fixed)
        else:
            # Also filter existing fixed versions
            existing_fixed = version_info.get('fixed_versions', [])
            version_info['fixed_versions'] = sorted(VersionTools.filter_stable_versions(existing_fixed, prefer_stable=True))
        
        # Keep all vulnerable versions (including pre-releases for accuracy)
        if all_vulnerable_versions:
            version_info['vulnerable_versions'] = sorted(list(all_vulnerable_versions))
        
        # Ensure vulnerable versions are included
        if not version_info.get('vulnerable_versions'):
            # Try to extract from descriptions
            desc = nvd_data.get('descriptions', [{}])[0].get('value', '')
            # Look for version patterns in description
            import re
            version_matches = re.findall(r'(\d+\.\d+\.\d+(?:\.\d+)?)', desc)
            if version_matches:
                version_info['vulnerable_versions'] = sorted(list(set(version_matches)))
        
        organized['version_information'] = version_info
        
        # Extract GitHub data
        github_data = collected_data.get('github_data', {})
        if github_data and github_data.get('data'):
            gh_data = github_data['data']
            organized['data_sources']['github'] = {
                'url': gh_data.get('html_url', ''),
                'provided': ['GitHub Security Advisory', 'Additional references'],
                'key_findings': {
                    'ghsa_id': gh_data.get('ghsa_id', ''),
                    'severity': gh_data.get('severity', '')
                }
            }
        
        # Collect all references
        all_urls = set()
        if nvd_data.get('references'):
            for ref in nvd_data['references']:
                if isinstance(ref, dict):
                    all_urls.add(ref.get('url', ''))
                else:
                    all_urls.add(str(ref))
        
        for vendor in vendor_data:
            if vendor.get('url'):
                all_urls.add(vendor['url'])
        
        if github_data and github_data.get('data', {}).get('references'):
            for ref in github_data['data']['references']:
                all_urls.add(ref)
        
        organized['references']['all'] = sorted(list(all_urls))
        organized['references']['primary'] = [url for url in organized['references']['all'] 
                                             if any(x in url for x in ['vendor', 'advisory', 'security', 'psirt'])]
        
        organized['metadata'] = {
            'sources_checked': ['NVD', 'Vendor Advisories', 'GitHub'],
            'data_quality': 'medium'
        }
        
        return organized