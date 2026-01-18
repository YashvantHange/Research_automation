"""LLM assistant for error handling and intelligent decision making."""

from typing import Dict, List, Optional, Any
import json

try:
    import ollama
except ImportError:
    ollama = None


class LLMAssistant:
    """LLM assistant for intelligent error handling and research decisions."""
    
    def __init__(self, model: str = "llama3.2"):
        """
        Initialize LLM assistant.
        
        Args:
            model: Ollama model name
        """
        self.model = model
        self.available = ollama is not None
    
    def handle_scraping_error(self, error: Exception, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Use LLM to suggest error handling strategies.
        
        Args:
            error: The exception that occurred
            context: Context about what was being scraped
            
        Returns:
            Dictionary with suggestions
        """
        if not self.available:
            return {'suggestion': 'Retry with exponential backoff', 'confidence': 'low'}
        
        prompt = f"""A scraping error occurred:
Error: {str(error)}
Context: {json.dumps(context, indent=2)}

Suggest the best error handling strategy:
1. Should we retry? (yes/no and why)
2. Alternative approaches?
3. Is this a rate limit issue?
4. Should we try a different URL pattern?

Respond in JSON format:
{{
    "retry": true/false,
    "retry_reason": "explanation",
    "alternative_approaches": ["approach1", "approach2"],
    "is_rate_limit": true/false,
    "suggested_url_patterns": ["pattern1", "pattern2"]
}}"""
        
        try:
            response = ollama.chat(
                model=self.model,
                messages=[{'role': 'user', 'content': prompt}]
            )
            suggestion_text = response['message']['content']
            # Try to extract JSON
            try:
                return json.loads(suggestion_text)
            except:
                return {'suggestion': suggestion_text, 'confidence': 'medium'}
        except Exception as e:
            return {'suggestion': 'Retry with exponential backoff', 'error': str(e)}
    
    def prioritize_sources(self, sources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Use LLM to prioritize data sources based on reliability.
        
        Args:
            sources: List of source dictionaries with metadata
            
        Returns:
            Prioritized list of sources
        """
        if not self.available or not sources:
            return sources
        
        prompt = f"""Prioritize these vulnerability data sources by reliability and completeness:

Sources:
{json.dumps(sources, indent=2)}

For each source, consider:
1. Source type (vendor advisory > GitHub > NVD > other)
2. Completeness of version information
3. Recency of information
4. Official status

Respond with prioritized list in JSON:
{{
    "prioritized": [
        {{"index": 0, "reason": "explanation"}},
        {{"index": 1, "reason": "explanation"}}
    ]
}}"""
        
        try:
            response = ollama.chat(
                model=self.model,
                messages=[{'role': 'user', 'content': prompt}]
            )
            result_text = response['message']['content']
            try:
                result = json.loads(result_text)
                prioritized_indices = [item['index'] for item in result.get('prioritized', [])]
                return [sources[i] for i in prioritized_indices if i < len(sources)]
            except:
                return sources
        except:
            return sources
    
    def extract_version_info(self, text: str, cve_id: str) -> Dict[str, Any]:
        """
        Use LLM to extract version information from unstructured text.
        
        Args:
            text: Text content to analyze
            cve_id: CVE identifier for context
            
        Returns:
            Dictionary with extracted version information
        """
        if not self.available:
            return {}
        
        # Limit text length
        text = text[:3000]
        
        prompt = f"""Extract version information from this security advisory text for {cve_id}:

Text:
{text}

Extract:
1. Vulnerable version ranges (e.g., "< 2.4.59", "1.2.0 to 1.2.8")
2. Fixed versions (e.g., "2.4.59", "1.2.9")
3. Backported fixes (if mentioned)
4. Unsupported but affected versions

Respond in JSON:
{{
    "vulnerable_versions": ["range1", "range2"],
    "fixed_versions": ["version1", "version2"],
    "backported_fixes": ["fix1"],
    "unsupported_versions": ["version1"],
    "confidence": "high/medium/low"
}}"""
        
        try:
            response = ollama.chat(
                model=self.model,
                messages=[{'role': 'user', 'content': prompt}]
            )
            result_text = response['message']['content']
            try:
                return json.loads(result_text)
            except:
                return {}
        except:
            return {}
    
    def interpret_version_wording(self, text: str, cve_id: str) -> Dict[str, Any]:
        """
        Use LLM to interpret natural language version descriptions and convert to proper version ranges.
        
        Examples:
        - "versions 3.0.0 and later" + "workaround in 3.88.0" -> ">= 3.0.0 < 3.88.0"
        - "all versions before 2.4.59" -> "< 2.4.59"
        - "versions 1.2.0 through 1.2.8" -> ">= 1.2.0 <= 1.2.8"
        
        Args:
            text: Text content containing version descriptions
            cve_id: CVE identifier for context
            
        Returns:
            Dictionary with interpreted version ranges in standard format
        """
        if not self.available:
            return {}
        
        # Limit text length but keep more context for interpretation
        text = text[:5000]
        
        prompt = f"""Interpret version information from this security advisory text for {cve_id} and convert to standard version range format.

Text:
{text}

Convert natural language version descriptions to standard version ranges:
- Use ">=" for "and later", "and above", "starting from", "from version X"
- Use "<" for "before", "prior to", "up to (but not including)", "less than"
- Use "<=" for "through", "up to and including", "and earlier"
- Use ">" for "after", "newer than"
- Combine ranges when multiple conditions exist (e.g., ">= 3.0.0 < 3.88.0" means "3.0.0 and later, but less than 3.88.0")

Examples:
- "versions 3.0.0 and later" -> ">= 3.0.0"
- "versions 3.0.0 and later" + "workaround available starting in version 3.88.0" -> ">= 3.0.0 < 3.88.0" (if workaround doesn't fully fix)
- "all versions before 2.4.59" -> "< 2.4.59"
- "versions 1.2.0 through 1.2.8" -> ">= 1.2.0 <= 1.2.8"
- "fixed in version 2.4.59" -> vulnerable: "< 2.4.59", fixed: ">= 2.4.59"

Respond in JSON:
{{
    "vulnerable_ranges": [
        {{
            "range": ">= 3.0.0 < 3.88.0",
            "description": "versions 3.0.0 and later, but workaround only available from 3.88.0",
            "confidence": "high/medium/low"
        }}
    ],
    "fixed_versions": ["3.88.0"],
    "fixed_ranges": [">= 3.88.0"],
    "workaround_versions": ["3.88.0"],
    "notes": "Workaround available but product remains vulnerable by default",
    "confidence": "high/medium/low"
}}"""
        
        try:
            response = ollama.chat(
                model=self.model,
                messages=[{'role': 'user', 'content': prompt}]
            )
            result_text = response['message']['content']
            try:
                # Try to extract JSON from response (might be wrapped in markdown)
                if '```json' in result_text:
                    result_text = result_text.split('```json')[1].split('```')[0].strip()
                elif '```' in result_text:
                    result_text = result_text.split('```')[1].split('```')[0].strip()
                
                result = json.loads(result_text)
                return result
            except json.JSONDecodeError as e:
                # If JSON parsing fails, try to extract key information
                return {
                    'vulnerable_ranges': [],
                    'fixed_versions': [],
                    'fixed_ranges': [],
                    'workaround_versions': [],
                    'notes': f"LLM response parsing failed: {str(e)}",
                    'confidence': 'low',
                    'raw_response': result_text[:500]
                }
        except Exception as e:
            return {
                'vulnerable_ranges': [],
                'fixed_versions': [],
                'fixed_ranges': [],
                'workaround_versions': [],
                'notes': f"LLM call failed: {str(e)}",
                'confidence': 'low'
            }
    
    def validate_cpe(self, cpe: str, product_name: str) -> Dict[str, Any]:
        """
        Use LLM to validate CPE format and suggest corrections.
        
        Args:
            cpe: CPE string to validate
            product_name: Product name for context
            
        Returns:
            Validation result with suggestions
        """
        if not self.available:
            return {'valid': True}
        
        prompt = f"""Validate this CPE identifier for product "{product_name}":

CPE: {cpe}

Check:
1. Is the format correct? (cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other)
2. Are vendor and product names normalized correctly?
3. Suggest corrections if needed

Respond in JSON:
{{
    "valid": true/false,
    "issues": ["issue1", "issue2"],
    "suggested_cpe": "corrected_cpe",
    "confidence": "high/medium/low"
}}"""
        
        try:
            response = ollama.chat(
                model=self.model,
                messages=[{'role': 'user', 'content': prompt}]
            )
            result_text = response['message']['content']
            try:
                return json.loads(result_text)
            except:
                return {'valid': True}
        except:
            return {'valid': True}
    
    def suggest_search_strategies(self, domain: str, cve_id: str, product: Optional[str] = None) -> List[str]:
        """
        Use LLM to suggest search strategies for vendor sites.
        
        Args:
            domain: Vendor domain
            cve_id: CVE identifier
            product: Optional product name
            
        Returns:
            List of suggested URL patterns or search strategies
        """
        if not self.available:
            return []
        
        prompt = f"""Suggest search strategies for finding CVE {cve_id} information on {domain} for product "{product or 'unknown'}".

Consider:
1. Common security advisory URL patterns
2. Site-specific search endpoints
3. Product-specific paths

Respond with JSON array of suggested URL patterns:
{{
    "strategies": [
        "https://{domain}/security/{cve_id}",
        "https://{domain}/advisories/{cve_id}"
    ]
}}"""
        
        try:
            response = ollama.chat(
                model=self.model,
                messages=[{'role': 'user', 'content': prompt}]
            )
            result_text = response['message']['content']
            try:
                result = json.loads(result_text)
                return result.get('strategies', [])
            except:
                return []
        except:
            return []
