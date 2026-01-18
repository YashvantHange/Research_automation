# Research Automation (OVAL XML Build)

A comprehensive research agent system for gathering CVE details to support **OVAL XML authoring/merging**. This system integrates:

- **Modern scrapers** for NVD, GitHub Security Advisories, and vendor advisories
- **Vendor URL database** extracted from merged OVAL XML files
- **Intelligent vendor site search** with fallback strategies
- **Local Ollama LLM** integration for structured output generation and error handling
- **OVAL XML learnings** extracted from merged XML files to ensure consistency

## Features

- 🔍 **Multi-source data collection**: NVD API v2, GitHub Security Advisories, vendor advisory scraping
- 🗄️ **Vendor URL database**: Caches vendor URLs from OVAL XML for faster lookups
- 🎯 **Prioritized research workflow**: Vendor advisories > GitHub > NVD (vendor sources take precedence)
- 🔎 **Intelligent vendor search**: Automatic vendor site search when URLs not found
- 🤖 **LLM-assisted intelligence**: Error handling, source prioritization, version extraction
- 📚 **OVAL XML learnings**: Deep pattern extraction from merged XML (version patterns, CPE patterns, best practices)
- 🛠️ **Research tools**: Version comparison, CPE validation, and normalization
- 📋 **Structured output**: Generates research data in the exact format needed for OVAL XML builds
- ✅ **Enhanced validation**: CVE ID, CPE, and version format validation using OVAL learnings
- 🔄 **Retry logic**: Exponential backoff for failed requests
- 💾 **Request caching**: 1-hour cache to avoid duplicate API calls
- 📊 **Comprehensive logging**: Detailed logging for debugging and monitoring

## Installation

### Quick Install (One Command):

**Ubuntu/Debian/Linux:**
```bash
bash install.sh
```

**Windows (PowerShell):**
```powershell
.\install.ps1
```

**Cross-platform (Python):**
```bash
python install.py
```

The installation script automatically:
- ✅ Checks and installs Python dependencies
- ✅ Installs Ollama (if not present)
- ✅ Starts Ollama service
- ✅ Pulls default model (llama3.2)
- ✅ Verifies installation

**See [INSTALL.md](INSTALL.md) for detailed instructions.**

### Manual Installation:

1. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Install and setup Ollama:**
   - **Linux**: `curl -fsSL https://ollama.com/install.sh | sh`
   - **Windows**: Download from https://ollama.com/download or `winget install Ollama.Ollama`
   - **macOS**: `brew install ollama` or download from https://ollama.com/download
   - Start service: `ollama serve`
   - Pull model: `ollama pull llama3.2`

3. **That's it!** No configuration needed - vendor database is created automatically on first run.

**Optional Configuration:**
   - Copy `config.example.yaml` to `config.yaml` for advanced settings
   - Add API keys for higher rate limits (NVD, GitHub)

**Verify Setup:**
```bash
python verify_installation.py  # Checks all components
```

## Example Usage

```bash
# Single CVE
python research.py CVE-2025-21556

# Multiple CVEs (combined JSON output)
python research.py CVE-2025-21556 CVE-2025-59922
```

## Quick Start - Single Command

The research agent now works with a **single command** that handles everything automatically:

### Windows (PowerShell)
```powershell
.\research.ps1 CVE-2025-5591
```

### Windows (Command Prompt)
```cmd
research.bat CVE-2025-5591
```

### Linux/Mac
```bash
./research.sh CVE-2025-5591
```

### Python (Cross-platform)
```bash
python research.py CVE-2025-5591
```

### What Happens Automatically

1. **Auto-initialization**: Checks if vendor database exists, extracts vendor URLs from OVAL XML if needed
2. **Research workflow**: 
   - Searches NVD for CVE data
   - Extracts vendor URLs from NVD references
   - Checks vendor database for known URLs
   - Prioritizes and scrapes vendor sources (highest priority)
   - Searches vendor sites if needed (fallback)
   - Searches GitHub Security Advisories
   - Uses LLM to prioritize sources
   - Generates structured output

### Examples

```bash
# Research a single CVE
python research.py CVE-2025-5591

# Research multiple CVEs
python research.py CVE-2025-5591 CVE-2025-5592 CVE-2025-5593

# With additional vendor URLs
python research.py CVE-2025-5591 --urls "https://vendor.com/advisory"

# Custom OVAL XML path
python research.py CVE-2025-5591 --oval-xml "path/to/OVAL_WINDOWS.xml"

# Different Ollama model
python research.py CVE-2025-5591 --ollama-model llama3.1

# With API keys for higher rate limits
python research.py CVE-2025-5591 --nvd-api-key "your-key" --github-token "your-token"
```

### With Additional Vendor URLs

```bash
python research_agent.py CVE-2025-5591 --urls "https://vendor.com/advisory" "https://github.com/repo/security/advisories/GHSA-xxx"
```

### Custom Configuration

```bash
python research_agent.py CVE-2025-5591 \
  --oval-xml "path/to/OVAL_WINDOWS.xml" \
  --ollama-model "llama3.1" \
  --nvd-api-key "your-nvd-key" \
  --output "outputs/my_research.md"
```

### Python API

```python
from research_agent import ResearchAgent

# Initialize agent
agent = ResearchAgent(
    oval_xml_path="C:\\Users\\Yashvant\\OneDrive\\Documents\\OVAL_WINDOWS.xml",
    ollama_model="llama3.2",
    nvd_api_key="your-key",  # optional
    github_token="your-token"  # optional
)

# Research a CVE
output = agent.research_cve(
    cve_id="CVE-2025-5591",
    additional_urls=["https://vendor.com/advisory"]
)

# Save output
agent.save_output(output, "outputs/CVE-2025-5591.md")
```

## Project Structure

```
Research_automation/
├── research.py                # 🚀 SINGLE COMMAND ENTRY POINT (use this!)
├── research.ps1               # PowerShell wrapper (Windows)
├── research.bat               # Batch file wrapper (Windows)
├── research.sh                # Bash wrapper (Linux/Mac)
├── research_agent.py          # Enhanced main research agent
├── oval_parser.py             # OVAL XML parser (learnings + vendor URLs)
├── vendor_database.py         # Vendor URL database system
├── llm_assistant.py           # LLM assistant for intelligence
├── extract_vendor_urls.py     # Script to extract vendor URLs (auto-run by research.py)
├── scrapers/
│   ├── __init__.py
│   ├── nvd_scraper.py         # NVD API v2 scraper
│   ├── github_scraper.py      # GitHub Security Advisories scraper
│   ├── vendor_scraper.py      # Generic vendor advisory scraper
│   └── vendor_search.py       # Intelligent vendor site search
├── tools/
│   ├── __init__.py
│   ├── version_tools.py        # Version comparison & parsing
│   └── cpe_validator.py       # CPE validation & normalization
├── prompts/
│   └── oval_xml_research_agent.md  # LLM prompt template
├── templates/
│   └── oval_xml_research_output.md # Output template
├── data/
│   └── vendor_db.json         # Vendor URL database (auto-generated)
├── outputs/                   # Generated research outputs
├── requirements.txt
├── config.example.yaml
├── WORKFLOW.md                # Detailed workflow documentation
└── README.md
```

## Components

### Research Workflow

See [WORKFLOW.md](WORKFLOW.md) for detailed workflow documentation.

**Priority Order:**
1. **Vendor Advisories** (Priority 1) - Direct vendor pages, highest reliability
2. **GitHub Security Advisories** (Priority 2) - Official GHSA entries
3. **NVD** (Priority 3) - Used for enrichment, not relied upon alone
4. **Vendor Site Search** (Priority 2) - Intelligent fallback search

### Scrapers

#### NVD Scraper (`scrapers/nvd_scraper.py`)
- Uses official NVD API v2
- Rate-limit aware (0.6s between requests)
- Extracts CPEs, version ranges, CVSS scores, references
- Extracts vendor URLs from references
- Optional API key for higher rate limits

#### GitHub Scraper (`scrapers/github_scraper.py`)
- GitHub Security Advisories API
- Extracts version information, severity, CVSS
- Can search by CVE ID or GHSA ID
- Optional token for higher rate limits

#### Vendor Scraper (`scrapers/vendor_scraper.py`)
- Generic web scraper for vendor advisories
- Extracts version information from text
- Handles various advisory formats

#### Vendor Site Searcher (`scrapers/vendor_search.py`)
- Intelligent vendor site search
- Tries direct URL patterns
- Uses site-specific search endpoints
- Falls back to generic search
- Confidence-based scoring

### Vendor Database (`vendor_database.py`)
- Caches vendor URLs from OVAL XML
- Product → Vendor URL mappings
- Domain → Product mappings
- CVE → Vendor URL mappings
- Fast lookups for known CVEs

### LLM Assistant (`llm_assistant.py`)
- **Error Handling**: Suggests retry strategies
- **Source Prioritization**: Ranks sources by reliability
- **Version Extraction**: Extracts version info from unstructured text
- **CPE Validation**: Validates and suggests corrections
- **Search Strategies**: Suggests URL patterns

### Research Tools (`tools/`)
- **Version Tools**: Version comparison, range parsing, extraction
- **CPE Validator**: CPE format validation and normalization

## OVAL XML Learnings

The system extracts learnings from your merged OVAL XML file:

- **CPE patterns**: Common CPE formats used in your OVAL definitions
- **Version patterns**: Version check formats and conventions
- **Product naming**: Normalization rules and naming variants
- **Required fields**: Fields consistently present in accepted definitions
- **Version mistakes**: Common mistakes to avoid (off-by-one, format inconsistencies)

## Output Format

The agent generates structured output matching `templates/oval_xml_research_output.md`:

- CVE Basic Information
- Vendor & Product Details
- Affected Versions
- Platform Scope
- CPE Identifiers
- Merged OVAL XML Learnings
- Confidence Level

## Requirements

- Python 3.8+
- Ollama installed and running
- Internet connection (for scrapers)
- Access to OVAL XML file (for learnings)

## Troubleshooting

### Ollama Connection Error
- Ensure Ollama is running: `ollama serve`
- Check model is available: `ollama list`
- Pull model if needed: `ollama pull llama3.2`

### NVD Rate Limiting
- Get API key from https://nvd.nist.gov/developers/request-an-api-key
- Pass with `--nvd-api-key` or set in config

### OVAL XML Too Large
- The parser uses iterparse for large files
- If issues persist, consider splitting the XML file

## License

MIT