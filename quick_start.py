"""Quick start script to verify the research agent setup."""

import sys
from pathlib import Path

def check_setup():
    """Check if all required components are set up."""
    print("Checking Research Agent Setup...")
    print("=" * 60)
    
    issues = []
    
    # Check Python version
    print(f"✓ Python version: {sys.version}")
    
    # Check required packages
    print("\nChecking required packages...")
    required_packages = {
        'requests': 'requests',
        'beautifulsoup4': 'bs4',
        'lxml': 'lxml',
        'ollama': 'ollama'
    }
    
    for package_name, import_name in required_packages.items():
        try:
            __import__(import_name)
            print(f"  ✓ {package_name}")
        except ImportError:
            print(f"  ✗ {package_name} - NOT INSTALLED")
            issues.append(f"Install {package_name} with: pip install {package_name}")
    
    # Check OVAL XML file
    print("\nChecking OVAL XML file...")
    oval_path = Path(r"C:\Users\Yashvant\OneDrive\Documents\OVAL_WINDOWS.xml")
    if oval_path.exists():
        size_mb = oval_path.stat().st_size / (1024 * 1024)
        print(f"  ✓ OVAL XML found: {oval_path}")
        print(f"    Size: {size_mb:.2f} MB")
    else:
        print(f"  ✗ OVAL XML not found: {oval_path}")
        issues.append(f"Update oval_xml_path in research_agent.py or provide correct path")
    
    # Check Ollama connection
    print("\nChecking Ollama connection...")
    try:
        import ollama
        models = ollama.list()
        if models and 'models' in models:
            print(f"  ✓ Ollama is running")
            print(f"    Available models: {', '.join([m['name'] for m in models['models']])}")
        else:
            print(f"  ⚠ Ollama is running but no models found")
            issues.append("Pull a model with: ollama pull llama3.2")
    except Exception as e:
        print(f"  ✗ Cannot connect to Ollama: {e}")
        issues.append("Start Ollama with: ollama serve")
    
    # Check project structure
    print("\nChecking project structure...")
    required_files = [
        'research_agent.py',
        'oval_parser.py',
        'scrapers/__init__.py',
        'scrapers/nvd_scraper.py',
        'scrapers/github_scraper.py',
        'scrapers/vendor_scraper.py',
        'prompts/oval_xml_research_agent.md',
        'templates/oval_xml_research_output.md'
    ]
    
    for file_path in required_files:
        if Path(file_path).exists():
            print(f"  ✓ {file_path}")
        else:
            print(f"  ✗ {file_path} - MISSING")
            issues.append(f"Missing file: {file_path}")
    
    # Summary
    print("\n" + "=" * 60)
    if issues:
        print("SETUP INCOMPLETE - Issues found:")
        for issue in issues:
            print(f"  • {issue}")
        print("\nFix the issues above and run again.")
        return False
    else:
        print("✓ All checks passed! Setup is complete.")
        print("\nYou can now use the research agent:")
        print("  python research_agent.py CVE-2025-5591")
        return True

if __name__ == '__main__':
    success = check_setup()
    sys.exit(0 if success else 1)
