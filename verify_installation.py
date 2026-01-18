#!/usr/bin/env python3
"""
Comprehensive verification script for Research Automation System
Checks all components, dependencies, and configuration
"""

import sys
import json
from pathlib import Path

def check_python():
    """Check Python version."""
    print("[1/8] Checking Python...")
    version = sys.version_info
    if version.major >= 3 and version.minor >= 8:
        print(f"  [OK] Python {version.major}.{version.minor}.{version.micro}")
        return True
    else:
        print(f"  [ERROR] Python 3.8+ required, found {version.major}.{version.minor}")
        return False

def check_packages():
    """Check required Python packages."""
    print("\n[2/8] Checking Python packages...")
    packages = {
        'requests': 'requests',
        'beautifulsoup4': 'bs4',
        'lxml': 'lxml',
        'ollama': 'ollama',
        'packaging': 'packaging'
    }
    
    missing = []
    for package_name, import_name in packages.items():
        try:
            __import__(import_name)
            print(f"  [OK] {package_name}")
        except ImportError:
            print(f"  [ERROR] {package_name} - NOT INSTALLED")
            missing.append(package_name)
    
    return len(missing) == 0

def check_core_modules():
    """Check core Python modules."""
    print("\n[3/8] Checking core modules...")
    modules = [
        'research_agent_enhanced',
        'llm_assistant',
        'version_extractor',
        'oval_parser',
        'vendor_database',
        'scrapers.nvd_scraper',
        'scrapers.github_scraper',
        'scrapers.vendor_scraper',
        'tools.version_tools',
        'tools.cpe_validator'
    ]
    
    missing = []
    for module in modules:
        try:
            __import__(module)
            print(f"  [OK] {module}")
        except ImportError as e:
            print(f"  [ERROR] {module} - {e}")
            missing.append(module)
    
    return len(missing) == 0

def check_ollama():
    """Check Ollama installation and service."""
    print("\n[4/8] Checking Ollama...")
    try:
        import ollama
        print("  [OK] Ollama Python package")
        
        # Check service
        try:
            models = ollama.list()
            print("  [OK] Ollama service is running")
            
            model_list = models.get('models', [])
            if model_list:
                print(f"  [OK] Found {len(model_list)} model(s)")
                for model in model_list[:3]:
                    name = str(model).split("'")[1] if "'" in str(model) else str(model)
                    print(f"    - {name}")
            else:
                print("  [WARNING] No models found. Run: ollama pull llama3.2")
            
            return True
        except Exception as e:
            print(f"  [ERROR] Ollama service not accessible: {e}")
            print("  [INFO] Start Ollama: ollama serve")
            return False
    except ImportError:
        print("  [ERROR] Ollama Python package not installed")
        return False

def check_files():
    """Check required files exist."""
    print("\n[5/8] Checking required files...")
    required_files = [
        'research.py',
        'research_agent_enhanced.py',
        'llm_assistant.py',
        'version_extractor.py',
        'oval_parser.py',
        'vendor_database.py',
        'requirements.txt',
        'scrapers/nvd_scraper.py',
        'scrapers/github_scraper.py',
        'scrapers/vendor_scraper.py',
        'tools/version_tools.py',
        'tools/cpe_validator.py'
    ]
    
    missing = []
    for file_path in required_files:
        if Path(file_path).exists():
            print(f"  [OK] {file_path}")
        else:
            print(f"  [ERROR] {file_path} - NOT FOUND")
            missing.append(file_path)
    
    return len(missing) == 0

def check_directories():
    """Check required directories."""
    print("\n[6/8] Checking directories...")
    directories = ['outputs', 'data', 'scrapers', 'tools', 'prompts', 'templates']
    
    missing = []
    for dir_path in directories:
        if Path(dir_path).exists():
            print(f"  [OK] {dir_path}/")
        else:
            print(f"  [WARNING] {dir_path}/ - Creating...")
            Path(dir_path).mkdir(parents=True, exist_ok=True)
            print(f"  [OK] {dir_path}/ created")
    
    return True

def check_oval_xml():
    """Check OVAL XML file (optional)."""
    print("\n[7/8] Checking OVAL XML file...")
    default_paths = [
        r'C:\Users\Yashvant\OneDrive\Documents\OVAL_WINDOWS.xml',
        'OVAL_WINDOWS.xml',
        '../OVAL_WINDOWS.xml'
    ]
    
    found = False
    for path in default_paths:
        if Path(path).exists():
            size_mb = Path(path).stat().st_size / (1024 * 1024)
            print(f"  [OK] Found: {path} ({size_mb:.2f} MB)")
            found = True
            break
    
    if not found:
        print("  [WARNING] OVAL XML file not found in default locations")
        print("  [INFO] You can specify path with: --oval-xml /path/to/file.xml")
    
    return True  # Not critical

def check_vendor_db():
    """Check vendor database."""
    print("\n[8/8] Checking vendor database...")
    db_path = Path('data/vendor_db.json')
    
    if db_path.exists():
        try:
            with open(db_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            count = len(data) if isinstance(data, dict) else 0
            print(f"  [OK] Vendor database found ({count} entries)")
        except:
            print(f"  [WARNING] Vendor database exists but may be corrupted")
    else:
        print("  [INFO] Vendor database not found (will be created on first run)")
    
    return True  # Not critical

def main():
    """Run all checks."""
    print("=" * 60)
    print("Research Automation System - Verification")
    print("=" * 60)
    print()
    
    results = {
        'python': check_python(),
        'packages': check_packages(),
        'modules': check_core_modules(),
        'ollama': check_ollama(),
        'files': check_files(),
        'directories': check_directories(),
        'oval_xml': check_oval_xml(),
        'vendor_db': check_vendor_db()
    }
    
    print("\n" + "=" * 60)
    print("Verification Summary")
    print("=" * 60)
    
    critical = ['python', 'packages', 'modules', 'files']
    critical_ok = all(results[k] for k in critical)
    
    if critical_ok and results['ollama']:
        print("\n[OK] All critical components are OK!")
        print("[OK] Ollama is working")
        print("\nSystem is ready to use!")
    elif critical_ok:
        print("\n[OK] All critical components are OK!")
        print("[WARNING] Ollama is not working (LLM features disabled)")
        print("\nSystem will work with basic features.")
        print("To enable LLM features: ollama serve")
    else:
        print("\n[ERROR] Some critical components are missing!")
        print("\nPlease fix the errors above and run again.")
        sys.exit(1)
    
    print("\n" + "=" * 60)

if __name__ == "__main__":
    main()
