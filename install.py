#!/usr/bin/env python3
"""
Cross-platform installation script for Research Automation System
Works on Windows, Linux (Ubuntu/Debian), and macOS
"""

import sys
import subprocess
import platform
import os
from pathlib import Path

def run_command(cmd, check=True, shell=False):
    """Run a command and return success status."""
    try:
        if isinstance(cmd, str):
            cmd = cmd.split()
        result = subprocess.run(cmd, check=check, shell=shell, 
                              capture_output=True, text=True)
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return False, e.stdout, e.stderr
    except FileNotFoundError:
        return False, "", "Command not found"

def check_python():
    """Check if Python is installed."""
    print("[1/6] Checking Python installation...")
    python_cmd = None
    
    # Try python3 first
    success, _, _ = run_command([sys.executable, "--version"], check=False)
    if success:
        python_cmd = sys.executable
        version_output = subprocess.run([sys.executable, "--version"], 
                                       capture_output=True, text=True).stdout
        print(f"  [OK] Python found: {version_output.strip()}")
        return python_cmd
    
    print("  [ERROR] Python not found. Please install Python 3.8+ first.")
    sys.exit(1)

def check_pip(python_cmd):
    """Check if pip is available."""
    print("\n[2/6] Checking pip...")
    success, _, _ = run_command([python_cmd, "-m", "pip", "--version"], check=False)
    if success:
        print("  [OK] pip is available")
        return True
    
    print("  [ERROR] pip not found. Installing pip...")
    os_type = platform.system().lower()
    
    if os_type == "linux":
        run_command(["sudo", "apt-get", "update"], check=False)
        run_command(["sudo", "apt-get", "install", "-y", "python3-pip"], check=False)
    elif os_type == "darwin":
        # macOS - try to install via get-pip.py
        import urllib.request
        urllib.request.urlretrieve("https://bootstrap.pypa.io/get-pip.py", "get-pip.py")
        run_command([python_cmd, "get-pip.py"], check=False)
        os.remove("get-pip.py")
    
    return True

def install_python_deps(python_cmd):
    """Install Python dependencies."""
    print("\n[3/6] Installing Python dependencies...")
    
    # Upgrade pip
    run_command([python_cmd, "-m", "pip", "install", "--upgrade", "pip"], check=False)
    
    # Install requirements
    if Path("requirements.txt").exists():
        success, _, _ = run_command([python_cmd, "-m", "pip", "install", "-r", "requirements.txt"])
        if success:
            print("  [OK] Python dependencies installed")
        else:
            print("  [WARNING] Some dependencies may have failed to install")
    else:
        print("  [WARNING] requirements.txt not found. Installing manually...")
        packages = ["requests>=2.31.0", "beautifulsoup4>=4.12.0", 
                   "lxml>=4.9.0", "ollama>=0.1.0", "packaging>=23.0"]
        for package in packages:
            run_command([python_cmd, "-m", "pip", "install", package], check=False)

def install_ollama():
    """Install Ollama if not present."""
    print("\n[4/6] Checking Ollama installation...")
    os_type = platform.system().lower()
    
    # Check if Ollama is already installed
    success, _, _ = run_command(["ollama", "--version"], check=False)
    if success:
        print("  [OK] Ollama is installed")
        return True
    
    print("  [INFO] Ollama not found. Installing Ollama...")
    
    if os_type == "linux":
        print("  [INFO] Installing Ollama for Linux...")
        run_command("curl -fsSL https://ollama.com/install.sh | sh", shell=True, check=False)
    elif os_type == "darwin":
        # macOS
        success, _, _ = run_command(["brew", "--version"], check=False)
        if success:
            print("  [INFO] Installing via Homebrew...")
            run_command(["brew", "install", "ollama"], check=False)
        else:
            print("  [WARNING] Homebrew not found. Please install Ollama manually:")
            print("    Download from: https://ollama.com/download")
    elif os_type == "windows":
        # Windows
        success, _, _ = run_command(["winget", "--version"], check=False)
        if success:
            print("  [INFO] Installing via winget...")
            run_command(["winget", "install", "Ollama.Ollama", 
                        "--accept-package-agreements", "--accept-source-agreements"], check=False)
        else:
            success, _, _ = run_command(["choco", "--version"], check=False)
            if success:
                print("  [INFO] Installing via Chocolatey...")
                run_command(["choco", "install", "ollama", "-y"], check=False)
            else:
                print("  [WARNING] Please install Ollama manually:")
                print("    Download from: https://ollama.com/download")
    
    return False

def start_ollama():
    """Start Ollama service."""
    print("\n[5/6] Starting Ollama service...")
    os_type = platform.system().lower()
    
    # Check if Ollama is already running
    try:
        import requests
        response = requests.get("http://localhost:11434/api/tags", timeout=2)
        if response.status_code == 200:
            print("  [OK] Ollama service is already running")
            return True
    except:
        pass
    
    if os_type == "linux":
        # Try systemd
        success, _, _ = run_command(["systemctl", "is-active", "ollama"], check=False)
        if success:
            print("  [OK] Ollama service is running")
            return True
        else:
            print("  [INFO] Starting Ollama service...")
            run_command(["sudo", "systemctl", "start", "ollama"], check=False)
            # Fallback: start in background
            run_command(["ollama", "serve"], check=False)
    elif os_type == "darwin":
        # macOS
        print("  [INFO] Starting Ollama...")
        run_command(["ollama", "serve"], check=False)
    else:
        # Windows
        print("  [INFO] Please start Ollama manually:")
        print("    - Run 'ollama serve' in a terminal")
        print("    - Or start Ollama from Start Menu")
        print("  [INFO] Attempting to start Ollama...")
        run_command(["ollama", "serve"], check=False)
    
    # Wait a bit for service to start
    import time
    time.sleep(3)
    
    # Verify
    try:
        import requests
        response = requests.get("http://localhost:11434/api/tags", timeout=2)
        if response.status_code == 200:
            print("  [OK] Ollama service started successfully")
            return True
    except:
        print("  [WARNING] Ollama may not be running. Please start it manually.")
    
    return False

def setup_ollama_model(python_cmd):
    """Setup Ollama model."""
    print("\n[6/6] Setting up Ollama model...")
    if Path("check_ollama.py").exists():
        run_command([python_cmd, "check_ollama.py", "--setup"], check=False)
    else:
        print("  [WARNING] check_ollama.py not found")

def verify_installation(python_cmd):
    """Verify installation."""
    print("\n" + "=" * 60)
    print("Verifying Installation")
    print("=" * 60)
    print()
    
    # Check Python packages
    print("Checking Python packages...")
    packages = {
        "requests": "requests",
        "beautifulsoup4": "bs4",
        "lxml": "lxml",
        "ollama": "ollama",
        "packaging": "packaging"
    }
    
    missing = []
    for package_name, import_name in packages.items():
        success, _, _ = run_command([python_cmd, "-c", f"import {import_name}"], check=False)
        if success:
            print(f"  [OK] {package_name}")
        else:
            print(f"  [ERROR] {package_name} - NOT INSTALLED")
            missing.append(package_name)
    
    # Check Ollama connection
    print("\nChecking Ollama connection...")
    try:
        import ollama
        models = ollama.list()
        print("  [OK] Ollama is accessible")
        if models.get('models'):
            print(f"  [OK] Found {len(models['models'])} model(s)")
    except Exception as e:
        print(f"  [WARNING] Ollama not accessible: {e}")
        print("  [INFO] Make sure Ollama is running: ollama serve")
    
    return missing

def main():
    """Main installation function."""
    print("=" * 60)
    print("Research Automation System - Installation Script")
    print("=" * 60)
    print()
    
    os_type = platform.system()
    print(f"[INFO] Detected OS: {os_type}")
    print()
    
    # Step 1: Check Python
    python_cmd = check_python()
    
    # Step 2: Check pip
    check_pip(python_cmd)
    
    # Step 3: Install Python dependencies
    install_python_deps(python_cmd)
    
    # Step 4: Install Ollama
    install_ollama()
    
    # Step 5: Start Ollama
    start_ollama()
    
    # Step 6: Setup Ollama model
    setup_ollama_model(python_cmd)
    
    # Verify
    missing = verify_installation(python_cmd)
    
    # Summary
    print("\n" + "=" * 60)
    print("Installation Summary")
    print("=" * 60)
    
    if not missing:
        print("\n✅ Installation completed successfully!")
        print("\nNext steps:")
        print(f"  1. Ensure OVAL XML file is available")
        print(f"  2. Run: {python_cmd} research.py CVE-2024-XXXX")
        print(f"\nFor help: {python_cmd} research.py --help")
    else:
        print("\n⚠️  Installation completed with warnings")
        print(f"Missing packages: {', '.join(missing)}")
        print(f"Install manually: {python_cmd} -m pip install {' '.join(missing)}")
    
    print("=" * 60)

if __name__ == "__main__":
    main()
