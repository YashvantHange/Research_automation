#!/bin/bash
# Cross-platform installation script for Research Automation System
# Works on Ubuntu/Debian, macOS, and Windows (via Git Bash/WSL)

set -e  # Exit on error

echo "============================================================"
echo "Research Automation System - Installation Script"
echo "============================================================"
echo ""

# Detect OS
OS="unknown"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    OS="windows"
fi

echo "[INFO] Detected OS: $OS"
echo ""

# Check Python
echo "[1/6] Checking Python installation..."
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    echo "  [OK] Python found: $PYTHON_VERSION"
elif command -v python &> /dev/null; then
    PYTHON_CMD="python"
    PYTHON_VERSION=$(python --version 2>&1 | awk '{print $2}')
    echo "  [OK] Python found: $PYTHON_VERSION"
else
    echo "  [ERROR] Python not found. Please install Python 3.8+ first."
    exit 1
fi

# Check pip
echo ""
echo "[2/6] Checking pip..."
if $PYTHON_CMD -m pip --version &> /dev/null; then
    echo "  [OK] pip is available"
else
    echo "  [ERROR] pip not found. Installing pip..."
    if [ "$OS" == "linux" ]; then
        sudo apt-get update && sudo apt-get install -y python3-pip
    elif [ "$OS" == "macos" ]; then
        curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
        $PYTHON_CMD get-pip.py
        rm get-pip.py
    fi
fi

# Install Python dependencies
echo ""
echo "[3/6] Installing Python dependencies..."
$PYTHON_CMD -m pip install --upgrade pip
$PYTHON_CMD -m pip install -r requirements.txt
echo "  [OK] Python dependencies installed"

# Install Ollama (if not installed)
echo ""
echo "[4/6] Checking Ollama installation..."
if command -v ollama &> /dev/null; then
    echo "  [OK] Ollama is installed"
    OLLAMA_VERSION=$(ollama --version 2>&1 || echo "unknown")
    echo "  [OK] Version: $OLLAMA_VERSION"
else
    echo "  [INFO] Ollama not found. Installing Ollama..."
    
    if [ "$OS" == "linux" ]; then
        # Linux installation
        curl -fsSL https://ollama.com/install.sh | sh
    elif [ "$OS" == "macos" ]; then
        # macOS installation
        if command -v brew &> /dev/null; then
            brew install ollama
        else
            echo "  [WARNING] Homebrew not found. Please install Ollama manually:"
            echo "    Download from: https://ollama.com/download"
        fi
    elif [ "$OS" == "windows" ]; then
        # Windows - try winget or direct download
        if command -v winget &> /dev/null; then
            echo "  [INFO] Installing via winget..."
            winget install Ollama.Ollama
        else
            echo "  [WARNING] winget not found. Please install Ollama manually:"
            echo "    Download from: https://ollama.com/download"
            echo "    Or use: choco install ollama (if Chocolatey is installed)"
        fi
    else
        echo "  [WARNING] Unknown OS. Please install Ollama manually:"
        echo "    Download from: https://ollama.com/download"
    fi
fi

# Start Ollama service
echo ""
echo "[5/6] Starting Ollama service..."
if [ "$OS" == "linux" ]; then
    # Linux - use systemd if available
    if systemctl is-active --quiet ollama 2>/dev/null; then
        echo "  [OK] Ollama service is already running"
    else
        echo "  [INFO] Starting Ollama service..."
        sudo systemctl start ollama 2>/dev/null || ollama serve &
        sleep 3
    fi
elif [ "$OS" == "macos" ]; then
    # macOS - check if running
    if pgrep -x "ollama" > /dev/null; then
        echo "  [OK] Ollama is already running"
    else
        echo "  [INFO] Starting Ollama..."
        ollama serve > /dev/null 2>&1 &
        sleep 3
    fi
else
    # Windows - check if port is accessible
    if nc -z localhost 11434 2>/dev/null || timeout 1 bash -c "cat < /dev/null > /dev/tcp/localhost/11434" 2>/dev/null; then
        echo "  [OK] Ollama service is accessible"
    else
        echo "  [INFO] Please start Ollama manually:"
        echo "    - Run 'ollama serve' in a terminal"
        echo "    - Or start Ollama from Start Menu"
    fi
fi

# Pull default model
echo ""
echo "[6/6] Setting up Ollama model..."
$PYTHON_CMD setup_ollama.py

# Verify installation
echo ""
echo "============================================================"
echo "Verifying Installation"
echo "============================================================"
echo ""

# Check Python packages
echo "Checking Python packages..."
MISSING_PACKAGES=()
for package in requests beautifulsoup4 lxml ollama packaging; do
    if $PYTHON_CMD -c "import $package" 2>/dev/null; then
        echo "  [OK] $package"
    else
        echo "  [ERROR] $package - NOT INSTALLED"
        MISSING_PACKAGES+=("$package")
    fi
done

# Check Ollama connection
echo ""
echo "Checking Ollama connection..."
if $PYTHON_CMD -c "import ollama; ollama.list()" 2>/dev/null; then
    echo "  [OK] Ollama is accessible"
else
    echo "  [WARNING] Ollama not accessible. Make sure it's running."
fi

# Summary
echo ""
echo "============================================================"
echo "Installation Summary"
echo "============================================================"
if [ ${#MISSING_PACKAGES[@]} -eq 0 ]; then
    echo ""
    echo "✅ Installation completed successfully!"
    echo ""
    echo "Next steps:"
    echo "  1. Ensure OVAL XML file is available"
    echo "  2. Run: $PYTHON_CMD research.py CVE-2024-XXXX"
    echo ""
    echo "For help: $PYTHON_CMD research.py --help"
else
    echo ""
    echo "⚠️  Installation completed with warnings"
    echo "Missing packages: ${MISSING_PACKAGES[*]}"
    echo "Install manually: $PYTHON_CMD -m pip install ${MISSING_PACKAGES[*]}"
fi
echo "============================================================"
