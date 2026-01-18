# Cross-platform installation script for Research Automation System (PowerShell)
# Works on Windows PowerShell and PowerShell Core (cross-platform)

$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Research Automation System - Installation Script" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Detect OS
$OS = "unknown"
if ($IsLinux -or $env:OS -like "*Linux*") {
    $OS = "linux"
} elseif ($IsMacOS -or $env:OS -like "*Darwin*") {
    $OS = "macos"
} elseif ($IsWindows -or $env:OS -like "*Windows*") {
    $OS = "windows"
}

Write-Host "[INFO] Detected OS: $OS" -ForegroundColor Yellow
Write-Host ""

# Check Python
Write-Host "[1/6] Checking Python installation..." -ForegroundColor Cyan
$pythonCmd = $null
if (Get-Command python3 -ErrorAction SilentlyContinue) {
    $pythonCmd = "python3"
    $pythonVersion = python3 --version 2>&1
    Write-Host "  [OK] Python found: $pythonVersion" -ForegroundColor Green
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonCmd = "python"
    $pythonVersion = python --version 2>&1
    Write-Host "  [OK] Python found: $pythonVersion" -ForegroundColor Green
} else {
    Write-Host "  [ERROR] Python not found. Please install Python 3.8+ first." -ForegroundColor Red
    exit 1
}

# Check pip
Write-Host ""
Write-Host "[2/6] Checking pip..." -ForegroundColor Cyan
try {
    & $pythonCmd -m pip --version | Out-Null
    Write-Host "  [OK] pip is available" -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] pip not found. Please install pip first." -ForegroundColor Red
    exit 1
}

# Install Python dependencies
Write-Host ""
Write-Host "[3/6] Installing Python dependencies..." -ForegroundColor Cyan
& $pythonCmd -m pip install --upgrade pip
& $pythonCmd -m pip install -r requirements.txt
Write-Host "  [OK] Python dependencies installed" -ForegroundColor Green

# Install Ollama (if not installed)
Write-Host ""
Write-Host "[4/6] Checking Ollama installation..." -ForegroundColor Cyan
if (Get-Command ollama -ErrorAction SilentlyContinue) {
    Write-Host "  [OK] Ollama is installed" -ForegroundColor Green
    $ollamaVersion = ollama --version 2>&1
    Write-Host "  [OK] Version: $ollamaVersion" -ForegroundColor Green
} else {
    Write-Host "  [INFO] Ollama not found. Installing Ollama..." -ForegroundColor Yellow
    
    if ($OS -eq "windows") {
        # Windows - try winget
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            Write-Host "  [INFO] Installing via winget..." -ForegroundColor Yellow
            winget install Ollama.Ollama --accept-package-agreements --accept-source-agreements
        } elseif (Get-Command choco -ErrorAction SilentlyContinue) {
            Write-Host "  [INFO] Installing via Chocolatey..." -ForegroundColor Yellow
            choco install ollama -y
        } else {
            Write-Host "  [WARNING] Please install Ollama manually:" -ForegroundColor Yellow
            Write-Host "    Download from: https://ollama.com/download" -ForegroundColor Yellow
        }
    } elseif ($OS -eq "linux") {
        Write-Host "  [INFO] Installing Ollama for Linux..." -ForegroundColor Yellow
        curl -fsSL https://ollama.com/install.sh | bash
    } elseif ($OS -eq "macos") {
        if (Get-Command brew -ErrorAction SilentlyContinue) {
            Write-Host "  [INFO] Installing via Homebrew..." -ForegroundColor Yellow
            brew install ollama
        } else {
            Write-Host "  [WARNING] Homebrew not found. Please install Ollama manually:" -ForegroundColor Yellow
            Write-Host "    Download from: https://ollama.com/download" -ForegroundColor Yellow
        }
    }
}

# Start Ollama service
Write-Host ""
Write-Host "[5/6] Starting Ollama service..." -ForegroundColor Cyan
if ($OS -eq "windows") {
    # Windows - check if port is accessible
    $portTest = Test-NetConnection -ComputerName localhost -Port 11434 -InformationLevel Quiet -WarningAction SilentlyContinue
    if ($portTest) {
        Write-Host "  [OK] Ollama service is accessible" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] Please start Ollama manually:" -ForegroundColor Yellow
        Write-Host "    - Run 'ollama serve' in a terminal" -ForegroundColor Yellow
        Write-Host "    - Or start Ollama from Start Menu" -ForegroundColor Yellow
        Write-Host "  [INFO] Attempting to start Ollama..." -ForegroundColor Yellow
        Start-Process -FilePath "ollama" -ArgumentList "serve" -WindowStyle Hidden -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
    }
} elseif ($OS -eq "linux") {
    if (Get-Service ollama -ErrorAction SilentlyContinue) {
        if ((Get-Service ollama).Status -eq "Running") {
            Write-Host "  [OK] Ollama service is running" -ForegroundColor Green
        } else {
            Write-Host "  [INFO] Starting Ollama service..." -ForegroundColor Yellow
            sudo systemctl start ollama
        }
    } else {
        Write-Host "  [INFO] Starting Ollama..." -ForegroundColor Yellow
        Start-Process -FilePath "ollama" -ArgumentList "serve" -WindowStyle Hidden
        Start-Sleep -Seconds 3
    }
} else {
    # macOS or other
    $ollamaProcess = Get-Process -Name "ollama" -ErrorAction SilentlyContinue
    if ($ollamaProcess) {
        Write-Host "  [OK] Ollama is running" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] Starting Ollama..." -ForegroundColor Yellow
        Start-Process -FilePath "ollama" -ArgumentList "serve" -WindowStyle Hidden
        Start-Sleep -Seconds 3
    }
}

# Pull default model
Write-Host ""
Write-Host "[6/6] Setting up Ollama model..." -ForegroundColor Cyan
& $pythonCmd setup_ollama.py

# Verify installation
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Verifying Installation" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Check Python packages
Write-Host "Checking Python packages..." -ForegroundColor Cyan
$missingPackages = @()
$packages = @("requests", "bs4", "lxml", "ollama", "packaging")
foreach ($package in $packages) {
    try {
        & $pythonCmd -c "import $package" 2>&1 | Out-Null
        Write-Host "  [OK] $package" -ForegroundColor Green
    } catch {
        Write-Host "  [ERROR] $package - NOT INSTALLED" -ForegroundColor Red
        $missingPackages += $package
    }
}

# Check Ollama connection
Write-Host ""
Write-Host "Checking Ollama connection..." -ForegroundColor Cyan
try {
    & $pythonCmd -c "import ollama; ollama.list()" 2>&1 | Out-Null
    Write-Host "  [OK] Ollama is accessible" -ForegroundColor Green
} catch {
    Write-Host "  [WARNING] Ollama not accessible. Make sure it's running." -ForegroundColor Yellow
}

# Summary
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Installation Summary" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
if ($missingPackages.Count -eq 0) {
    Write-Host ""
    Write-Host "✅ Installation completed successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "  1. Ensure OVAL XML file is available" -ForegroundColor White
    Write-Host "  2. Run: $pythonCmd research.py CVE-2024-XXXX" -ForegroundColor White
    Write-Host ""
    Write-Host "For help: $pythonCmd research.py --help" -ForegroundColor White
} else {
    Write-Host ""
    Write-Host "⚠️  Installation completed with warnings" -ForegroundColor Yellow
    Write-Host "Missing packages: $($missingPackages -join ', ')" -ForegroundColor Yellow
    Write-Host "Install manually: $pythonCmd -m pip install $($missingPackages -join ' ')" -ForegroundColor Yellow
}
Write-Host "============================================================" -ForegroundColor Cyan
