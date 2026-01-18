# PowerShell wrapper for Research Agent
# Usage: .\research.ps1 CVE-2025-5591

param(
    [Parameter(Mandatory=$true, Position=0)]
    [string[]]$CVEIds,
    
    [string]$OvalXml = "C:\Users\Yashvant\OneDrive\Documents\OVAL_WINDOWS.xml",
    [string]$OllamaModel = "llama3.2",
    [string]$NvdApiKey = "",
    [string]$GitHubToken = "",
    [string[]]$Urls = @(),
    [string]$OutputDir = "outputs",
    [string]$VendorDb = "data/vendor_db.json"
)

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "OVAL XML Research Agent" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Build Python command
$pythonArgs = @()
$pythonArgs += $CVEIds
$pythonArgs += "--oval-xml", $OvalXml
$pythonArgs += "--ollama-model", $OllamaModel
$pythonArgs += "--output-dir", $OutputDir
$pythonArgs += "--vendor-db", $VendorDb

if ($NvdApiKey) {
    $pythonArgs += "--nvd-api-key", $NvdApiKey
}

if ($GitHubToken) {
    $pythonArgs += "--github-token", $GitHubToken
}

if ($Urls.Count -gt 0) {
    $pythonArgs += "--urls"
    $pythonArgs += $Urls
}

# Run Python script
Write-Host "Running research agent..." -ForegroundColor Yellow
python research.py $pythonArgs

if ($LASTEXITCODE -ne 0) {
    Write-Host "`nError: Research failed with exit code $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "`nResearch completed successfully!" -ForegroundColor Green
