@echo off
REM Batch file wrapper for Research Agent (Windows)
REM Usage: research.bat CVE-2025-5591

setlocal enabledelayedexpansion

REM Check if CVE ID provided
if "%~1"=="" (
    echo Usage: research.bat CVE-2025-5591 [additional CVEs...]
    echo Example: research.bat CVE-2025-5591 CVE-2025-5592
    exit /b 1
)

REM Build arguments
set ARGS=
:loop
if "%~1"=="" goto :done
set ARGS=!ARGS! %1
shift
goto :loop
:done

REM Run Python script
python research.py %ARGS%

if errorlevel 1 (
    echo.
    echo Error: Research failed
    exit /b 1
)

echo.
echo Research completed successfully!
