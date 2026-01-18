#!/bin/bash
# Bash wrapper for Research Agent (Linux/Mac)
# Usage: ./research.sh CVE-2025-5591

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}OVAL XML Research Agent${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""

# Check if CVE ID provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 CVE-2025-5591 [additional CVEs...]"
    echo "Example: $0 CVE-2025-5591 CVE-2025-5592"
    exit 1
fi

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    if ! command -v python &> /dev/null; then
        echo -e "${RED}Error: Python not found${NC}"
        exit 1
    else
        PYTHON_CMD=python
    fi
else
    PYTHON_CMD=python3
fi

# Run Python script
echo -e "${YELLOW}Running research agent...${NC}"
$PYTHON_CMD research.py "$@"

if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}Research completed successfully!${NC}"
else
    echo ""
    echo -e "${RED}Error: Research failed${NC}"
    exit 1
fi
