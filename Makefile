# Makefile for Research Agent
# Usage: make research CVE=CVE-2025-5591

.PHONY: help research install test clean

# Default values
CVE ?= CVE-2025-5591
OVAL_XML ?= C:\Users\Yashvant\OneDrive\Documents\OVAL_WINDOWS.xml
MODEL ?= llama3.2
OUTPUT_DIR ?= outputs

help:
	@echo "OVAL XML Research Agent - Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make research CVE=CVE-2025-5591"
	@echo "  make research CVE=CVE-2025-5591 CVE2=CVE-2025-5592"
	@echo "  make install          - Install dependencies"
	@echo "  make test             - Run quick start test"
	@echo "  make clean            - Clean output files"
	@echo ""
	@echo "Examples:"
	@echo "  make research CVE=CVE-2025-5591"
	@echo "  make research CVE=CVE-2025-5591 OVAL_XML=/path/to/file.xml MODEL=llama3.1"

research:
	@echo "============================================================"
	@echo "Researching $(CVE)"
	@echo "============================================================"
	python research.py $(CVE) $(CVE2) $(CVE3) --oval-xml "$(OVAL_XML)" --ollama-model $(MODEL) --output-dir $(OUTPUT_DIR)

install:
	@echo "Installing dependencies..."
	pip install -r requirements.txt
	@echo "✓ Dependencies installed"

test:
	@echo "Running quick start test..."
	python quick_start.py

clean:
	@echo "Cleaning output files..."
	rm -rf outputs/*.md
	rm -rf data/vendor_db.json
	@echo "✓ Cleaned"
