#!/usr/bin/env python3
"""Quick check of all installation files."""

from pathlib import Path

files = [
    'install.sh',
    'install.ps1', 
    'install.py',
    'verify_installation.py',
    'INSTALL.md',
    'SYSTEM_STATUS.md',
    'INSTALLATION_COMPLETE.md'
]

print('=' * 60)
print('FINAL SYSTEM CHECK')
print('=' * 60)
print()

all_ok = True
for f in files:
    p = Path(f)
    status = 'OK' if p.exists() else 'MISSING'
    if p.exists():
        size = p.stat().st_size
        print(f'{f:35} {status:8} ({size:,} bytes)')
    else:
        print(f'{f:35} {status:8}')
        all_ok = False

print()
if all_ok:
    print('[OK] All installation files: READY')
else:
    print('[ERROR] Some files are missing')
print('=' * 60)
