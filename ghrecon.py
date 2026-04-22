#!/usr/bin/env python3
"""
GHRecon — GitHub Secret Reconnaissance Engine
==============================================

Production-grade offensive security tool for automated GitHub
organization/user reconnaissance with focus on credential
extraction, validation, and stealth operation.

Usage:
    python ghrecon.py scan <target> [options]
    python ghrecon.py export <scan_id> [options]
    python ghrecon.py status [scan_id]

Examples:
    python ghrecon.py scan myorg
    python ghrecon.py scan myorg --stealth --tokens tokens.txt --validate-secrets
    python ghrecon.py scan https://github.com/user/repo --depth full
    python ghrecon.py scan --type search "org:google language:python" --max-repos 50
    python ghrecon.py --resume-scan 20250422_143522_myorg
    python ghrecon.py export 20250422_143522_myorg --validated-only --format json
"""

import sys
import os

# Ensure the project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ghrecon.cli import app

if __name__ == "__main__":
    app()
