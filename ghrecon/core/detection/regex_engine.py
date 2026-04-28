"""
Regex detection engine — fallback scanner for Git-Hunter v2.

This engine is the original scanner from v1, wrapped behind the
DetectionEngine interface.  It is NOT enabled by default.  It activates
only when:
  * TruffleHog returns zero results, AND
  * The user passed ``--mode deep``

The output is already in normalized format (matching the schema expected
by the pipeline), so no extra normalization step is needed.
"""

import os
from typing import Optional

from .base import DetectionEngine
from ghrecon.core.scanner import SecretScanner, get_memory_mb
from ghrecon.config import GHReconConfig
from ghrecon.utils.logger import get_logger

logger = get_logger("ghrecon.detection.regex")


class RegexEngine(DetectionEngine):
    """Fallback regex + entropy detection engine (v1 scanner)."""

    name = "regex"

    def __init__(self, config: GHReconConfig):
        self._scanner = SecretScanner(config)

    def scan(self, target_path: str, **kwargs) -> list[dict]:
        """Run the v1 regex + entropy scanner on a repo path.

        Returns findings already in normalized-ish format (``type``,
        ``value``, ``file_path``, ``line_number``, etc.).
        """
        logger.info(f"Regex fallback scan: {target_path}")
        findings = self._scanner.scan_directory(target_path)

        logger.info(
            f"Regex engine: {len(findings)} findings "
            f"({self._scanner.files_scanned} files, mem: {get_memory_mb():.0f}MB)"
        )
        return findings

    def is_available(self) -> bool:
        """Regex engine is always available (pure Python)."""
        return True
