"""
TruffleHog detection engine — primary secret scanner for Git-Hunter v2.

Wraps the TruffleHog CLI binary, runs it in `filesystem` mode against
cloned repo paths, streams NDJSON output line-by-line, and returns raw
findings for downstream normalization.
"""

import json
import shutil
import subprocess
from typing import Optional

from .base import DetectionEngine
from ghrecon.utils.logger import get_logger

logger = get_logger("ghrecon.detection.trufflehog")

# Fallback binary names to search
_BINARY_NAMES = ("trufflehog", "trufflehog.exe")


class TruffleHogEngine(DetectionEngine):
    """Primary detection engine using TruffleHog."""

    name = "trufflehog"

    def __init__(
        self,
        verified_only: bool = True,
        timeout: int = 600,
        concurrency: int = 4,
        binary_path: Optional[str] = None,
    ):
        self.verified_only = verified_only
        self.timeout = timeout
        self.concurrency = concurrency
        self._binary = binary_path or self._find_binary()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, target_path: str, **kwargs) -> list[dict]:
        """Run TruffleHog against a filesystem path.

        Returns a list of raw TruffleHog JSON objects (one per finding).
        """
        if not self._binary:
            logger.error("TruffleHog binary not found — skipping scan")
            return []

        cmd = [
            self._binary,
            "filesystem",
            target_path,
            "--json",
            "--concurrency", str(self.concurrency),
        ]

        if self.verified_only:
            cmd.append("--only-verified")

        logger.debug(f"Running: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            findings: list[dict] = []
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

            if result.returncode != 0 and result.stderr:
                # Log stderr but don't fail — TruffleHog returns non-zero
                # when it finds secrets (exit code 183) in some versions
                stderr_preview = result.stderr[:300]
                if "no detectors" not in stderr_preview.lower():
                    logger.debug(f"TruffleHog stderr: {stderr_preview}")

            logger.info(
                f"TruffleHog: {len(findings)} findings from {target_path}"
            )
            return findings

        except subprocess.TimeoutExpired:
            logger.warning(
                f"TruffleHog timed out after {self.timeout}s on {target_path}"
            )
            return []
        except FileNotFoundError:
            logger.error(f"TruffleHog binary not found at: {self._binary}")
            self._binary = None
            return []
        except Exception as e:
            logger.error(f"TruffleHog scan error: {e}")
            return []

    def is_available(self) -> bool:
        """Check if TruffleHog binary is installed and reachable."""
        return self._binary is not None

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _find_binary() -> Optional[str]:
        """Locate the TruffleHog binary on PATH."""
        for name in _BINARY_NAMES:
            path = shutil.which(name)
            if path:
                return path
        return None
