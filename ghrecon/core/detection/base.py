"""
Abstract base class for detection engines.

All detection engines (TruffleHog, regex fallback) must implement this
interface so the pipeline can swap them transparently.
"""

from abc import ABC, abstractmethod
from typing import Optional

from ghrecon.utils.logger import get_logger

logger = get_logger("ghrecon.detection.base")


class DetectionEngine(ABC):
    """Base interface for secret detection engines."""

    name: str = "base"

    @abstractmethod
    def scan(self, target_path: str, **kwargs) -> list[dict]:
        """Scan a target path and return raw findings.

        Args:
            target_path: Filesystem path to scan (cloned repo root).

        Returns:
            List of raw finding dicts (engine-specific format).
        """
        raise NotImplementedError

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this engine's binary/dependency is installed."""
        raise NotImplementedError

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} engine={self.name}>"
