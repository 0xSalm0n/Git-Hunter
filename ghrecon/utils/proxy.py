"""
SOCKS5 proxy rotation manager.
"""

import random
import asyncio
from typing import Optional

from ghrecon.utils.logger import get_logger

logger = get_logger("ghrecon.proxy")


class ProxyManager:
    """Manages a pool of proxies with rotation and health tracking."""

    def __init__(self, proxies: Optional[list[str]] = None):
        self.proxies: list[str] = []
        self.failed: set[str] = set()
        self._index = 0
        self._lock = asyncio.Lock()

        if proxies:
            self.proxies = [p.strip() for p in proxies if p.strip()]

    @classmethod
    def from_file(cls, filepath: str) -> "ProxyManager":
        """Load proxies from a file (one per line)."""
        try:
            with open(filepath, "r") as f:
                proxies = [
                    line.strip() for line in f
                    if line.strip() and not line.startswith("#")
                ]
            mgr = cls(proxies)
            logger.info(f"Loaded {len(mgr.proxies)} proxies from {filepath}")
            return mgr
        except FileNotFoundError:
            logger.warning(f"Proxy file not found: {filepath}")
            return cls()

    async def get_proxy(self) -> Optional[str]:
        """Get the next available proxy (round-robin with skip of failed)."""
        if not self.proxies:
            return None

        async with self._lock:
            active = [p for p in self.proxies if p not in self.failed]
            if not active:
                logger.warning("All proxies have failed. Resetting failed list.")
                self.failed.clear()
                active = self.proxies.copy()

            proxy = active[self._index % len(active)]
            self._index = (self._index + 1) % len(active)
            return proxy

    async def get_random_proxy(self) -> Optional[str]:
        """Get a random available proxy."""
        if not self.proxies:
            return None

        async with self._lock:
            active = [p for p in self.proxies if p not in self.failed]
            if not active:
                self.failed.clear()
                active = self.proxies.copy()
            return random.choice(active)

    async def mark_failed(self, proxy: str) -> None:
        """Mark a proxy as failed."""
        async with self._lock:
            self.failed.add(proxy)
            logger.warning(f"Proxy marked as failed: {proxy} ({len(self.failed)}/{len(self.proxies)} failed)")

    async def mark_success(self, proxy: str) -> None:
        """Mark a proxy as working (remove from failed set)."""
        async with self._lock:
            self.failed.discard(proxy)

    @property
    def active_count(self) -> int:
        return len(self.proxies) - len(self.failed)

    @property
    def has_proxies(self) -> bool:
        return len(self.proxies) > 0

    def get_env_dict(self, proxy: Optional[str] = None) -> dict:
        """Get environment variables dict for git commands using the given proxy."""
        if not proxy:
            return {}
        if proxy.startswith("socks5://"):
            return {"ALL_PROXY": proxy, "http_proxy": proxy, "https_proxy": proxy}
        return {"http_proxy": proxy, "https_proxy": proxy}
