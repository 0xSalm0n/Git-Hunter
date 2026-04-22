"""
GitHub API Token Pool with rotation, health tracking, and rate limit management.
"""

import time
import hashlib
import asyncio
from typing import Optional

from ghrecon.utils.logger import get_logger

logger = get_logger("ghrecon.token_pool")


class TokenPool:
    """Manages a pool of GitHub API tokens with automatic rotation and health tracking."""

    def __init__(self, tokens: list[str]):
        if not tokens:
            raise ValueError("At least one GitHub token is required")
        self.tokens = [t.strip() for t in tokens if t.strip()]
        self.health: dict[str, dict] = {
            t: {"remaining": 5000, "reset": 0, "errors": 0, "expired": False}
            for t in self.tokens
        }
        self._lock = asyncio.Lock()

    @staticmethod
    def hash_token(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()[:12]

    @classmethod
    def from_file(cls, filepath: str) -> "TokenPool":
        """Load tokens from a file (one per line)."""
        with open(filepath, "r") as f:
            tokens = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        return cls(tokens)

    @classmethod
    def from_env(cls, env_var: str = "GITHUB_TOKENS") -> "TokenPool":
        """Load tokens from an environment variable (comma-separated)."""
        import os
        raw = os.environ.get(env_var, "")
        tokens = [t.strip() for t in raw.split(",") if t.strip()]
        if not tokens:
            single = os.environ.get("GITHUB_TOKEN", "")
            if single:
                tokens = [single]
        return cls(tokens)

    async def get_healthy_token(self) -> str:
        """Return the token with the most remaining calls, or wait for reset."""
        async with self._lock:
            # Filter out expired tokens
            active = [t for t in self.tokens if not self.health[t]["expired"]]
            if not active:
                logger.error("All tokens expired or invalid!")
                raise RuntimeError("No valid GitHub tokens available")

            # Sort by remaining calls (descending)
            active.sort(key=lambda t: self.health[t]["remaining"], reverse=True)

            # Return best token if it has calls remaining
            best = active[0]
            if self.health[best]["remaining"] > 100:
                return best

            # All exhausted — find soonest reset
            soonest_reset = min(self.health[t]["reset"] for t in active)
            wait_time = soonest_reset - time.time()

            if wait_time > 0:
                logger.warning(f"All tokens exhausted. Waiting {wait_time:.0f}s for reset...")
                await asyncio.sleep(min(wait_time + 5, 3700))

            # Reset counters after waiting
            for t in active:
                if time.time() >= self.health[t]["reset"]:
                    self.health[t]["remaining"] = 5000
                    self.health[t]["errors"] = 0

            return active[0]

    async def update_health(self, token: str, response_headers: dict) -> None:
        """Update rate limit info from GitHub API response headers."""
        async with self._lock:
            remaining = int(response_headers.get("X-RateLimit-Remaining", 0))
            reset_ts = int(response_headers.get("X-RateLimit-Reset", 0))
            self.health[token]["remaining"] = remaining
            self.health[token]["reset"] = reset_ts

            if remaining < 100:
                logger.warning(
                    f"Token ...{self.hash_token(token)} low: {remaining} calls remaining, "
                    f"resets at {time.strftime('%H:%M:%S', time.localtime(reset_ts))}"
                )

    async def mark_error(self, token: str, status_code: int) -> None:
        """Track errors for a token. Mark as expired on 401."""
        async with self._lock:
            self.health[token]["errors"] += 1

            if status_code == 401:
                self.health[token]["expired"] = True
                logger.error(f"Token ...{self.hash_token(token)} expired/invalid (401). Removed from pool.")
            elif status_code == 403:
                self.health[token]["remaining"] = 0
                logger.warning(f"Token ...{self.hash_token(token)} rate limited (403).")

    def get_status(self) -> list[dict]:
        """Get current status of all tokens."""
        return [
            {
                "token_id": self.hash_token(t),
                "remaining": self.health[t]["remaining"],
                "reset": time.strftime("%H:%M:%S", time.localtime(self.health[t]["reset"]))
                if self.health[t]["reset"] > 0 else "N/A",
                "errors": self.health[t]["errors"],
                "expired": self.health[t]["expired"],
            }
            for t in self.tokens
        ]

    @property
    def active_count(self) -> int:
        return sum(1 for t in self.tokens if not self.health[t]["expired"])
