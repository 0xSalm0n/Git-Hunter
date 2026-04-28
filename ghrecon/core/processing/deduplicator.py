"""
Deduplicator — removes duplicate findings based on content fingerprinting.

A finding is considered duplicate if the same secret value appeared in
the same file at the same commit.  This prevents the DB from filling
with repeated entries when TruffleHog reports the same credential
across multiple commits or branches.
"""

import hashlib

from ghrecon.utils.logger import get_logger

logger = get_logger("ghrecon.processing.deduplicator")


def fingerprint(finding: dict) -> str:
    """Generate a SHA-256 fingerprint for a normalized finding.

    The fingerprint is computed from:
      secret value + file path + commit hash

    This ensures the same secret in different files or commits is
    treated as a separate finding, while exact duplicates collapse.
    """
    raw = (
        f"{finding.get('value', '')}"
        f"-{finding.get('file_path', '')}"
        f"-{finding.get('commit_hash', '')}"
    )
    return hashlib.sha256(raw.encode()).hexdigest()


def deduplicate(findings: list[dict]) -> list[dict]:
    """Remove duplicate findings based on fingerprint.

    Args:
        findings: List of normalized finding dicts.

    Returns:
        Deduplicated list (order preserved, first occurrence kept).
    """
    seen: set[str] = set()
    unique: list[dict] = []

    for f in findings:
        fp = fingerprint(f)

        if fp in seen:
            continue

        seen.add(fp)
        unique.append(f)

    removed = len(findings) - len(unique)
    if removed > 0:
        logger.info(f"Deduplication: {len(findings)} -> {unique.__len__()} ({removed} duplicates removed)")

    return unique
