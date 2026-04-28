"""
Normalizer — transforms raw TruffleHog output into Git-Hunter's
unified finding schema.

Every finding stored in the DB must go through this layer.  Raw
TruffleHog JSON is NEVER stored directly.
"""

from typing import Optional

from ghrecon.utils.logger import get_logger

logger = get_logger("ghrecon.processing.normalizer")


def normalize_trufflehog(finding: dict) -> dict:
    """Convert a single raw TruffleHog finding to the unified schema.

    Unified schema fields:
        engine, type, value, verified, file_path, line_number,
        commit_hash, commit_date, commit_author, timestamp,
        context, source, entropy
    """
    # TruffleHog nests git metadata under SourceMetadata.Data.Git
    source_meta = finding.get("SourceMetadata", {}).get("Data", {})
    git_data = source_meta.get("Git", {})
    filesystem_data = source_meta.get("Filesystem", {})

    # Determine file path from git metadata or filesystem metadata
    file_path = (
        git_data.get("file")
        or filesystem_data.get("file")
        or ""
    )

    # Extract the raw secret value
    raw_value = finding.get("Raw", "") or ""
    # TruffleHog may also provide RawV2
    if not raw_value:
        raw_value = finding.get("RawV2", "") or ""

    return {
        "engine": "trufflehog",
        "type": finding.get("DetectorName", "unknown"),
        "value": raw_value,
        "verified": finding.get("Verified", False),
        "file_path": file_path,
        "line_number": git_data.get("line", None),
        "commit_hash": git_data.get("commit", ""),
        "commit_date": git_data.get("date", ""),
        "commit_author": git_data.get("email", ""),
        "branch": "",
        "timestamp": finding.get("Timestamp", ""),
        "context": _build_context(finding),
        "source": "trufflehog",
        "entropy": finding.get("RawEntropy", None),
        "detector_name": finding.get("DetectorName", ""),
    }


def normalize_regex(finding: dict) -> dict:
    """Pass through a regex-engine finding with engine tag added.

    The v1 regex scanner already emits a compatible dict, so we just
    stamp the engine field and ensure all keys exist.
    """
    finding.setdefault("engine", "regex")
    finding.setdefault("verified", False)
    finding.setdefault("detector_name", finding.get("type", ""))
    return finding


def normalize(finding: dict, engine: str = "trufflehog") -> dict:
    """Route to the correct normalizer based on engine name."""
    if engine == "trufflehog":
        return normalize_trufflehog(finding)
    return normalize_regex(finding)


def _build_context(finding: dict) -> str:
    """Build a short context string from TruffleHog metadata."""
    parts = []

    detector = finding.get("DetectorName", "")
    if detector:
        parts.append(f"Detector: {detector}")

    decoder = finding.get("DecoderName", "")
    if decoder and decoder != "PLAIN":
        parts.append(f"Decoder: {decoder}")

    verified = finding.get("Verified", False)
    parts.append(f"Verified: {verified}")

    extra = finding.get("ExtraData", {})
    if isinstance(extra, dict):
        for k, v in list(extra.items())[:5]:
            parts.append(f"{k}: {v}")

    return " | ".join(parts)[:500]
