"""
JSON report generator.
"""

import json
import os
from datetime import datetime, timezone
from typing import Optional

from ghrecon.utils.db import DatabaseManager
from ghrecon.utils.logger import get_logger

logger = get_logger("ghrecon.reporting.json")


def generate_json_report(db: DatabaseManager, scan_id: str,
                         output_dir: str, validated_only: bool = False) -> str:
    """Generate a comprehensive JSON report for a scan."""
    stats = db.get_scan_stats(scan_id)
    scan = stats.get("scan", {})
    repos = db.get_all_repos(scan_id)
    all_secrets = db.get_secrets(scan_id)
    high_value = db.get_secrets(scan_id, high_value_only=True)
    validated = db.get_secrets(scan_id, validated_only=True)

    # Calculate duration
    start = scan.get("start_time", "")
    end = scan.get("end_time", "")
    duration = 0
    if start and end:
        try:
            s = datetime.fromisoformat(start)
            e = datetime.fromisoformat(end)
            duration = int((e - s).total_seconds())
        except (ValueError, TypeError):
            pass

    report = {
        "scan_metadata": {
            "scan_id": scan_id,
            "target": scan.get("target", ""),
            "target_type": scan.get("target_type", ""),
            "start_time": start,
            "end_time": end,
            "duration_seconds": duration,
            "status": scan.get("status", ""),
            "repos_found": stats["repositories"]["total"],
            "repos_scanned": stats["repositories"]["scanned"],
            "repos_failed": stats["repositories"]["failed"],
            "repos_skipped": stats["repositories"]["skipped"],
            "total_secrets_found": stats["secrets"]["total"],
            "validated_secrets": stats["secrets"]["valid"] or 0,
            "invalid_secrets": stats["secrets"]["invalid"] or 0,
            "high_value_secrets": stats["secrets"]["high_value"] or 0,
        },
        "summary": {
            "by_type": stats.get("by_type", {}),
            "by_validation": {
                "valid": stats["secrets"]["valid"] or 0,
                "invalid": stats["secrets"]["invalid"] or 0,
                "not_validated": stats["secrets"]["unvalidated"] or 0,
            },
        },
        "high_value_findings": [_format_secret(s, db) for s in high_value],
        "validated_findings": [_format_secret(s, db) for s in validated] if not validated_only else None,
        "all_findings": [_format_secret(s, db) for s in all_secrets] if not validated_only else None,
        "repositories": [
            {
                "full_name": r["full_name"],
                "url": r["url"],
                "clone_status": r["clone_status"],
                "scan_status": r["scan_status"],
                "size_mb": r["size_mb"],
                "stars": r["stars"],
                "is_fork": bool(r["is_fork"]),
                "is_archived": bool(r["is_archived"]),
            }
            for r in repos
        ],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    # Remove None values
    report = {k: v for k, v in report.items() if v is not None}

    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, f"{scan_id}_report.json")

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    logger.info(f"JSON report written: {output_path}")
    return output_path


def _format_secret(secret: dict, db: DatabaseManager) -> dict:
    """Format a secret record for the report."""
    validation = {}
    if secret.get("validation_result"):
        try:
            validation = json.loads(secret["validation_result"])
        except (json.JSONDecodeError, TypeError):
            pass

    return {
        "type": secret.get("secret_type", ""),
        "file_path": secret.get("file_path", ""),
        "line_number": secret.get("line_number"),
        "branch": secret.get("branch", ""),
        "commit_hash": secret.get("commit_hash", ""),
        "commit_date": secret.get("commit_date", ""),
        "commit_author": secret.get("commit_author", ""),
        "source": secret.get("source", ""),
        "entropy": secret.get("entropy"),
        "validated": bool(secret.get("validated")),
        "is_valid": secret.get("is_valid"),
        "high_value": bool(secret.get("high_value")),
        "privilege_level": secret.get("privilege_level", ""),
        "validation_details": validation,
        "discovered_at": secret.get("discovered_at", ""),
    }
