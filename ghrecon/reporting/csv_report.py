"""
CSV report generator.
"""

import csv
import json
import os
from typing import Optional

from ghrecon.utils.db import DatabaseManager
from ghrecon.utils.logger import get_logger

logger = get_logger("ghrecon.reporting.csv")


def generate_csv_report(db: DatabaseManager, scan_id: str,
                        output_dir: str, validated_only: bool = False) -> str:
    """Generate a CSV report for spreadsheet import."""
    if validated_only:
        secrets = db.get_secrets(scan_id, validated_only=True)
    else:
        secrets = db.get_secrets(scan_id)

    repos = {r["repo_id"]: r for r in db.get_all_repos(scan_id)}

    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, f"{scan_id}_report.csv")

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Type", "Repository", "File", "Line", "Branch", "Commit",
            "Commit Author", "Commit Date", "Source", "Entropy",
            "Validated", "Is Valid", "Privilege Level", "High Value",
            "Account Info", "Discovered At"
        ])

        for secret in secrets:
            repo = repos.get(secret.get("repo_id", 0), {})
            validation = {}
            if secret.get("validation_result"):
                try:
                    validation = json.loads(secret["validation_result"])
                except (json.JSONDecodeError, TypeError):
                    pass

            writer.writerow([
                secret.get("secret_type", ""),
                repo.get("full_name", ""),
                secret.get("file_path", ""),
                secret.get("line_number", ""),
                secret.get("branch", ""),
                (secret.get("commit_hash") or "")[:12],
                secret.get("commit_author", ""),
                secret.get("commit_date", ""),
                secret.get("source", ""),
                f"{secret.get('entropy', 0):.2f}" if secret.get("entropy") else "",
                "Yes" if secret.get("validated") else "No",
                "Yes" if secret.get("is_valid") else ("No" if secret.get("validated") else ""),
                secret.get("privilege_level", ""),
                "Yes" if secret.get("high_value") else "No",
                validation.get("account_info", ""),
                secret.get("discovered_at", ""),
            ])

    logger.info(f"CSV report written: {output_path}")
    return output_path
