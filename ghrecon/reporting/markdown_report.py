"""
Markdown report generator.
"""

import json
import os
from datetime import datetime, timezone
from typing import Optional

from ghrecon.utils.db import DatabaseManager
from ghrecon.utils.logger import get_logger

logger = get_logger("ghrecon.reporting.markdown")


def generate_markdown_report(db: DatabaseManager, scan_id: str,
                              output_dir: str) -> str:
    """Generate a human-readable Markdown report."""
    stats = db.get_scan_stats(scan_id)
    scan = stats.get("scan", {})
    high_value = db.get_secrets(scan_id, high_value_only=True)
    validated = db.get_secrets(scan_id, validated_only=True)
    all_secrets = db.get_secrets(scan_id)

    # Duration
    start = scan.get("start_time", "")
    end = scan.get("end_time", "")
    duration_str = "N/A"
    if start and end:
        try:
            s = datetime.fromisoformat(start)
            e = datetime.fromisoformat(end)
            secs = int((e - s).total_seconds())
            mins, sec = divmod(secs, 60)
            duration_str = f"{mins}m {sec}s"
        except (ValueError, TypeError):
            pass

    target = scan.get("target", "unknown")
    lines = []
    lines.append(f"# GitHub Reconnaissance Report: {target}")
    lines.append(f"**Scan ID:** {scan_id}  ")
    lines.append(f"**Duration:** {duration_str}  ")
    lines.append(f"**Completed:** {end or 'In Progress'}  ")
    lines.append(f"**Status:** {scan.get('status', 'unknown')}")
    lines.append("")

    # Executive Summary
    lines.append("## Executive Summary")
    lines.append(f"- **Repositories Found:** {stats['repositories']['total']}")
    lines.append(f"- **Repositories Scanned:** {stats['repositories']['scanned']}")
    lines.append(f"- **Total Secrets Found:** {stats['secrets']['total']}")

    valid_count = stats['secrets']['valid'] or 0
    total_count = stats['secrets']['total'] or 0
    pct = f"({valid_count/total_count*100:.1f}%)" if total_count > 0 else ""
    lines.append(f"- **Validated Secrets:** {valid_count} {pct}")

    hv_count = stats['secrets']['high_value'] or 0
    emoji = " 🚨" if hv_count > 0 else ""
    lines.append(f"- **High-Value Secrets:** {hv_count}{emoji}")
    lines.append("")

    # High-Value Findings
    if high_value:
        lines.append("## 🔴 High-Value Findings")
        lines.append("")
        for i, secret in enumerate(high_value, 1):
            validation = _parse_validation(secret)
            lines.append(f"### {i}. {_friendly_type(secret['secret_type'])} 🔴")
            lines.append(f"- **File:** `{secret.get('file_path', 'N/A')}"
                         f":{secret.get('line_number', '')}`")
            if secret.get("branch"):
                lines.append(f"- **Branch:** `{secret['branch']}`")
            if secret.get("commit_hash"):
                lines.append(f"- **Commit:** `{secret['commit_hash'][:12]}`")

            if validation:
                if validation.get("account_info"):
                    lines.append(f"- **Account:** {validation['account_info']}")
                if validation.get("privilege_level"):
                    lines.append(f"- **Privilege:** {validation['privilege_level']}")
                if validation.get("scopes"):
                    lines.append(f"- **Scopes:** {', '.join(validation['scopes'])}")
                if validation.get("organizations"):
                    lines.append(f"- **Organizations:** {', '.join(validation['organizations'])}")
                if validation.get("arn"):
                    lines.append(f"- **ARN:** `{validation['arn']}`")

            lines.append(f"- **Risk:** {_risk_description(secret['secret_type'], validation)}")
            lines.append("")

    # Findings by Type
    if stats.get("by_type"):
        lines.append("## Findings by Type")
        lines.append("| Type | Total | Validated | High-Value |")
        lines.append("|------|-------|-----------|------------|")

        for secret_type, count in sorted(stats["by_type"].items(), key=lambda x: x[1], reverse=True):
            type_secrets = [s for s in all_secrets if s["secret_type"] == secret_type]
            type_valid = sum(1 for s in type_secrets if s.get("is_valid"))
            type_hv = sum(1 for s in type_secrets if s.get("high_value"))
            lines.append(f"| {_friendly_type(secret_type)} | {count} | {type_valid} | {type_hv} |")
        lines.append("")

    # Validated Findings Detail
    if validated:
        lines.append("## Validated Findings")
        lines.append("")
        for secret in validated:
            validation = _parse_validation(secret)
            lines.append(f"- **{_friendly_type(secret['secret_type'])}** "
                         f"in `{secret.get('file_path', 'N/A')}` — "
                         f"Privilege: {secret.get('privilege_level', 'unknown')}")
        lines.append("")

    # Recommendations
    lines.append("## Recommendations")
    lines.append("1. **Immediate rotation** of all validated credentials")
    lines.append("2. Enable GitHub **secret scanning** and **push protection**")
    lines.append("3. Audit deployment scripts for hardcoded secrets")
    lines.append("4. Implement a secrets manager (Vault, AWS Secrets Manager)")
    lines.append("5. Add pre-commit hooks (e.g., `detect-secrets`, `gitleaks`)")
    lines.append("6. Review CI/CD pipelines for secret exposure")
    lines.append("")

    lines.append("---")
    lines.append(f"*Generated by GHRecon v1.0.0 at {datetime.now(timezone.utc).isoformat()}*")

    content = "\n".join(lines)

    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, f"{scan_id}_report.md")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

    logger.info(f"Markdown report written: {output_path}")
    return output_path


def _friendly_type(secret_type: str) -> str:
    names = {
        "aws_access_key": "AWS Access Key",
        "aws_secret": "AWS Secret Key",
        "github_pat": "GitHub PAT",
        "github_oauth": "GitHub OAuth Token",
        "github_app": "GitHub App Token",
        "slack_token": "Slack Token",
        "slack_webhook": "Slack Webhook",
        "stripe_live": "Stripe Live Key",
        "stripe_restricted": "Stripe Restricted Key",
        "google_api": "Google API Key",
        "openai_api": "OpenAI API Key",
        "openai_api_v2": "OpenAI API Key",
        "private_key": "Private Key",
        "jwt": "JWT Token",
        "connection_string": "Connection String",
        "password_var": "Password Variable",
        "high_entropy": "High-Entropy String",
        "sendgrid_api": "SendGrid API Key",
        "twilio_api": "Twilio API Key",
        "telegram_bot": "Telegram Bot Token",
        "discord_token": "Discord Token",
    }
    return names.get(secret_type, secret_type.replace("_", " ").title())


def _parse_validation(secret: dict) -> dict:
    if secret.get("validation_result"):
        try:
            return json.loads(secret["validation_result"])
        except (json.JSONDecodeError, TypeError):
            pass
    return {}


def _risk_description(secret_type: str, validation: dict) -> str:
    risks = {
        "aws_access_key": "Can access AWS resources, potential data exfiltration",
        "github_pat": "Can read/write repositories, manage org settings",
        "slack_token": "Can read messages, post to channels",
        "stripe_live": "Can charge customers, access financial data",
        "openai_api": "Can consume API credits, access models",
        "private_key": "Can authenticate as server/service, decrypt data",
    }
    base = risks.get(secret_type, "Unauthorized access to service")
    priv = validation.get("privilege_level", "")
    if priv == "admin":
        base += " — **ADMIN ACCESS**"
    return base
