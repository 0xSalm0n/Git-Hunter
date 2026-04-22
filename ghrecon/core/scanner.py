"""
Secret detection engine with regex patterns, entropy analysis, and multi-zone scanning.
"""

import os
import re
import math
import hashlib
import asyncio
import zipfile
import tarfile
import tempfile
from typing import Optional
from datetime import datetime, timezone

import yaml

from ghrecon.utils.logger import get_logger
from ghrecon.config import GHReconConfig

logger = get_logger("ghrecon.scanner")

# Comprehensive secret patterns
SECRET_PATTERNS: dict[str, str] = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "aws_secret": r"(?i)aws[_\s]*secret[_\s]*(?:access)?[_\s]*key[_\s]*[:=][_\s]*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
    "github_pat": r"ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}",
    "github_oauth": r"gho_[a-zA-Z0-9]{36}",
    "github_app": r"(?:ghu|ghs)_[a-zA-Z0-9]{36}",
    "github_refresh": r"ghr_[a-zA-Z0-9]{36}",
    "slack_token": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}",
    "slack_webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
    "stripe_live": r"sk_live_[0-9a-zA-Z]{24,}",
    "stripe_restricted": r"rk_live_[0-9a-zA-Z]{24,}",
    "stripe_publishable": r"pk_live_[0-9a-zA-Z]{24,}",
    "google_api": r"AIza[0-9A-Za-z_-]{35}",
    "google_oauth": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "openai_api": r"sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}",
    "openai_api_v2": r"sk-(?:proj-)?[a-zA-Z0-9_-]{40,}",
    "azure_storage": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88};",
    "azure_connection": r"(?i)(?:AccountKey|SharedAccessKey)=[A-Za-z0-9+/=]{44,}",
    "square_token": r"sq0csp-[0-9A-Za-z_-]{43}",
    "square_oauth": r"sq0atp-[0-9A-Za-z_-]{22}",
    "twitter_bearer": r"AAAAAAAAAAAAAAAAAAAAAA[a-zA-Z0-9%]{60,}",
    "sendgrid_api": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
    "mailgun_api": r"key-[0-9a-zA-Z]{32}",
    "twilio_api": r"SK[0-9a-fA-F]{32}",
    "twilio_auth": r"(?i)twilio[_\s]*auth[_\s]*token[_\s]*[:=][_\s]*['\"]?([0-9a-f]{32})['\"]?",
    "private_key": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?:\sBLOCK)?-----",
    "jwt": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
    "connection_string": r"(?i)(?:jdbc|mongodb(?:\+srv)?|mysql|postgresql|redis|amqp)://[^\s'\"]{10,}",
    "password_var": r"(?i)(?:password|passwd|pwd|pass|db_pass|api_pass)\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
    "heroku_api": r"(?i)heroku[_\s]*api[_\s]*key[_\s]*[:=][_\s]*['\"]?([0-9a-f-]{36})['\"]?",
    "shopify_token": r"shpat_[a-fA-F0-9]{32}",
    "shopify_secret": r"shpss_[a-fA-F0-9]{32}",
    "databricks_token": r"dapi[a-zA-Z0-9]{32}",
    "digitalocean_token": r"dop_v1_[a-f0-9]{64}",
    "npm_token": r"npm_[a-zA-Z0-9]{36}",
    "pypi_token": r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}",
    "telegram_bot": r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}",
    "discord_token": r"(?:mfa\.[a-zA-Z0-9_-]{84}|[a-zA-Z0-9_-]{24}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27})",
    "firebase_key": r"(?i)firebase[_\s]*(?:api[_\s]*key|secret|database[_\s]*url)[_\s]*[:=][_\s]*['\"]?([^\s'\"]{10,})['\"]?",
    "gcp_service_account": r'"type"\s*:\s*"service_account"',
    "generic_secret": r"(?i)(?:api[_\s]*key|secret[_\s]*key|access[_\s]*token|auth[_\s]*token)\s*[:=]\s*['\"]([^'\"]{16,})['\"]",
}

# File extensions to skip (binary/irrelevant)
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".pyc", ".pyo", ".class", ".o", ".so", ".dll", ".exe",
    ".lock", ".sum",
}

# High-value config files to always scan
CONFIG_PATTERNS = [
    ".env", ".env.*", "*.env", ".env.local", ".env.production", ".env.staging",
    "config.json", "config.yaml", "config.yml", "config.toml",
    "settings.py", "settings.json", "application.properties", "application.yml",
    "docker-compose.yml", "docker-compose.yaml", "Dockerfile",
    ".github/workflows/*.yml", ".github/workflows/*.yaml",
    ".gitlab-ci.yml", "Jenkinsfile", ".circleci/config.yml",
    "*.tf", "*.tfvars", "*.tfstate",
    "cloudformation*.yaml", "cloudformation*.yml", "cloudformation*.json",
    "kubernetes/*.yaml", "kubernetes/*.yml", "k8s/*.yaml", "k8s/*.yml",
    "credentials", "credentials.json", "service-account*.json",
    "secrets.yaml", "secrets.yml", "vault*.yaml",
]

ENTROPY_KEYWORDS = [
    "api", "key", "token", "secret", "password", "passwd", "pwd", "auth",
    "credential", "private", "access", "bearer", "oauth", "jwt",
]


class SecretScanner:
    """Multi-zone secret detection engine."""

    def __init__(self, config: GHReconConfig, custom_patterns: Optional[dict] = None):
        self.config = config
        self.patterns = {**SECRET_PATTERNS}
        if custom_patterns:
            self.patterns.update(custom_patterns)
        self._compiled = {name: re.compile(pat) for name, pat in self.patterns.items()}
        self._seen_hashes: set[str] = set()

    @classmethod
    def with_patterns_file(cls, config: GHReconConfig, patterns_path: str) -> "SecretScanner":
        """Create scanner with additional patterns from a YAML file."""
        custom = {}
        if os.path.exists(patterns_path):
            with open(patterns_path) as f:
                data = yaml.safe_load(f) or {}
                custom = data.get("patterns", {})
        return cls(config, custom)

    def scan_text(self, text: str, file_path: str = "", branch: str = "",
                  commit_hash: str = "", commit_date: str = "",
                  commit_author: str = "") -> list[dict]:
        """Scan text content for secrets."""
        findings = []
        lines = text.split("\n")

        for line_num, line in enumerate(lines, 1):
            if len(line) > 5000:
                continue

            for name, pattern in self._compiled.items():
                for match in pattern.finditer(line):
                    value = match.group(1) if match.lastindex else match.group(0)
                    value_hash = hashlib.sha256(value.encode()).hexdigest()

                    if value_hash in self._seen_hashes:
                        continue
                    self._seen_hashes.add(value_hash)

                    # Skip obvious test/example values
                    if self._is_likely_false_positive(value, name):
                        continue

                    entropy = calculate_entropy(value) if len(value) >= 16 else 0

                    context_start = max(0, line_num - 3)
                    context_end = min(len(lines), line_num + 2)
                    context_lines = lines[context_start:context_end]
                    context = "\n".join(context_lines)

                    findings.append({
                        "type": name,
                        "value": value,
                        "file_path": file_path,
                        "line_number": line_num,
                        "branch": branch,
                        "commit_hash": commit_hash,
                        "commit_date": commit_date,
                        "commit_author": commit_author,
                        "context": context[:500],
                        "entropy": entropy,
                        "source": "regex",
                    })

        return findings

    def _is_likely_false_positive(self, value: str, pattern_name: str) -> bool:
        """Check if a match is likely a false positive."""
        lower = value.lower()

        # Skip placeholder/example values
        fp_indicators = [
            "example", "sample", "placeholder", "your_", "xxx", "000",
            "test", "dummy", "fake", "todo", "fixme", "changeme",
            "insert_", "replace_", "<your", "${", "{{",
        ]
        if any(ind in lower for ind in fp_indicators):
            return True

        # Skip very short values for certain types
        if pattern_name in ("password_var", "generic_secret") and len(value) < 8:
            return True

        # Skip values that are all the same character
        if len(set(value)) <= 2:
            return True

        return False

    def scan_file(self, file_path: str, branch: str = "") -> list[dict]:
        """Scan a single file for secrets."""
        ext = os.path.splitext(file_path)[1].lower()
        if ext in SKIP_EXTENSIONS:
            return []

        try:
            # Check file size (skip files > 10MB)
            if os.path.getsize(file_path) > 10 * 1024 * 1024:
                return []

            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            return self.scan_text(content, file_path=file_path, branch=branch)
        except (OSError, PermissionError) as e:
            logger.warning(f"Cannot read {file_path}: {e}")
            return []

    def scan_directory(self, dir_path: str, branch: str = "") -> list[dict]:
        """Recursively scan a directory for secrets."""
        findings = []
        for root, dirs, files in os.walk(dir_path):
            # Skip .git directory and common non-code dirs
            dirs[:] = [d for d in dirs if d not in (
                ".git", "node_modules", "vendor", "venv", "__pycache__",
                ".tox", ".mypy_cache", ".pytest_cache", "dist", "build"
            )]

            for filename in files:
                filepath = os.path.join(root, filename)
                file_findings = self.scan_file(filepath, branch=branch)
                findings.extend(file_findings)

        return findings

    async def scan_commit_history(self, repo_path: str,
                                    max_commits: int = 500) -> list[dict]:
        """Scan commit diffs for secrets."""
        findings = []
        try:
            proc = await asyncio.create_subprocess_exec(
                "git", "-C", repo_path, "log", "-p",
                f"-n{max_commits}", "--all", "--diff-filter=ACMR",
                "--pretty=format:COMMIT_SEP|%H|%an|%aI",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)

            output = stdout.decode(errors="replace")
            commits = output.split("COMMIT_SEP|")

            for commit_block in commits:
                if not commit_block.strip():
                    continue

                lines = commit_block.split("\n", 1)
                header = lines[0].strip()
                diff_content = lines[1] if len(lines) > 1 else ""

                parts = header.split("|", 2)
                commit_hash = parts[0] if parts else ""
                author = parts[1] if len(parts) > 1 else ""
                date = parts[2] if len(parts) > 2 else ""

                # Scan added lines in diffs
                current_file = ""
                for diff_line in diff_content.split("\n"):
                    if diff_line.startswith("+++ b/"):
                        current_file = diff_line[6:]
                    elif diff_line.startswith("+") and not diff_line.startswith("+++"):
                        line_findings = self.scan_text(
                            diff_line[1:], file_path=current_file,
                            commit_hash=commit_hash, commit_author=author,
                            commit_date=date
                        )
                        findings.extend(line_findings)

        except Exception as e:
            logger.warning(f"Commit history scan failed: {e}")

        return findings

    async def scan_commit_messages(self, repo_path: str,
                                     max_commits: int = 1000) -> list[dict]:
        """Scan commit messages for credential keywords."""
        findings = []
        keywords = ["password", "token", "secret", "key", "credential",
                     "api_key", "apikey", "auth", "bearer"]

        try:
            proc = await asyncio.create_subprocess_exec(
                "git", "-C", repo_path, "log",
                f"-n{max_commits}", "--all",
                "--pretty=format:%H|%an|%aI|%s",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)

            for line in stdout.decode(errors="replace").splitlines():
                parts = line.split("|", 3)
                if len(parts) < 4:
                    continue
                commit_hash, author, date, message = parts

                msg_lower = message.lower()
                if any(kw in msg_lower for kw in keywords):
                    msg_findings = self.scan_text(
                        message, file_path="[commit_message]",
                        commit_hash=commit_hash, commit_author=author,
                        commit_date=date
                    )
                    findings.extend(msg_findings)

        except Exception as e:
            logger.warning(f"Commit message scan failed: {e}")

        return findings

    def scan_archive(self, archive_path: str) -> list[dict]:
        """Extract and scan archive files (.zip, .tar, .tar.gz)."""
        findings = []
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                if archive_path.endswith(".zip"):
                    with zipfile.ZipFile(archive_path, "r") as zf:
                        zf.extractall(tmpdir)
                elif archive_path.endswith((".tar", ".tar.gz", ".tgz")):
                    with tarfile.open(archive_path, "r:*") as tf:
                        tf.extractall(tmpdir, filter="data")
                else:
                    return findings

                findings = self.scan_directory(tmpdir)
                for f in findings:
                    f["file_path"] = f"[archive:{archive_path}]/{f['file_path']}"

        except Exception as e:
            logger.warning(f"Archive scan failed for {archive_path}: {e}")

        return findings

    def entropy_scan(self, text: str, file_path: str = "") -> list[dict]:
        """Find high-entropy strings near sensitive keywords."""
        findings = []
        lines = text.split("\n")

        for line_num, line in enumerate(lines, 1):
            if len(line) > 2000:
                continue

            # Extract potential secret strings (quoted values, assignments)
            string_pattern = re.compile(
                r"""['"]([\w+/=@.:-]{16,})['""]|[:=]\s*[\s'"]*([A-Za-z0-9+/=_-]{20,})"""
            )

            for match in string_pattern.finditer(line):
                value = match.group(1) or match.group(2)
                if not value or len(value) < 16:
                    continue

                entropy = calculate_entropy(value)
                if entropy < 4.5:
                    continue

                # Check if near a keyword
                context_window = line.lower()
                if not any(kw in context_window for kw in ENTROPY_KEYWORDS):
                    continue

                value_hash = hashlib.sha256(value.encode()).hexdigest()
                if value_hash in self._seen_hashes:
                    continue
                self._seen_hashes.add(value_hash)

                findings.append({
                    "type": "high_entropy",
                    "value": value,
                    "file_path": file_path,
                    "line_number": line_num,
                    "entropy": entropy,
                    "context": line[:500],
                    "source": "entropy",
                })

        return findings

    async def full_repo_scan(self, repo_path: str, repo_name: str = "") -> list[dict]:
        """Perform a comprehensive scan of a repository."""
        all_findings = []
        logger.info(f"Starting full scan: {repo_name or repo_path}")

        # 1. Scan working directory
        dir_findings = self.scan_directory(repo_path)
        all_findings.extend(dir_findings)
        logger.info(f"  Directory scan: {len(dir_findings)} findings")

        # 2. Entropy scan on high-value files
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "vendor")]
            for fname in files:
                fpath = os.path.join(root, fname)
                ext = os.path.splitext(fname)[1].lower()
                if ext in SKIP_EXTENSIONS:
                    continue
                try:
                    if os.path.getsize(fpath) > 5 * 1024 * 1024:
                        continue
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    entropy_findings = self.entropy_scan(content, file_path=fpath)
                    all_findings.extend(entropy_findings)
                except (OSError, PermissionError):
                    pass

        # 3. Scan commit history
        history_findings = await self.scan_commit_history(repo_path)
        all_findings.extend(history_findings)
        logger.info(f"  History scan: {len(history_findings)} findings")

        # 4. Scan commit messages
        msg_findings = await self.scan_commit_messages(repo_path)
        all_findings.extend(msg_findings)

        # 5. Scan archives found in the repo
        for root, _, files in os.walk(repo_path):
            for fname in files:
                if fname.endswith((".zip", ".tar", ".tar.gz", ".tgz")):
                    fpath = os.path.join(root, fname)
                    if os.path.getsize(fpath) < 50 * 1024 * 1024:  # <50MB
                        archive_findings = self.scan_archive(fpath)
                        all_findings.extend(archive_findings)

        logger.info(f"Total findings for {repo_name}: {len(all_findings)}")
        return all_findings


def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    seen = {}
    for ch in data:
        seen[ch] = seen.get(ch, 0) + 1
    for count in seen.values():
        p_x = count / length
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return entropy
