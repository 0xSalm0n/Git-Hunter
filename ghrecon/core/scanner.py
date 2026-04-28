"""
Secret detection engine with regex patterns, entropy analysis, and multi-zone scanning.

Memory-efficient implementation: streaming git log, single-pass scanning,
bounded archive handling, and runtime memory pressure monitoring.
"""

import gc
import os
import re
import io
import math
import hashlib
import asyncio
import zipfile
import tarfile
from typing import Optional, Generator
from datetime import datetime, timezone

import psutil
import yaml

from ghrecon.utils.logger import get_logger
from ghrecon.config import GHReconConfig

logger = get_logger("ghrecon.scanner")

# ---------------------------------------------------------------------------
# Memory helpers
# ---------------------------------------------------------------------------

# Hard ceiling: if process RSS exceeds this, aggressive GC + skip heavy ops
_MEMORY_HARD_LIMIT_MB = int(os.environ.get("GHRECON_MEM_LIMIT_MB", "1500"))
# Soft ceiling: trigger GC and log a warning
_MEMORY_SOFT_LIMIT_MB = int(_MEMORY_HARD_LIMIT_MB * 0.75)


def get_memory_mb() -> float:
    """Return current process RSS in MB."""
    try:
        return psutil.Process().memory_info().rss / (1024 * 1024)
    except Exception:
        return 0.0


def _check_memory(label: str = "") -> bool:
    """Check memory pressure. Returns True if under hard limit."""
    mem = get_memory_mb()
    if mem > _MEMORY_HARD_LIMIT_MB:
        logger.error(f"MEMORY HARD LIMIT ({mem:.0f}MB > {_MEMORY_HARD_LIMIT_MB}MB) at {label}")
        gc.collect()
        return False
    if mem > _MEMORY_SOFT_LIMIT_MB:
        logger.warning(f"Memory pressure ({mem:.0f}MB) at {label} — running GC")
        gc.collect()
    return True


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

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

# Max file size to read into memory (2 MB)
_MAX_FILE_BYTES = 2 * 1024 * 1024
# Max archive entry size to scan in-memory (1 MB)
_MAX_ARCHIVE_ENTRY_BYTES = 1 * 1024 * 1024
# Max total extracted bytes from a single archive
_MAX_ARCHIVE_TOTAL_BYTES = 50 * 1024 * 1024
# Streaming buffer for git log (read this many bytes at a time)
_GIT_LOG_CHUNK = 64 * 1024


class SecretScanner:
    """Multi-zone secret detection engine with memory-efficient scanning."""

    def __init__(self, config: GHReconConfig, custom_patterns: Optional[dict] = None):
        self.config = config
        self.patterns = {**SECRET_PATTERNS}
        if custom_patterns:
            self.patterns.update(custom_patterns)
        self._compiled = {name: re.compile(pat) for name, pat in self.patterns.items()}
        self._seen_hashes: set[str] = set()
        # Entropy string extractor (compiled once)
        self._entropy_re = re.compile(
            r"""['"]([\\w+/=@.:-]{16,})['"]|[:=]\s*[\s'"]*([A-Za-z0-9+/=_-]{20,})"""
        )
        # Stats
        self.files_scanned = 0
        self.files_skipped = 0
        self.bytes_scanned = 0

    @classmethod
    def with_patterns_file(cls, config: GHReconConfig, patterns_path: str) -> "SecretScanner":
        """Create scanner with additional patterns from a YAML file."""
        custom = {}
        if os.path.exists(patterns_path):
            with open(patterns_path) as f:
                data = yaml.safe_load(f) or {}
                custom = data.get("patterns", {})
        return cls(config, custom)

    # ------------------------------------------------------------------
    # Core text scanning
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Single-file scan (with size guard)
    # ------------------------------------------------------------------

    def scan_file(self, file_path: str, branch: str = "",
                  also_entropy: bool = False) -> list[dict]:
        """Scan a single file for secrets, optionally including entropy scan.

        Combines regex + entropy in a single read to avoid duplicate I/O.
        """
        ext = os.path.splitext(file_path)[1].lower()
        if ext in SKIP_EXTENSIONS:
            self.files_skipped += 1
            return []

        try:
            fsize = os.path.getsize(file_path)
            if fsize > _MAX_FILE_BYTES:
                self.files_skipped += 1
                return []

            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            self.files_scanned += 1
            self.bytes_scanned += len(content)

            findings = self.scan_text(content, file_path=file_path, branch=branch)

            if also_entropy:
                findings.extend(self.entropy_scan(content, file_path=file_path))

            # Release content immediately
            del content
            return findings

        except (OSError, PermissionError) as e:
            logger.warning(f"Cannot read {file_path}: {e}")
            return []

    # ------------------------------------------------------------------
    # Directory scan — single pass (regex + entropy), memory-aware
    # ------------------------------------------------------------------

    _SKIP_DIRS = frozenset({
        ".git", "node_modules", "vendor", "venv", "__pycache__",
        ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
        ".eggs", ".venv", "env", ".env",
    })

    def scan_directory(self, dir_path: str, branch: str = "") -> list[dict]:
        """Recursively scan a directory — single pass with memory guards."""
        findings = []
        file_count = 0

        for root, dirs, files in os.walk(dir_path):
            dirs[:] = [d for d in dirs if d not in self._SKIP_DIRS]

            for filename in files:
                # Periodic memory check every 200 files
                file_count += 1
                if file_count % 200 == 0:
                    if not _check_memory(f"dir_scan file #{file_count}"):
                        logger.error("Aborting directory scan due to memory pressure")
                        return findings

                filepath = os.path.join(root, filename)
                # Combined regex + entropy in single read
                file_findings = self.scan_file(
                    filepath, branch=branch, also_entropy=True
                )
                findings.extend(file_findings)

        return findings

    # ------------------------------------------------------------------
    # Streaming commit history scan (memory-efficient)
    # ------------------------------------------------------------------

    async def scan_commit_history(self, repo_path: str,
                                    max_commits: int = 500) -> list[dict]:
        """Scan commit diffs for secrets using streaming line-by-line reads.

        Instead of buffering the entire ``git log -p`` output (which can be
        hundreds of MB for large repos), we read the subprocess stdout line
        by line and parse/scan incrementally.
        """
        findings = []
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                "git", "-C", repo_path, "log", "-p",
                f"-n{max_commits}", "--all", "--diff-filter=ACMR",
                "--pretty=format:COMMIT_SEP|%H|%an|%aI",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            )

            commit_hash = ""
            author = ""
            date = ""
            current_file = ""
            commits_processed = 0

            async for raw_line in proc.stdout:
                line = raw_line.decode(errors="replace").rstrip("\n").rstrip("\r")

                if line.startswith("COMMIT_SEP|"):
                    commits_processed += 1
                    # Memory check every 50 commits
                    if commits_processed % 50 == 0:
                        if not _check_memory(f"history commit #{commits_processed}"):
                            logger.error("Aborting history scan due to memory")
                            break

                    rest = line[len("COMMIT_SEP|"):]
                    parts = rest.split("|", 2)
                    commit_hash = parts[0] if parts else ""
                    author = parts[1] if len(parts) > 1 else ""
                    date = parts[2] if len(parts) > 2 else ""
                    current_file = ""
                    continue

                if line.startswith("+++ b/"):
                    current_file = line[6:]
                    continue

                if line.startswith("+") and not line.startswith("+++"):
                    added_text = line[1:]
                    if len(added_text) > 5000:
                        continue
                    line_findings = self.scan_text(
                        added_text, file_path=current_file,
                        commit_hash=commit_hash, commit_author=author,
                        commit_date=date,
                    )
                    findings.extend(line_findings)

        except asyncio.TimeoutError:
            logger.warning("Commit history scan timed out")
        except Exception as e:
            logger.warning(f"Commit history scan failed: {e}")
        finally:
            if proc and proc.returncode is None:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass

        return findings

    # ------------------------------------------------------------------
    # Commit message scan (already lightweight)
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Memory-efficient archive scan (streaming, no full extraction)
    # ------------------------------------------------------------------

    def scan_archive(self, archive_path: str) -> list[dict]:
        """Scan archive entries in-memory without full disk extraction.

        Each entry is read individually, size-checked, scanned, then freed.
        """
        findings = []
        total_bytes_read = 0

        try:
            if archive_path.endswith(".zip"):
                findings = self._scan_zip_streaming(archive_path)
            elif archive_path.endswith((".tar", ".tar.gz", ".tgz")):
                findings = self._scan_tar_streaming(archive_path)
        except Exception as e:
            logger.warning(f"Archive scan failed for {archive_path}: {e}")

        return findings

    def _scan_zip_streaming(self, archive_path: str) -> list[dict]:
        """Stream-scan a zip archive entry by entry."""
        findings = []
        total_read = 0

        try:
            with zipfile.ZipFile(archive_path, "r") as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    # Skip oversized entries
                    if info.file_size > _MAX_ARCHIVE_ENTRY_BYTES:
                        continue
                    # Skip binary extensions
                    ext = os.path.splitext(info.filename)[1].lower()
                    if ext in SKIP_EXTENSIONS:
                        continue
                    # Enforce total budget
                    total_read += info.file_size
                    if total_read > _MAX_ARCHIVE_TOTAL_BYTES:
                        logger.info(f"Archive budget exhausted for {archive_path}")
                        break

                    if not _check_memory("zip_entry"):
                        break

                    try:
                        data = zf.read(info.filename)
                        text = data.decode("utf-8", errors="ignore")
                        del data
                        entry_findings = self.scan_text(
                            text, file_path=f"[archive:{archive_path}]/{info.filename}"
                        )
                        findings.extend(entry_findings)
                        del text
                    except Exception:
                        continue
        except zipfile.BadZipFile:
            logger.warning(f"Bad zip file: {archive_path}")

        return findings

    def _scan_tar_streaming(self, archive_path: str) -> list[dict]:
        """Stream-scan a tar archive entry by entry."""
        findings = []
        total_read = 0

        try:
            with tarfile.open(archive_path, "r:*") as tf:
                for member in tf:
                    if not member.isfile():
                        continue
                    if member.size > _MAX_ARCHIVE_ENTRY_BYTES:
                        continue
                    ext = os.path.splitext(member.name)[1].lower()
                    if ext in SKIP_EXTENSIONS:
                        continue
                    total_read += member.size
                    if total_read > _MAX_ARCHIVE_TOTAL_BYTES:
                        logger.info(f"Archive budget exhausted for {archive_path}")
                        break

                    if not _check_memory("tar_entry"):
                        break

                    try:
                        fobj = tf.extractfile(member)
                        if fobj is None:
                            continue
                        data = fobj.read()
                        fobj.close()
                        text = data.decode("utf-8", errors="ignore")
                        del data
                        entry_findings = self.scan_text(
                            text, file_path=f"[archive:{archive_path}]/{member.name}"
                        )
                        findings.extend(entry_findings)
                        del text
                    except Exception:
                        continue
        except (tarfile.TarError, EOFError):
            logger.warning(f"Bad tar file: {archive_path}")

        return findings

    # ------------------------------------------------------------------
    # Entropy scan
    # ------------------------------------------------------------------

    def entropy_scan(self, text: str, file_path: str = "") -> list[dict]:
        """Find high-entropy strings near sensitive keywords."""
        findings = []
        lines = text.split("\n")

        for line_num, line in enumerate(lines, 1):
            if len(line) > 2000:
                continue

            for match in self._entropy_re.finditer(line):
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

    # ------------------------------------------------------------------
    # Full repo scan — memory-aware orchestrator
    # ------------------------------------------------------------------

    async def full_repo_scan(self, repo_path: str, repo_name: str = "") -> list[dict]:
        """Perform a comprehensive scan of a repository.

        Key memory optimisations vs. the original:
        1. Directory + entropy scan combined into a single walk (no duplicate I/O).
        2. Commit history scanned via streaming (no full stdout buffer).
        3. Memory pressure checked between each phase and periodically during scans.
        4. Archives scanned entry-by-entry without full extraction.
        5. Explicit GC between phases.
        """
        all_findings = []
        mem_start = get_memory_mb()
        logger.info(f"Starting full scan: {repo_name or repo_path} (mem: {mem_start:.0f}MB)")

        # 1. Single-pass directory scan (regex + entropy combined)
        if _check_memory("pre_dir_scan"):
            dir_findings = self.scan_directory(repo_path)
            all_findings.extend(dir_findings)
            logger.info(f"  Directory scan: {len(dir_findings)} findings "
                        f"({self.files_scanned} files, {self.bytes_scanned / 1024 / 1024:.1f}MB read)")
            del dir_findings
            gc.collect()

        # 2. Streaming commit history scan
        if _check_memory("pre_history_scan"):
            history_findings = await self.scan_commit_history(repo_path)
            all_findings.extend(history_findings)
            logger.info(f"  History scan: {len(history_findings)} findings")
            del history_findings
            gc.collect()

        # 3. Commit message scan
        if _check_memory("pre_msg_scan"):
            msg_findings = await self.scan_commit_messages(repo_path)
            all_findings.extend(msg_findings)
            del msg_findings

        # 4. Archive scan (streaming, no full extraction)
        if _check_memory("pre_archive_scan"):
            for root, _, files in os.walk(repo_path):
                for fname in files:
                    if fname.endswith((".zip", ".tar", ".tar.gz", ".tgz")):
                        fpath = os.path.join(root, fname)
                        try:
                            if os.path.getsize(fpath) < 50 * 1024 * 1024:
                                if not _check_memory("archive"):
                                    break
                                archive_findings = self.scan_archive(fpath)
                                all_findings.extend(archive_findings)
                                del archive_findings
                        except OSError:
                            pass

        mem_end = get_memory_mb()
        logger.info(f"Total findings for {repo_name}: {len(all_findings)} "
                     f"(mem: {mem_start:.0f}MB -> {mem_end:.0f}MB)")
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
