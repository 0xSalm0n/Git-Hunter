"""
SQLite database operations for scan state management.
"""

import sqlite3
import json
import os
import hashlib
import base64
from datetime import datetime, timezone
from typing import Any, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from ghrecon.utils.logger import get_logger

logger = get_logger("ghrecon.db")


class DatabaseManager:
    """SQLite database manager for GHRecon state and results."""

    def __init__(self, db_path: str = "ghrecon.db", encryption_key: Optional[str] = None):
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._fernet: Optional[Fernet] = None
        if encryption_key:
            self._init_encryption(encryption_key)

    def _init_encryption(self, key: str) -> None:
        salt = b"ghrecon_salt_v1"
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
        derived_key = base64.urlsafe_b64encode(kdf.derive(key.encode()))
        self._fernet = Fernet(derived_key)

    def encrypt_value(self, value: str) -> str:
        if self._fernet and value:
            return self._fernet.encrypt(value.encode()).decode()
        return value

    def decrypt_value(self, value: str) -> str:
        if self._fernet and value:
            try:
                return self._fernet.decrypt(value.encode()).decode()
            except Exception:
                return value
        return value

    @staticmethod
    def hash_secret(value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()

    def connect(self) -> None:
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def _init_schema(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY, target TEXT NOT NULL,
                target_type TEXT DEFAULT 'unknown', start_time TIMESTAMP NOT NULL,
                end_time TIMESTAMP, status TEXT DEFAULT 'running',
                repos_found INTEGER DEFAULT 0, repos_scanned INTEGER DEFAULT 0,
                repos_skipped INTEGER DEFAULT 0, secrets_found INTEGER DEFAULT 0,
                secrets_validated INTEGER DEFAULT 0, high_value_count INTEGER DEFAULT 0,
                config_snapshot TEXT, error_log TEXT
            );
            CREATE TABLE IF NOT EXISTS repositories (
                repo_id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL,
                url TEXT NOT NULL, full_name TEXT NOT NULL, name TEXT NOT NULL,
                owner TEXT NOT NULL, clone_status TEXT DEFAULT 'pending',
                clone_path TEXT, scan_status TEXT DEFAULT 'pending',
                is_fork BOOLEAN DEFAULT 0, is_archived BOOLEAN DEFAULT 0,
                size_mb REAL DEFAULT 0, last_push TIMESTAMP,
                default_branch TEXT DEFAULT 'main', languages TEXT,
                stars INTEGER DEFAULT 0, description TEXT,
                branches_scanned INTEGER DEFAULT 0, commits_scanned INTEGER DEFAULT 0,
                error_message TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            );
            CREATE TABLE IF NOT EXISTS secrets (
                secret_id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL,
                repo_id INTEGER NOT NULL, secret_type TEXT NOT NULL,
                secret_value TEXT, secret_hash TEXT NOT NULL,
                file_path TEXT, line_number INTEGER, commit_hash TEXT,
                commit_date TIMESTAMP, commit_author TEXT, branch TEXT,
                context TEXT, source TEXT DEFAULT 'regex', entropy REAL,
                engine TEXT DEFAULT 'regex',
                verified BOOLEAN DEFAULT 0,
                detector_name TEXT,
                validated BOOLEAN DEFAULT 0, validation_result TEXT,
                is_valid BOOLEAN, high_value BOOLEAN DEFAULT 0,
                privilege_level TEXT, false_positive BOOLEAN DEFAULT 0,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id),
                FOREIGN KEY (repo_id) REFERENCES repositories(repo_id)
            );
            CREATE TABLE IF NOT EXISTS rate_limits (
                token_hash TEXT PRIMARY KEY, remaining INTEGER DEFAULT 5000,
                reset_timestamp INTEGER DEFAULT 0,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS scan_progress (
                progress_id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL, phase TEXT NOT NULL,
                current_item TEXT, items_completed INTEGER DEFAULT 0,
                items_total INTEGER DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            );
            CREATE INDEX IF NOT EXISTS idx_secrets_validated ON secrets(validated, high_value);
            CREATE INDEX IF NOT EXISTS idx_secrets_scan ON secrets(scan_id);
            CREATE INDEX IF NOT EXISTS idx_secrets_repo ON secrets(repo_id);
            CREATE INDEX IF NOT EXISTS idx_secrets_type ON secrets(secret_type);
            CREATE INDEX IF NOT EXISTS idx_secrets_hash ON secrets(secret_hash);
            CREATE INDEX IF NOT EXISTS idx_secrets_engine ON secrets(engine);
            CREATE INDEX IF NOT EXISTS idx_secrets_verified ON secrets(verified);
            CREATE INDEX IF NOT EXISTS idx_repos_scan ON repositories(scan_id);
            CREATE INDEX IF NOT EXISTS idx_repos_status ON repositories(clone_status, scan_status);
            CREATE INDEX IF NOT EXISTS idx_progress_scan ON scan_progress(scan_id, phase);
        """)
        # Migrate existing databases — add new columns if missing
        for col, typedef in [
            ("engine", "TEXT DEFAULT 'regex'"),
            ("verified", "BOOLEAN DEFAULT 0"),
            ("detector_name", "TEXT"),
        ]:
            try:
                self._conn.execute(f"ALTER TABLE secrets ADD COLUMN {col} {typedef}")
            except Exception:
                pass  # Column already exists
        self._conn.commit()

    def create_scan(self, scan_id: str, target: str, target_type: str = "unknown",
                    config_snapshot: Optional[dict] = None) -> str:
        self._conn.execute(
            "INSERT INTO scans (scan_id, target, target_type, start_time, config_snapshot) VALUES (?, ?, ?, ?, ?)",
            (scan_id, target, target_type, datetime.now(timezone.utc).isoformat(),
             json.dumps(config_snapshot) if config_snapshot else None))
        self._conn.commit()
        return scan_id

    def update_scan(self, scan_id: str, **kwargs) -> None:
        allowed = {"end_time", "status", "repos_found", "repos_scanned", "repos_skipped",
                    "secrets_found", "secrets_validated", "high_value_count", "error_log"}
        fields = {k: v for k, v in kwargs.items() if k in allowed}
        if not fields:
            return
        set_clause = ", ".join(f"{k} = ?" for k in fields)
        self._conn.execute(f"UPDATE scans SET {set_clause} WHERE scan_id = ?",
                           list(fields.values()) + [scan_id])
        self._conn.commit()

    def get_scan(self, scan_id: str) -> Optional[dict]:
        row = self._conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        return dict(row) if row else None

    def get_latest_scan(self, target: Optional[str] = None) -> Optional[dict]:
        if target:
            row = self._conn.execute(
                "SELECT * FROM scans WHERE target = ? ORDER BY start_time DESC LIMIT 1", (target,)).fetchone()
        else:
            row = self._conn.execute("SELECT * FROM scans ORDER BY start_time DESC LIMIT 1").fetchone()
        return dict(row) if row else None

    def add_repository(self, scan_id: str, repo_data: dict) -> int:
        cursor = self._conn.execute(
            """INSERT INTO repositories (scan_id, url, full_name, name, owner, is_fork, is_archived,
               size_mb, last_push, default_branch, languages, stars, description)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, repo_data.get("url", ""), repo_data.get("full_name", ""),
             repo_data.get("name", ""), repo_data.get("owner", ""),
             repo_data.get("is_fork", False), repo_data.get("is_archived", False),
             repo_data.get("size_mb", 0), repo_data.get("last_push"),
             repo_data.get("default_branch", "main"),
             json.dumps(repo_data.get("languages", [])),
             repo_data.get("stars", 0), repo_data.get("description", "")))
        self._conn.commit()
        return cursor.lastrowid

    def update_repository(self, repo_id: int, **kwargs) -> None:
        allowed = {"clone_status", "clone_path", "scan_status", "branches_scanned",
                    "commits_scanned", "error_message"}
        fields = {k: v for k, v in kwargs.items() if k in allowed}
        if not fields:
            return
        set_clause = ", ".join(f"{k} = ?" for k in fields)
        self._conn.execute(f"UPDATE repositories SET {set_clause} WHERE repo_id = ?",
                           list(fields.values()) + [repo_id])
        self._conn.commit()

    def get_pending_repos(self, scan_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM repositories WHERE scan_id = ? AND clone_status = 'pending' ORDER BY stars DESC",
            (scan_id,)).fetchall()
        return [dict(r) for r in rows]

    def get_cloned_unscanned_repos(self, scan_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM repositories WHERE scan_id = ? AND clone_status = 'success' AND scan_status = 'pending'",
            (scan_id,)).fetchall()
        return [dict(r) for r in rows]

    def get_all_repos(self, scan_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM repositories WHERE scan_id = ? ORDER BY stars DESC", (scan_id,)).fetchall()
        return [dict(r) for r in rows]

    def repo_already_tracked(self, scan_id: str, full_name: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM repositories WHERE scan_id = ? AND full_name = ?",
            (scan_id, full_name)).fetchone()
        return row is not None

    def add_secret(self, scan_id: str, repo_id: int, secret_data: dict,
                   store_value: bool = True) -> Optional[int]:
        secret_value = secret_data.get("value", "")
        secret_hash = self.hash_secret(secret_value)
        existing = self._conn.execute(
            "SELECT 1 FROM secrets WHERE repo_id = ? AND secret_hash = ?",
            (repo_id, secret_hash)).fetchone()
        if existing:
            return None
        stored_value = self.encrypt_value(secret_value) if store_value else "[REDACTED]"
        cursor = self._conn.execute(
            """INSERT INTO secrets (scan_id, repo_id, secret_type, secret_value, secret_hash,
               file_path, line_number, commit_hash, commit_date, commit_author, branch,
               context, source, entropy, engine, verified, detector_name)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, repo_id, secret_data.get("type", "unknown"), stored_value, secret_hash,
             secret_data.get("file_path"), secret_data.get("line_number"),
             secret_data.get("commit_hash"), secret_data.get("commit_date"),
             secret_data.get("commit_author"), secret_data.get("branch"),
             secret_data.get("context", ""), secret_data.get("source", "regex"),
             secret_data.get("entropy"),
             secret_data.get("engine", "regex"),
             secret_data.get("verified", False),
             secret_data.get("detector_name", "")))
        self._conn.commit()
        return cursor.lastrowid

    def update_secret_validation(self, secret_id: int, validation_result: dict) -> None:
        self._conn.execute(
            """UPDATE secrets SET validated = 1, is_valid = ?, validation_result = ?,
               high_value = ?, privilege_level = ? WHERE secret_id = ?""",
            (validation_result.get("valid", False), json.dumps(validation_result),
             validation_result.get("high_value", False),
             validation_result.get("privilege_level", "unknown"), secret_id))
        self._conn.commit()

    def get_secrets(self, scan_id: str, validated_only: bool = False,
                    high_value_only: bool = False) -> list[dict]:
        query = "SELECT * FROM secrets WHERE scan_id = ? AND false_positive = 0"
        params: list[Any] = [scan_id]
        if validated_only:
            query += " AND validated = 1 AND is_valid = 1"
        if high_value_only:
            query += " AND high_value = 1"
        query += " ORDER BY high_value DESC, discovered_at ASC"
        rows = self._conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_unvalidated_secrets(self, scan_id: str) -> list[dict]:
        rows = self._conn.execute(
            """SELECT s.*, r.full_name as repo_name FROM secrets s
               JOIN repositories r ON s.repo_id = r.repo_id
               WHERE s.scan_id = ? AND s.validated = 0 AND s.false_positive = 0""",
            (scan_id,)).fetchall()
        return [dict(r) for r in rows]

    def get_secret_value(self, secret_id: int) -> Optional[str]:
        row = self._conn.execute(
            "SELECT secret_value FROM secrets WHERE secret_id = ?", (secret_id,)).fetchone()
        if row and row["secret_value"] != "[REDACTED]":
            return self.decrypt_value(row["secret_value"])
        return None

    def get_scan_stats(self, scan_id: str) -> dict:
        scan = self.get_scan(scan_id)
        if not scan:
            return {}
        repos_row = self._conn.execute(
            """SELECT COUNT(*) as total,
               SUM(CASE WHEN clone_status='success' THEN 1 ELSE 0 END) as cloned,
               SUM(CASE WHEN clone_status='failed' THEN 1 ELSE 0 END) as failed,
               SUM(CASE WHEN clone_status='skipped' THEN 1 ELSE 0 END) as skipped,
               SUM(CASE WHEN scan_status='complete' THEN 1 ELSE 0 END) as scanned
               FROM repositories WHERE scan_id = ?""", (scan_id,)).fetchone()
        secrets_row = self._conn.execute(
            """SELECT COUNT(*) as total,
               SUM(CASE WHEN validated=1 AND is_valid=1 THEN 1 ELSE 0 END) as valid,
               SUM(CASE WHEN validated=1 AND is_valid=0 THEN 1 ELSE 0 END) as invalid,
               SUM(CASE WHEN validated=0 THEN 1 ELSE 0 END) as unvalidated,
               SUM(CASE WHEN high_value=1 THEN 1 ELSE 0 END) as high_value
               FROM secrets WHERE scan_id = ? AND false_positive = 0""", (scan_id,)).fetchone()
        type_rows = self._conn.execute(
            """SELECT secret_type, COUNT(*) as count FROM secrets
               WHERE scan_id = ? AND false_positive = 0
               GROUP BY secret_type ORDER BY count DESC""", (scan_id,)).fetchall()
        return {"scan": dict(scan), "repositories": dict(repos_row),
                "secrets": dict(secrets_row),
                "by_type": {r["secret_type"]: r["count"] for r in type_rows}}

    def update_progress(self, scan_id: str, phase: str, current_item: str = "",
                        items_completed: int = 0, items_total: int = 0) -> None:
        existing = self._conn.execute(
            "SELECT progress_id FROM scan_progress WHERE scan_id = ? AND phase = ?",
            (scan_id, phase)).fetchone()
        if existing:
            self._conn.execute(
                """UPDATE scan_progress SET current_item = ?, items_completed = ?,
                   items_total = ?, updated_at = CURRENT_TIMESTAMP WHERE progress_id = ?""",
                (current_item, items_completed, items_total, existing["progress_id"]))
        else:
            self._conn.execute(
                "INSERT INTO scan_progress (scan_id, phase, current_item, items_completed, items_total) VALUES (?, ?, ?, ?, ?)",
                (scan_id, phase, current_item, items_completed, items_total))
        self._conn.commit()

    def update_rate_limit(self, token_hash: str, remaining: int, reset_ts: int) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO rate_limits (token_hash, remaining, reset_timestamp, last_updated) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
            (token_hash, remaining, reset_ts))
        self._conn.commit()
