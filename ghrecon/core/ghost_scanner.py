"""
Ghost Commit Scanner — Scan dangling commits from GitHub Archive force-push events.

GitHub Archive logs every public commit, including those developers try to
delete via force pushes.  When history is rewritten, the original "before"
commits become dangling — unreachable from any branch but still fetchable by
SHA.  In the archive these appear as "zero-commit" PushEvents (size == 0).

This module:
  1. Ingests force-push event data from a SQLite DB or CSV file.
  2. Reports a summary (repos impacted, total commits, yearly histogram).
  3. Optionally scans each dangling commit for leaked secrets using
     TruffleHog in ``git`` mode (partial-clone, no blobs).

Usage (via CLI):
    python ghrecon.py ghost myorg --db-file pushes.db
    python ghrecon.py ghost myorg --db-file pushes.db --scan
    python ghrecon.py ghost myorg --events-file events.csv --scan
"""

from __future__ import annotations

import csv
import json
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import datetime as _dt
from collections import Counter, defaultdict
from contextlib import suppress
from datetime import timezone
from pathlib import Path
from typing import Dict, List, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from ghrecon.utils.logger import get_logger

logger = get_logger("ghrecon.ghost_scanner")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")
_EXPECTED_FIELDS = {"repo_org", "repo_name", "before", "timestamp"}

console = Console(force_terminal=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_year(date_val) -> str:
    """Return the four-digit year (YYYY) from a Unix epoch int."""
    return _dt.datetime.fromtimestamp(int(date_val), tz=timezone.utc).strftime("%Y")


def _run_git(cmd: List[str], cwd: Path | None = None) -> str:
    """Execute *cmd* and return stdout.  Raises ``RuntimeError`` on failure."""
    logger.debug("Running: %s (cwd=%s)", " ".join(cmd), cwd or ".")
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
            env=env,
        )
        return proc.stdout
    except subprocess.CalledProcessError as err:
        raise RuntimeError(
            f"Command failed ({err.returncode}): {' '.join(cmd)}\n"
            f"{err.stderr.strip()}"
        ) from err


def _scan_with_trufflehog(
    repo_path: Path, since_commit: str, branch: str
) -> List[dict]:
    """Run TruffleHog in *git* mode against a specific commit range.

    Uses ``--branch <before_sha>`` and ``--since-commit <base_sha>`` so only
    the orphaned diff is scanned.
    """
    trufflehog_bin = shutil.which("trufflehog") or shutil.which("trufflehog.exe")
    if not trufflehog_bin:
        console.print("[red][✗] TruffleHog not found on PATH — cannot scan[/]")
        return []

    cmd = [
        trufflehog_bin,
        "git",
        "--branch", branch,
        "--since-commit", since_commit,
        "--no-update",
        "--json",
        "--only-verified",
        "file://" + str(repo_path.absolute()),
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=600,
        )
        findings: List[dict] = []
        for line in result.stdout.splitlines():
            with suppress(json.JSONDecodeError):
                findings.append(json.loads(line))
        return findings
    except subprocess.TimeoutExpired:
        console.print("[yellow]  ⚠ TruffleHog timed out for this commit — skipping[/]")
        return []
    except Exception as exc:
        console.print(f"[yellow]  ⚠ TruffleHog error: {exc} — skipping[/]")
        return []


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _validate_row(input_org: str, row: dict, idx: int):
    """Validate a single data row.  Returns (repo_org, repo_name, before, ts)."""
    missing = _EXPECTED_FIELDS - row.keys()
    if missing:
        raise ValueError(f"Row {idx} is missing fields: {', '.join(sorted(missing))}")

    repo_org = str(row["repo_org"]).strip()
    repo_name = str(row["repo_name"]).strip()
    before = str(row["before"]).strip()
    ts = row["timestamp"]

    if not repo_org:
        raise ValueError(f"Row {idx} — 'repo_org' is empty")
    if repo_org != input_org:
        raise ValueError(
            f"Row {idx} — 'repo_org' does not match target: {repo_org} != {input_org}"
        )
    if not repo_name:
        raise ValueError(f"Row {idx} — 'repo_name' is empty")
    if not _SHA_RE.fullmatch(before):
        raise ValueError(f"Row {idx} — 'before' does not look like a commit SHA: {before}")

    try:
        ts_int = int(ts)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Row {idx} — 'timestamp' must be int, got {ts!r}") from exc

    return repo_org, repo_name, before, ts_int


# ---------------------------------------------------------------------------
# GhostCommitScanner
# ---------------------------------------------------------------------------

class GhostCommitScanner:
    """Scan dangling commits from GitHub Archive force-push events."""

    def __init__(self, target_org: str):
        self.target_org = target_org

    # ------------------------------------------------------------------
    # Phase 1: Gather data
    # ------------------------------------------------------------------

    def gather_commits(
        self,
        events_file: Optional[Path] = None,
        db_file: Optional[Path] = None,
    ) -> Dict[str, List[dict]]:
        """Load force-push events and return ``{repo_url: [{before, date}]}``.

        Exactly one of *events_file* (CSV) or *db_file* (SQLite) must be provided.
        Both sources must expose columns: ``repo_org, repo_name, before, timestamp``.
        """
        if events_file is not None:
            rows = self._load_csv(events_file)
        elif db_file is not None:
            rows = self._load_sqlite(db_file)
        else:
            console.print("[red][✗] You must supply --db-file or --events-file.[/]")
            raise SystemExit(1)

        return self._rows_to_repos(rows)

    def _load_csv(self, path: Path) -> List[dict]:
        if not path.exists():
            console.print(f"[red][✗] Events file not found: {path}[/]")
            raise SystemExit(1)
        try:
            with path.open("r", encoding="utf-8", newline="") as fh:
                reader = csv.DictReader(fh)
                return list(reader)
        except Exception as exc:
            console.print(f"[red][✗] Failed to parse CSV {path}: {exc}[/]")
            raise SystemExit(1)

    def _load_sqlite(self, path: Path) -> List[dict]:
        if not path.exists():
            console.print(f"[red][✗] SQLite database not found: {path}[/]")
            raise SystemExit(1)
        try:
            with sqlite3.connect(str(path)) as conn:
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT repo_org, repo_name, before, timestamp
                    FROM pushes
                    WHERE repo_org = ?
                    """,
                    (self.target_org,),
                )
                return [dict(r) for r in cur.fetchall()]
        except Exception as exc:
            console.print(f"[red][✗] Failed querying SQLite DB {path}: {exc}[/]")
            raise SystemExit(1)

    def _rows_to_repos(self, rows: List[dict]) -> Dict[str, List[dict]]:
        repos: Dict[str, List[dict]] = defaultdict(list)
        for idx, row in enumerate(rows, 1):
            try:
                repo_org, repo_name, before, ts_int = _validate_row(
                    self.target_org, row, idx
                )
            except ValueError as ve:
                console.print(f"[red][✗] {ve}[/]")
                raise SystemExit(1)

            url = f"https://github.com/{repo_org}/{repo_name}"
            repos[url].append({"before": before, "date": ts_int})

        if not repos:
            console.print(
                f"[yellow][!] No force-push events found for '{self.target_org}' "
                f"— dataset is empty.[/]"
            )
            raise SystemExit(0)

        return repos

    # ------------------------------------------------------------------
    # Phase 2: Report
    # ------------------------------------------------------------------

    def report(self, repos: Dict[str, List[dict]]) -> None:
        """Print a Rich-formatted summary of force-push events."""
        repo_count = len(repos)
        total_commits = sum(len(v) for v in repos.values())

        # --- Header panel ---
        console.print()
        console.print(Panel(
            f"[bold white]Force-Push Ghost Commit Summary for "
            f"[cyan]{self.target_org}[/cyan][/bold white]",
            border_style="cyan",
            padding=(0, 2),
        ))

        # --- Stats table ---
        stats_table = Table(show_header=False, box=None, padding=(0, 2))
        stats_table.add_column("Metric", style="dim")
        stats_table.add_column("Value", style="bold green")
        stats_table.add_row("Repos Impacted", str(repo_count))
        stats_table.add_row("Total Dangling Commits", str(total_commits))
        console.print(stats_table)
        console.print()

        # --- Per-repo breakdown ---
        repo_table = Table(
            title="Commits per Repository",
            show_header=True,
            header_style="bold cyan",
        )
        repo_table.add_column("Repository", style="yellow")
        repo_table.add_column("Commits", justify="right", style="bold")

        for repo_url, commits in sorted(repos.items(), key=lambda x: -len(x[1])):
            repo_table.add_row(repo_url, str(len(commits)))
        console.print(repo_table)
        console.print()

        # --- Yearly histogram ---
        counter = Counter(
            _to_year(c["date"]) for commits in repos.values() for c in commits
        )

        first_year = int(min(counter)) if counter else _dt.date.today().year
        current_year = _dt.date.today().year

        console.print("[bold cyan]Yearly Histogram[/bold cyan]")
        for year in range(first_year, current_year + 1):
            year_key = f"{year:04d}"
            count = counter.get(year_key, 0)
            bar = "▇" * min(count, 50)
            if count > 0:
                console.print(f"  [green]{year_key}[/green] │ {bar} {count}")
            else:
                console.print(f"  [dim]{year_key}[/dim] │ ")

        console.print("[cyan]" + "═" * 50 + "[/cyan]\n")

    # ------------------------------------------------------------------
    # Phase 3: Scan dangling commits
    # ------------------------------------------------------------------

    def scan_commits(self, repos: Dict[str, List[dict]]) -> None:
        """Clone each repo (partial, no blobs), fetch dangling commits,
        identify the base commit, and run TruffleHog on the orphaned range.
        """
        # Pre-flight: ensure git and trufflehog are available
        for tool in ("git", "trufflehog"):
            if shutil.which(tool) is None:
                console.print(
                    f"[red][✗] Required tool '{tool}' not found on PATH — aborting scan.[/]"
                )
                raise SystemExit(1)

        total_findings = 0

        for repo_url, commits in repos.items():
            console.print(f"\n[bold yellow]▶[/bold yellow] Scanning repo: [cyan]{repo_url}[/cyan]")

            commit_counter = 0
            skipped_repo = False

            tmp_dir = tempfile.mkdtemp(prefix="ghrecon-ghost-")
            try:
                tmp_path = Path(tmp_dir)

                # Partial clone — no blobs, no checkout (fast + small)
                try:
                    _run_git(
                        [
                            "git", "clone",
                            "--filter=blob:none",
                            "--no-checkout",
                            repo_url + ".git",
                            ".",
                        ],
                        cwd=tmp_path,
                    )
                except RuntimeError as err:
                    console.print(
                        f"  [red][✗] git clone failed: {err} — skipping repo[/]"
                    )
                    skipped_repo = True
                    continue

                for c in commits:
                    before = c["before"]
                    if not _SHA_RE.fullmatch(before):
                        console.print(
                            f"  [dim]• Commit {before} — invalid SHA, skipping[/dim]"
                        )
                        continue

                    commit_counter += 1
                    console.print(f"  [dim]• Commit[/dim] [white]{before}[/white]")

                    try:
                        since_commit = self._identify_base_commit(tmp_path, before)
                    except RuntimeError as err:
                        err_str = str(err)
                        if "not our ref" in err_str:
                            console.print(
                                "    [yellow]↳ Commit was manually removed from "
                                "the repository network — skipping[/yellow]"
                            )
                        else:
                            console.print(
                                f"    [yellow]↳ fetch failed: {err_str[:120]} — skipping[/yellow]"
                            )
                        continue

                    # Scan the orphaned range with TruffleHog
                    findings = _scan_with_trufflehog(
                        tmp_path, since_commit=since_commit, branch=before
                    )

                    if findings:
                        total_findings += len(findings)
                        for f in findings:
                            self._print_finding(f, repo_url)

            finally:
                try:
                    shutil.rmtree(tmp_dir, ignore_errors=True)
                except OSError:
                    console.print(
                        f"    [dim]⚠ Error cleaning up temp dir: {tmp_dir}[/dim]"
                    )

            if skipped_repo:
                console.print("  [red][!] Repo skipped due to earlier errors[/]")
            else:
                console.print(
                    f"  [green][✓][/green] {commit_counter} commit(s) scanned"
                )

        # Final summary
        console.print()
        if total_findings > 0:
            console.print(Panel(
                f"[bold red]🔑 {total_findings} VERIFIED SECRET"
                f"{'S' if total_findings > 1 else ''} FOUND IN GHOST COMMITS![/bold red]\n"
                "[dim]These credentials were leaked in force-pushed commits that "
                "developers tried to delete.\nRotate them immediately.[/dim]",
                border_style="red",
            ))
        else:
            console.print(
                "[green][✓][/green] Scan complete — no verified secrets found "
                "in ghost commits."
            )

    # ------------------------------------------------------------------
    # Internal: identify base commit
    # ------------------------------------------------------------------

    def _identify_base_commit(self, repo_path: Path, since_commit: str) -> str:
        """Find the base commit for TruffleHog's ``--since-commit`` flag.

        Strategy:
        1. Fetch the dangling ``since_commit`` (partial clone missed it).
        2. Walk ``git rev-list <since_commit>`` backwards.
        3. The first commit that is reachable from *any* branch is our base.
        4. If the base equals ``since_commit``, step back one commit so
           TruffleHog scans the commit itself.
        5. If nothing is reachable, return ``""`` (scan the entire range).
        """
        # Fetch the dangling commit object (blobs fetched lazily by TruffleHog)
        _run_git(["git", "fetch", "origin", since_commit], cwd=repo_path)

        # Get all commits reachable from the dangling commit
        output = _run_git(["git", "rev-list", since_commit], cwd=repo_path)

        for commit in output.splitlines():
            commit = commit.strip()
            if not commit:
                continue

            # Check if this commit exists in any branch
            branch_output = _run_git(
                ["git", "branch", "--contains", commit, "--all"], cwd=repo_path
            )

            if branch_output.strip():
                if commit != since_commit:
                    return commit
                # since_commit itself is in a branch — step back one
                try:
                    parent = _run_git(
                        ["git", "rev-list", commit + "~1", "-n", "1"],
                        cwd=repo_path,
                    )
                    return parent.strip()
                except RuntimeError:
                    # No parent (root commit) — scan everything
                    return ""

        # No commit in any branch — orphaned tree, scan everything
        return ""

    # ------------------------------------------------------------------
    # Internal: pretty-print a finding
    # ------------------------------------------------------------------

    def _print_finding(self, finding: dict, repo_url: str) -> None:
        """Rich-formatted output for a single TruffleHog verified finding."""
        git_meta = (
            finding.get("SourceMetadata", {}).get("Data", {}).get("Git", {})
        )
        raw_val = finding.get("Raw") or finding.get("RawV2", "")
        commit_sha = git_meta.get("commit", "")

        lines = [
            f"[bold green]✅ Found verified result 🐷🔑[/bold green]",
            f"[green]Detector Type:[/green] {finding.get('DetectorName', 'N/A')}",
            f"[green]Decoder Type:[/green]  {finding.get('DecoderName', 'N/A')}",
            f"[green]Raw result:[/green]    {raw_val}",
            f"[green]Repository:[/green]    {repo_url}.git",
            f"[green]Commit:[/green]        {commit_sha}",
            f"[green]Email:[/green]         {git_meta.get('email', 'unknown')}",
            f"[green]File:[/green]          {git_meta.get('file', '')}",
            f"[green]Link:[/green]          {repo_url}/commit/{commit_sha}",
            f"[green]Timestamp:[/green]     {git_meta.get('timestamp', '')}",
        ]

        # Flatten extra metadata
        extra = finding.get("ExtraData") or {}
        for k, v in extra.items():
            key_str = str(k).replace("_", " ").title()
            lines.append(f"[green]{key_str}:[/green] {v}")

        console.print(Panel(
            "\n".join(lines),
            border_style="green",
            title="[bold]Verified Secret[/bold]",
            title_align="left",
        ))
