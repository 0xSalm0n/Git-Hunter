"""
GHRecon CLI interface using Typer with Rich output.
"""

import gc
import os
import sys
import asyncio
import random
import shutil
from datetime import datetime, timezone
from typing import Optional

# Fix Windows console encoding
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.live import Live
from rich import print as rprint

from ghrecon import __version__
from ghrecon.config import load_config, GHReconConfig
from ghrecon.utils.logger import setup_logger, get_logger
from ghrecon.utils.db import DatabaseManager
from ghrecon.utils.token_pool import TokenPool
from ghrecon.utils.proxy import ProxyManager
from ghrecon.core.enumerator import GitHubEnumerator
from ghrecon.core.cloner import AsyncCloner
from ghrecon.core.scanner import SecretScanner
from ghrecon.core.validator import SecretValidator
from ghrecon.core.analyzer import Analyzer
from ghrecon.reporting.json_report import generate_json_report
from ghrecon.reporting.markdown_report import generate_markdown_report
from ghrecon.reporting.csv_report import generate_csv_report

app = typer.Typer(
    name="ghrecon",
    help="GitHub Secret Reconnaissance Engine -- Automated credential extraction and validation",
    add_completion=False,
)
console = Console(force_terminal=True)


def _generate_scan_id(target: str) -> str:
    """Generate a unique scan ID."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_target = "".join(c if c.isalnum() else "_" for c in target)[:30]
    return f"{ts}_{safe_target}"


def _print_banner():
    """Display the GHRecon banner."""
    console.print("[bold cyan]" + "=" * 58 + "[/]")
    console.print("  [bold white]GHRecon -- GitHub Secret Reconnaissance Engine[/]")
    console.print(f"  [dim]v{__version__} -- Credential Extraction & Validation[/]")
    console.print("[bold cyan]" + "=" * 58 + "[/]")


async def _run_scan(config: GHReconConfig, target: str, target_type: str,
                     scan_id: str, resume: bool = False):
    """Core scan execution logic."""
    log = setup_logger(
        log_file=os.path.join(config.output.directory, f"{scan_id}.log"),
        json_console=False
    )

    # Initialize database
    db_path = os.path.join(config.output.directory, config.output.database)
    db = DatabaseManager(
        db_path=db_path,
        encryption_key=config.output.encryption_key
    )
    db.connect()

    if not resume:
        db.create_scan(scan_id, target, target_type)
    else:
        existing = db.get_scan(scan_id)
        if not existing:
            console.print(f"[red]Scan {scan_id} not found in database![/]")
            return

    # Initialize token pool
    tokens = config.github.tokens
    if not tokens and config.github.tokens_file:
        with open(config.github.tokens_file) as f:
            tokens = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    if not tokens:
        token_env = os.environ.get("GITHUB_TOKEN", "")
        if token_env:
            tokens = [token_env]
    if not tokens:
        console.print("[red]No GitHub tokens configured! Set GITHUB_TOKEN or use --tokens[/]")
        db.update_scan(scan_id, status="failed", error_log="No tokens configured")
        db.close()
        return

    token_pool = TokenPool(tokens)
    console.print(f"[green][+][/] Token pool: {token_pool.active_count} tokens loaded")

    # Initialize proxy manager
    proxy_mgr = None
    if config.stealth.enabled and config.stealth.proxy_list:
        proxy_mgr = ProxyManager.from_file(config.stealth.proxy_list)
        if proxy_mgr.has_proxies:
            console.print(f"[green][+][/] Proxy pool: {proxy_mgr.active_count} proxies loaded")

    clone_base = os.path.join(config.output.directory, scan_id, "repos")
    os.makedirs(clone_base, exist_ok=True)

    try:
        # --- Phase 1: Enumeration ---
        console.print(f"\n[bold yellow]>> Phase 1:[/] Enumerating repositories for [cyan]{target}[/]...")

        if not resume or not db.get_all_repos(scan_id):
            async with GitHubEnumerator(config, token_pool) as enumerator:
                repos = await enumerator.enumerate(target, target_type)

            db.update_scan(scan_id, repos_found=len(repos))
            console.print(f"[green][+][/] Found {len(repos)} repositories (after filtering)")

            # Store repos in DB
            for repo in repos:
                if not db.repo_already_tracked(scan_id, repo["full_name"]):
                    db.add_repository(scan_id, repo)

            db.update_progress(scan_id, "enumeration", items_completed=len(repos), items_total=len(repos))
        else:
            repos_data = db.get_all_repos(scan_id)
            repos = repos_data
            console.print(f"[yellow]~[/] Resuming with {len(repos)} enumerated repos")

        # --- Phase 2: Cloning ---
        console.print(f"\n[bold yellow]>> Phase 2:[/] Cloning repositories...")

        cloner = AsyncCloner(config, proxy_mgr)
        pending = db.get_pending_repos(scan_id)

        if pending:
            with Progress(
                SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                BarColumn(), TaskProgressColumn(), console=console
            ) as progress:
                task = progress.add_task("Cloning...", total=len(pending))

                clone_results = await cloner.clone_repos_parallel(pending, clone_base)

                for result in clone_results:
                    full_name = result.get("full_name", "")
                    matching = [r for r in pending if r.get("full_name") == full_name]
                    if matching:
                        repo_id = matching[0]["repo_id"]
                        status = "success" if result.get("success") else "failed"
                        db.update_repository(
                            repo_id, clone_status=status,
                            clone_path=result.get("path", "")
                        )
                    progress.advance(task)

            success = sum(1 for r in clone_results if r.get("success"))
            console.print(f"[green][+][/] Cloned {success}/{len(pending)} repositories")
            db.update_scan(scan_id, repos_scanned=success)
        else:
            console.print("[yellow]~[/] All repos already cloned (resume mode)")

        # --- Phase 3: Secret Scanning (memory-tracked) ---
        console.print(f"\n[bold yellow]>> Phase 3:[/] Scanning for secrets...")

        from ghrecon.core.scanner import get_memory_mb, _MEMORY_HARD_LIMIT_MB

        scanner = SecretScanner(config)
        unscanned = db.get_cloned_unscanned_repos(scan_id)
        total_findings = 0
        store_value = not config.output.no_store_secrets

        mem_before = get_memory_mb()
        console.print(f"[dim]  Memory at scan start: {mem_before:.0f} MB "
                       f"(hard limit: {_MEMORY_HARD_LIMIT_MB} MB)[/]")

        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            BarColumn(), TaskProgressColumn(),
            TextColumn("[dim]{task.fields[mem]}[/]"),
            console=console
        ) as progress:
            task = progress.add_task("Scanning...", total=len(unscanned), mem="")

            for idx, repo_row in enumerate(unscanned):
                repo_path = repo_row.get("clone_path", "")
                repo_name = repo_row.get("full_name", "")
                repo_id = repo_row["repo_id"]

                cur_mem = get_memory_mb()
                progress.update(
                    task,
                    description=f"Scanning {repo_name}...",
                    mem=f"{cur_mem:.0f}MB"
                )

                # Abort if memory pressure is critical
                if cur_mem > _MEMORY_HARD_LIMIT_MB:
                    console.print(
                        f"\n[bold red]!! Memory limit hit ({cur_mem:.0f}MB) — "
                        f"stopping scan at repo {idx+1}/{len(unscanned)}[/]"
                    )
                    log.error(f"Memory limit exceeded ({cur_mem:.0f}MB), aborting scan")
                    break

                if not repo_path or not os.path.exists(repo_path):
                    db.update_repository(repo_id, scan_status="failed",
                                         error_message="Clone path not found")
                    progress.advance(task)
                    continue

                try:
                    findings = await scanner.full_repo_scan(repo_path, repo_name)

                    for finding in findings:
                        secret_id = db.add_secret(scan_id, repo_id, finding,
                                                   store_value=store_value)
                        if secret_id:
                            total_findings += 1

                    db.update_repository(repo_id, scan_status="complete",
                                         commits_scanned=len(findings))

                    # Free findings list and force GC between repos
                    del findings
                    gc.collect()

                except Exception as e:
                    log.error(f"Scan failed for {repo_name}: {e}")
                    db.update_repository(repo_id, scan_status="failed",
                                         error_message=str(e)[:500])

                progress.advance(task)

        mem_after = get_memory_mb()
        console.print(f"[green][+][/] Found {total_findings} potential secrets "
                       f"[dim](mem: {mem_before:.0f}MB -> {mem_after:.0f}MB, "
                       f"files: {scanner.files_scanned}, "
                       f"skipped: {scanner.files_skipped})[/]")
        db.update_scan(scan_id, secrets_found=total_findings)

        # --- Phase 4: Validation ---
        if config.validation.enabled:
            console.print(f"\n[bold yellow]>> Phase 4:[/] Validating credentials...")

            validator = SecretValidator(config)
            unvalidated = db.get_unvalidated_secrets(scan_id)

            # Only validate secrets that have a validator
            validatable = [s for s in unvalidated if validator.can_validate(s.get("secret_type", ""))]

            if validatable:
                # Decrypt values for validation
                for s in validatable:
                    decrypted = db.get_secret_value(s["secret_id"])
                    if decrypted:
                        s["secret_value"] = decrypted

                results = await validator.validate_batch(validatable)

                valid_count = 0
                hv_count = 0
                for result in results:
                    sid = result.get("secret_id")
                    val = result.get("validation", {})
                    if sid:
                        db.update_secret_validation(sid, val)
                        if val.get("valid"):
                            valid_count += 1
                        if val.get("high_value"):
                            hv_count += 1

                console.print(f"[green][+][/] Validated {len(validatable)} secrets: "
                              f"{valid_count} valid, {hv_count} high-value")
                db.update_scan(scan_id, secrets_validated=valid_count, high_value_count=hv_count)
            else:
                console.print("[dim]No validatable secrets found[/]")

        # --- Phase 5: Reporting ---
        console.print(f"\n[bold yellow]>> Phase 5:[/] Generating reports...")

        report_dir = os.path.join(config.output.directory, scan_id)
        os.makedirs(report_dir, exist_ok=True)

        for fmt in config.output.formats:
            if fmt == "json":
                path = generate_json_report(db, scan_id, report_dir)
                console.print(f"  [green][+][/] JSON:     {path}")
            elif fmt == "markdown":
                path = generate_markdown_report(db, scan_id, report_dir)
                console.print(f"  [green][+][/] Markdown: {path}")
            elif fmt == "csv":
                path = generate_csv_report(db, scan_id, report_dir)
                console.print(f"  [green][+][/] CSV:      {path}")

        # Finalize scan
        db.update_scan(
            scan_id, status="complete",
            end_time=datetime.now(timezone.utc).isoformat()
        )

        # Cleanup
        if not config.output.keep_repos:
            console.print(f"\n[dim]Cleaning up cloned repos...[/]")
            await cloner.cleanup_repos(clone_base)

        # Print summary
        _print_summary(db, scan_id)

    except KeyboardInterrupt:
        console.print("\n[yellow]! Scan interrupted. Progress saved -- use --resume-scan to continue.[/]")
        db.update_scan(scan_id, status="interrupted")
    except Exception as e:
        console.print(f"\n[red]X Fatal error: {e}[/]")
        db.update_scan(scan_id, status="failed", error_log=str(e)[:1000])
        raise
    finally:
        db.close()


def _print_summary(db: DatabaseManager, scan_id: str):
    """Print a rich summary table."""
    stats = db.get_scan_stats(scan_id)

    console.print()
    table = Table(title="Scan Summary", show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")

    table.add_row("Target", stats["scan"].get("target", ""))
    table.add_row("Status", stats["scan"].get("status", ""))
    table.add_row("Repos Found", str(stats["repositories"]["total"]))
    table.add_row("Repos Scanned", str(stats["repositories"]["scanned"]))
    table.add_row("Secrets Found", str(stats["secrets"]["total"]))
    table.add_row("Validated (Valid)", str(stats["secrets"]["valid"] or 0))
    table.add_row("High-Value (!)", str(stats["secrets"]["high_value"] or 0))

    console.print(table)

    # Type breakdown
    if stats.get("by_type"):
        type_table = Table(title="Findings by Type", show_header=True)
        type_table.add_column("Type")
        type_table.add_column("Count", justify="right")
        for stype, count in sorted(stats["by_type"].items(), key=lambda x: x[1], reverse=True):
            type_table.add_row(stype, str(count))
        console.print(type_table)

    # High value alert
    hv = stats["secrets"]["high_value"] or 0
    if hv > 0:
        console.print(Panel(
            f"[bold red]!! {hv} HIGH-VALUE SECRET{'S' if hv > 1 else ''} FOUND !![/]\n"
            "[dim]Review the report immediately and rotate compromised credentials.[/]",
            border_style="red"
        ))


@app.command()
def scan(
    target: str = typer.Argument(help="Target: org name, user name, repo URL, search query, or file path"),
    target_type: Optional[str] = typer.Option(None, "--type", "-t", help="Target type: org, user, repo, search, file (auto-detected if omitted)"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c", help="Path to config.yaml"),
    tokens_file: Optional[str] = typer.Option(None, "--tokens", help="Path to tokens file"),
    parallel: int = typer.Option(8, "--parallel", "-p", help="Number of parallel clone jobs"),
    depth: str = typer.Option("shallow", "--depth", help="Clone depth: shallow, medium, full"),
    validate_secrets: bool = typer.Option(True, "--validate-secrets/--no-validate", help="Validate discovered secrets"),
    scan_branches: bool = typer.Option(True, "--scan-branches/--no-branches", help="Scan all branches"),
    scan_actions: bool = typer.Option(False, "--scan-actions", help="Scan GitHub Actions artifacts/logs"),
    scan_prs: bool = typer.Option(False, "--scan-prs", help="Scan pull request diffs"),
    skip_forks: bool = typer.Option(True, "--skip-forks/--include-forks", help="Skip forked repos"),
    skip_archived: bool = typer.Option(True, "--skip-archived/--include-archived", help="Skip archived repos"),
    max_size: int = typer.Option(500, "--max-size", help="Max repo size in MB"),
    max_repos: int = typer.Option(0, "--max-repos", help="Max repos to scan (0 = unlimited)"),
    proxy_list: Optional[str] = typer.Option(None, "--proxy-list", help="Path to proxy list file"),
    stealth: bool = typer.Option(False, "--stealth", help="Enable stealth mode (delays, user-agent rotation)"),
    output_format: str = typer.Option("json,markdown,csv", "--output-format", "-f", help="Output formats (comma-separated)"),
    output_dir: str = typer.Option("./scans", "--output-dir", "-o", help="Output directory"),
    no_store_secrets: bool = typer.Option(False, "--no-store-secrets", help="Don't store secret values in DB"),
    keep_repos: bool = typer.Option(False, "--keep-repos", help="Keep cloned repos after scan"),
    resume_scan: Optional[str] = typer.Option(None, "--resume-scan", help="Resume an interrupted scan by ID"),
):
    """
    Run a GitHub secret reconnaissance scan.

    Examples:
      ghrecon scan myorg
      ghrecon scan https://github.com/user/repo
      ghrecon scan --type search "org:target language:python"
      ghrecon scan myorg --stealth --tokens tokens.txt
    """
    _print_banner()

    # Auto-detect target type
    if not target_type:
        target_type = GitHubEnumerator.detect_target_type(target)
    console.print(f"[dim]Target:[/] {target} [dim]({target_type})[/]")

    # Load config
    config = load_config(
        config_path=config_file,
        tokens_file=tokens_file, parallel=parallel, depth=depth,
        validate_secrets=validate_secrets, scan_branches=scan_branches,
        scan_actions=scan_actions, scan_prs=scan_prs,
        skip_forks=skip_forks, skip_archived=skip_archived,
        max_size=max_size, max_repos=max_repos,
        proxy_list=proxy_list, stealth=stealth,
        output_format=output_format, output_dir=output_dir,
        no_store_secrets=no_store_secrets, keep_repos=keep_repos,
    )

    # Generate or use scan ID
    scan_id = resume_scan or _generate_scan_id(target)
    resume = resume_scan is not None

    console.print(f"[dim]Scan ID:[/] {scan_id}")
    console.print(f"[dim]Stealth:[/] {'enabled' if config.stealth.enabled else 'disabled'}")
    console.print(f"[dim]Parallel:[/] {config.scanning.parallel_jobs} jobs")
    console.print(f"[dim]Output:[/] {config.output.directory}")

    asyncio.run(_run_scan(config, target, target_type, scan_id, resume))


@app.command()
def export(
    scan_id: str = typer.Argument(help="Scan ID to export"),
    format: str = typer.Option("json", "--format", "-f", help="Export format: json, csv"),
    validated_only: bool = typer.Option(False, "--validated-only", help="Export only validated secrets"),
    output_dir: str = typer.Option("./scans", "--output-dir", "-o", help="Output directory"),
    db_path: str = typer.Option("./scans/ghrecon.db", "--db", help="Database path"),
):
    """Export results from a completed scan."""
    _print_banner()

    db = DatabaseManager(db_path=db_path)
    db.connect()

    scan = db.get_scan(scan_id)
    if not scan:
        console.print(f"[red]Scan {scan_id} not found![/]")
        db.close()
        raise typer.Exit(1)

    report_dir = os.path.join(output_dir, scan_id)

    if format == "json":
        path = generate_json_report(db, scan_id, report_dir, validated_only)
    elif format == "csv":
        path = generate_csv_report(db, scan_id, report_dir, validated_only)
    elif format == "markdown":
        path = generate_markdown_report(db, scan_id, report_dir)
    else:
        console.print(f"[red]Unknown format: {format}[/]")
        db.close()
        raise typer.Exit(1)

    console.print(f"[green][+][/] Exported: {path}")
    db.close()


@app.command()
def status(
    scan_id: Optional[str] = typer.Argument(None, help="Scan ID to check (latest if omitted)"),
    db_path: str = typer.Option("./scans/ghrecon.db", "--db", help="Database path"),
):
    """Check the status of a scan."""
    _print_banner()

    db = DatabaseManager(db_path=db_path)
    db.connect()

    if scan_id:
        scan = db.get_scan(scan_id)
    else:
        scan = db.get_latest_scan()
        if scan:
            scan_id = scan["scan_id"]

    if not scan:
        console.print("[yellow]No scans found.[/]")
        db.close()
        return

    _print_summary(db, scan_id)
    db.close()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-v", help="Show version"),
):
    """GHRecon -- GitHub Secret Reconnaissance Engine"""
    if version:
        console.print(f"GHRecon v{__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        _print_banner()
        console.print("\n[dim]Run 'ghrecon scan --help' for usage information.[/]")


if __name__ == "__main__":
    app()
