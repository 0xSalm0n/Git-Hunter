"""
Advanced analysis: entropy timelines, dependency confusion, CI/CD artifacts.
"""

import os
import re
import json
import asyncio
from typing import Optional
from datetime import datetime

import aiohttp

from ghrecon.utils.logger import get_logger
from ghrecon.utils.token_pool import TokenPool
from ghrecon.config import GHReconConfig

logger = get_logger("ghrecon.analyzer")

GITHUB_API = "https://api.github.com"

# Package registries for dependency confusion checks
REGISTRIES = {
    "pypi": "https://pypi.org/pypi/{}/json",
    "npm": "https://registry.npmjs.org/{}",
    "rubygems": "https://rubygems.org/api/v1/gems/{}.json",
}


class Analyzer:
    """Advanced analysis: timelines, dependencies, CI/CD, containers."""

    def __init__(self, config: GHReconConfig, token_pool: Optional[TokenPool] = None):
        self.config = config
        self.token_pool = token_pool

    # ---- Secret Timeline ----

    async def build_secret_timeline(self, repo_path: str,
                                      scan_func=None) -> list[dict]:
        """Track when secrets were introduced and removed."""
        timeline = []
        try:
            proc = await asyncio.create_subprocess_exec(
                "git", "-C", repo_path, "log", "--all", "-p",
                "--pretty=format:COMMIT|%H|%an|%aI|%s", "-n", "200",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            output = stdout.decode(errors="replace")

            commits = output.split("COMMIT|")
            for block in commits:
                if not block.strip():
                    continue

                header_line, *diff_lines = block.split("\n", 1)
                parts = header_line.split("|", 3)
                if len(parts) < 4:
                    continue

                commit_hash, author, date, subject = parts
                diff_text = diff_lines[0] if diff_lines else ""

                added_lines = []
                removed_lines = []
                current_file = ""

                for line in diff_text.split("\n"):
                    if line.startswith("+++ b/"):
                        current_file = line[6:]
                    elif line.startswith("+") and not line.startswith("+++"):
                        added_lines.append((current_file, line[1:]))
                    elif line.startswith("-") and not line.startswith("---"):
                        removed_lines.append((current_file, line[1:]))

                if scan_func:
                    for f, content in added_lines:
                        secrets = scan_func(content, file_path=f)
                        for s in secrets:
                            timeline.append({
                                "commit": commit_hash, "date": date,
                                "author": author, "subject": subject,
                                "secret_type": s["type"], "status": "added",
                                "file": f, "value_hash": s.get("value", "")[:8] + "..."
                            })

                    for f, content in removed_lines:
                        secrets = scan_func(content, file_path=f)
                        for s in secrets:
                            timeline.append({
                                "commit": commit_hash, "date": date,
                                "author": author, "subject": subject,
                                "secret_type": s["type"], "status": "removed",
                                "file": f, "value_hash": s.get("value", "")[:8] + "..."
                            })

        except Exception as e:
            logger.warning(f"Timeline build failed: {e}")

        return timeline

    # ---- Dependency Confusion Detection ----

    async def check_dependency_confusion(self, repo_path: str) -> list[dict]:
        """Extract private packages and check public registry existence."""
        packages = self._extract_package_names(repo_path)
        results = []

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            for pkg in packages:
                pkg_name = pkg["name"]
                registry = pkg["registry"]
                url_template = REGISTRIES.get(registry)
                if not url_template:
                    continue

                try:
                    url = url_template.format(pkg_name)
                    async with session.get(url) as resp:
                        if resp.status == 404:
                            results.append({
                                "package": pkg_name,
                                "registry": registry,
                                "source_file": pkg["file"],
                                "status": "NOT_FOUND",
                                "risk": "high",
                                "note": "Package not found on public registry — "
                                        "potential dependency confusion target"
                            })
                        elif resp.status == 200:
                            results.append({
                                "package": pkg_name,
                                "registry": registry,
                                "status": "EXISTS",
                                "risk": "low"
                            })
                except Exception:
                    pass

        vulnerable = [r for r in results if r.get("status") == "NOT_FOUND"]
        if vulnerable:
            logger.warning(f"Found {len(vulnerable)} potential dependency confusion targets")
        return results

    def _extract_package_names(self, repo_path: str) -> list[dict]:
        """Extract package names from manifest files."""
        packages = []

        # Python: requirements.txt
        for name in ("requirements.txt", "requirements-dev.txt", "requirements_dev.txt"):
            path = os.path.join(repo_path, name)
            if os.path.exists(path):
                with open(path, errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith(("#", "-", "git+")):
                            pkg = re.split(r'[>=<!\[;]', line)[0].strip()
                            if pkg and not pkg.startswith("."):
                                packages.append({"name": pkg, "registry": "pypi", "file": name})

        # Python: pyproject.toml (basic)
        pyproject = os.path.join(repo_path, "pyproject.toml")
        if os.path.exists(pyproject):
            with open(pyproject, errors="ignore") as f:
                content = f.read()
            deps = re.findall(r'"([a-zA-Z0-9_-]+)"', content)
            for d in deps:
                if len(d) > 2 and d not in ("python", "requires"):
                    packages.append({"name": d, "registry": "pypi", "file": "pyproject.toml"})

        # JavaScript: package.json
        pkg_json = os.path.join(repo_path, "package.json")
        if os.path.exists(pkg_json):
            try:
                with open(pkg_json) as f:
                    data = json.load(f)
                for section in ("dependencies", "devDependencies"):
                    for pkg in data.get(section, {}):
                        if pkg.startswith("@"):
                            packages.append({"name": pkg, "registry": "npm", "file": "package.json"})
                        else:
                            packages.append({"name": pkg, "registry": "npm", "file": "package.json"})
            except (json.JSONDecodeError, OSError):
                pass

        # Ruby: Gemfile
        gemfile = os.path.join(repo_path, "Gemfile")
        if os.path.exists(gemfile):
            with open(gemfile, errors="ignore") as f:
                for line in f:
                    match = re.match(r"""gem\s+['"]([^'"]+)['"]""", line.strip())
                    if match:
                        packages.append({"name": match.group(1), "registry": "rubygems", "file": "Gemfile"})

        return packages

    # ---- CI/CD Artifact Scanning ----

    async def scan_actions_artifacts(self, full_name: str) -> list[dict]:
        """Download and scan GitHub Actions artifacts."""
        if not self.token_pool:
            return []

        findings = []
        token = await self.token_pool.get_healthy_token()
        headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}

        try:
            async with aiohttp.ClientSession(headers=headers) as session:
                # List recent workflow runs
                async with session.get(
                    f"{GITHUB_API}/repos/{full_name}/actions/runs?per_page=10"
                ) as resp:
                    if resp.status != 200:
                        return []
                    runs_data = await resp.json()

                for run in runs_data.get("workflow_runs", [])[:5]:
                    run_id = run["id"]

                    # List artifacts for this run
                    async with session.get(
                        f"{GITHUB_API}/repos/{full_name}/actions/runs/{run_id}/artifacts"
                    ) as resp:
                        if resp.status != 200:
                            continue
                        artifacts_data = await resp.json()

                    for artifact in artifacts_data.get("artifacts", []):
                        findings.append({
                            "type": "ci_artifact",
                            "name": artifact["name"],
                            "run_id": run_id,
                            "size_bytes": artifact.get("size_in_bytes", 0),
                            "created_at": artifact.get("created_at"),
                            "expired": artifact.get("expired", False),
                        })

        except Exception as e:
            logger.warning(f"Actions artifact scan failed for {full_name}: {e}")

        return findings

    async def scan_actions_logs(self, full_name: str) -> list[dict]:
        """Scan GitHub Actions workflow run logs for secrets."""
        if not self.token_pool:
            return []

        findings = []
        token = await self.token_pool.get_healthy_token()
        headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}

        try:
            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.get(
                    f"{GITHUB_API}/repos/{full_name}/actions/runs?per_page=5"
                ) as resp:
                    if resp.status != 200:
                        return []
                    data = await resp.json()

                for run in data.get("workflow_runs", [])[:3]:
                    async with session.get(
                        f"{GITHUB_API}/repos/{full_name}/actions/runs/{run['id']}/logs",
                        allow_redirects=True
                    ) as resp:
                        if resp.status == 200:
                            # Logs come as zip
                            log_content = await resp.read()
                            findings.append({
                                "type": "actions_log",
                                "run_id": run["id"],
                                "size": len(log_content),
                                "status": run.get("conclusion"),
                            })

        except Exception as e:
            logger.warning(f"Actions log scan failed: {e}")

        return findings

    # ---- Container Image Analysis ----

    async def discover_container_images(self, org: str) -> list[dict]:
        """Discover container images in GitHub Packages."""
        if not self.token_pool:
            return []

        token = await self.token_pool.get_healthy_token()
        headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}

        images = []
        try:
            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.get(
                    f"{GITHUB_API}/orgs/{org}/packages?package_type=container&per_page=100"
                ) as resp:
                    if resp.status == 200:
                        packages = await resp.json()
                        for pkg in packages:
                            images.append({
                                "name": pkg.get("name"),
                                "full_name": f"ghcr.io/{org}/{pkg.get('name', '')}",
                                "visibility": pkg.get("visibility"),
                                "created_at": pkg.get("created_at"),
                                "updated_at": pkg.get("updated_at"),
                            })
        except Exception as e:
            logger.warning(f"Container discovery failed for {org}: {e}")

        return images
