"""
Async git clone operations with stealth, proxy support, and resume capability.
"""

import asyncio
import os
import random
import shutil
import tempfile
from typing import Optional

from ghrecon.utils.logger import get_logger
from ghrecon.utils.proxy import ProxyManager
from ghrecon.config import GHReconConfig

logger = get_logger("ghrecon.cloner")


class AsyncCloner:
    """Handles async git clone operations with stealth and parallelism."""

    def __init__(self, config: GHReconConfig, proxy_manager: Optional[ProxyManager] = None):
        self.config = config
        self.proxy_manager = proxy_manager
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._clone_count = 0

    def _get_semaphore(self) -> asyncio.Semaphore:
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.config.scanning.parallel_jobs)
        return self._semaphore

    def _random_user_agent(self) -> str:
        agents = self.config.stealth.user_agents
        return random.choice(agents) if agents else "git/2.40.0"

    async def _stealth_delay(self) -> None:
        """Apply jittered delay for stealth operations."""
        if self.config.stealth.enabled:
            delay = random.uniform(self.config.stealth.min_delay, self.config.stealth.max_delay)
            await asyncio.sleep(delay)

    def _check_disk_space(self, min_gb: float = 5.0) -> bool:
        """Check if sufficient disk space is available."""
        try:
            stat = shutil.disk_usage(os.getcwd())
            free_gb = stat.free / (1024 ** 3)
            if free_gb < min_gb:
                logger.warning(f"Low disk space: {free_gb:.1f}GB free (need {min_gb}GB)")
                return False
            return True
        except Exception:
            return True

    async def clone_repo(self, clone_url: str, dest_path: str,
                         depth: Optional[int] = None,
                         branch: Optional[str] = None) -> bool:
        """Clone a single repository with retry and stealth support."""
        if not self._check_disk_space():
            logger.error(f"Insufficient disk space for cloning {clone_url}")
            return False

        if os.path.exists(dest_path) and os.listdir(dest_path):
            logger.info(f"Already cloned: {dest_path}")
            return True

        os.makedirs(dest_path, exist_ok=True)

        clone_depth = depth if depth is not None else self.config.scanning.clone_depth
        proxy = None
        if self.proxy_manager and self.proxy_manager.has_proxies:
            proxy = await self.proxy_manager.get_random_proxy()

        for attempt in range(3):
            try:
                cmd = ["git", "clone"]
                if clone_depth and clone_depth > 0:
                    cmd.extend(["--depth", str(clone_depth)])
                if branch:
                    cmd.extend(["--branch", branch])
                cmd.extend(["--single-branch" if branch else "--no-single-branch"])
                cmd.extend([clone_url, dest_path])

                env = os.environ.copy()
                env["GIT_TERMINAL_PROMPT"] = "0"
                if self.config.stealth.enabled:
                    env["GIT_HTTP_USER_AGENT"] = self._random_user_agent()
                if proxy and self.proxy_manager:
                    env.update(self.proxy_manager.get_env_dict(proxy))

                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE, env=env
                )

                try:
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
                except asyncio.TimeoutError:
                    proc.kill()
                    logger.warning(f"Clone timeout (attempt {attempt+1}): {clone_url}")
                    if os.path.exists(dest_path):
                        shutil.rmtree(dest_path, ignore_errors=True)
                    continue

                if proc.returncode == 0:
                    self._clone_count += 1
                    logger.info(f"Cloned: {clone_url} -> {dest_path}")
                    if proxy and self.proxy_manager:
                        await self.proxy_manager.mark_success(proxy)
                    return True
                else:
                    err_msg = stderr.decode(errors="replace").strip()
                    logger.warning(f"Clone failed (attempt {attempt+1}): {err_msg[:200]}")
                    if os.path.exists(dest_path):
                        shutil.rmtree(dest_path, ignore_errors=True)
                        os.makedirs(dest_path, exist_ok=True)

            except Exception as e:
                logger.error(f"Clone error (attempt {attempt+1}): {e}")

            if proxy and self.proxy_manager:
                await self.proxy_manager.mark_failed(proxy)
                proxy = await self.proxy_manager.get_random_proxy()

            await asyncio.sleep(2 ** attempt)

        return False

    async def clone_with_semaphore(self, clone_url: str, dest_path: str,
                                    repo_info: Optional[dict] = None) -> dict:
        """Clone with semaphore-based rate limiting."""
        sem = self._get_semaphore()
        async with sem:
            await self._stealth_delay()
            success = await self.clone_repo(clone_url, dest_path)

            result = {
                "url": clone_url,
                "path": dest_path,
                "success": success,
                "full_name": (repo_info or {}).get("full_name", ""),
            }

            if success and self.config.scanning.scan_branches:
                await self.fetch_all_branches(dest_path)
            if success and self.config.scanning.scan_tags:
                await self.fetch_all_tags(dest_path)

            return result

    async def fetch_all_branches(self, repo_path: str) -> list[str]:
        """Fetch all remote branches for a cloned repository."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "git", "-C", repo_path, "fetch", "--all", "--quiet",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(proc.communicate(), timeout=120)

            proc = await asyncio.create_subprocess_exec(
                "git", "-C", repo_path, "branch", "-r",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)

            branches = []
            for line in stdout.decode().splitlines():
                branch = line.strip()
                if branch and "HEAD" not in branch:
                    branches.append(branch)
            return branches
        except Exception as e:
            logger.warning(f"Failed to fetch branches for {repo_path}: {e}")
            return []

    async def fetch_all_tags(self, repo_path: str) -> list[str]:
        """Fetch all tags for a cloned repository."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "git", "-C", repo_path, "fetch", "--tags", "--quiet",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(proc.communicate(), timeout=60)

            proc = await asyncio.create_subprocess_exec(
                "git", "-C", repo_path, "tag", "-l",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            return [t.strip() for t in stdout.decode().splitlines() if t.strip()]
        except Exception as e:
            logger.warning(f"Failed to fetch tags for {repo_path}: {e}")
            return []

    async def recover_dangling_commits(self, repo_path: str) -> list[str]:
        """Recover dangling commits using git fsck."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "git", "-C", repo_path, "fsck", "--unreachable", "--no-reflogs",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)

            dangling = []
            for line in stdout.decode().splitlines():
                if "dangling commit" in line:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        dangling.append(parts[-1])
            return dangling
        except Exception as e:
            logger.warning(f"fsck failed for {repo_path}: {e}")
            return []

    async def get_stash_entries(self, repo_path: str) -> list[str]:
        """Extract git stash entries."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "git", "-C", repo_path, "stash", "list",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            return [l.strip() for l in stdout.decode().splitlines() if l.strip()]
        except Exception:
            return []

    async def get_deleted_files(self, repo_path: str) -> list[dict]:
        """Find deleted files in commit history."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "git", "-C", repo_path, "log", "--diff-filter=D", "--name-only",
                "--pretty=format:%H|%an|%aI", "-n", "500",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)

            deleted = []
            current_commit = None
            for line in stdout.decode().splitlines():
                line = line.strip()
                if not line:
                    continue
                if "|" in line:
                    parts = line.split("|", 2)
                    current_commit = {
                        "hash": parts[0], "author": parts[1] if len(parts) > 1 else "",
                        "date": parts[2] if len(parts) > 2 else ""
                    }
                elif current_commit:
                    deleted.append({**current_commit, "file": line})
            return deleted
        except Exception as e:
            logger.warning(f"Deleted files scan failed for {repo_path}: {e}")
            return []

    async def clone_repos_parallel(self, repos: list[dict],
                                    base_dir: str) -> list[dict]:
        """Clone multiple repositories in parallel."""
        # Randomize order for stealth
        if self.config.stealth.enabled:
            repos = repos.copy()
            random.shuffle(repos)

        tasks = []
        for repo in repos:
            full_name = repo.get("full_name", "")
            clone_url = repo.get("clone_url") or f"https://github.com/{full_name}.git"
            dest = os.path.join(base_dir, full_name.replace("/", os.sep))
            tasks.append(self.clone_with_semaphore(clone_url, dest, repo))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        completed = []
        for r in results:
            if isinstance(r, Exception):
                logger.error(f"Clone task exception: {r}")
                completed.append({"success": False, "error": str(r)})
            else:
                completed.append(r)

        success_count = sum(1 for r in completed if r.get("success"))
        logger.info(f"Cloned {success_count}/{len(repos)} repos successfully")
        return completed

    async def cleanup_repos(self, base_dir: str) -> None:
        """Remove cloned repositories."""
        if os.path.exists(base_dir):
            shutil.rmtree(base_dir, ignore_errors=True)
            logger.info(f"Cleaned up cloned repos: {base_dir}")
