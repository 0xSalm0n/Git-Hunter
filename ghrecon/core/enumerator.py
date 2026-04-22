"""
Target enumeration: GitHub REST & GraphQL API for repos, orgs, users, and search.
"""

import asyncio
import re
import random
from datetime import datetime, timezone, timedelta
from typing import Optional, AsyncGenerator

import aiohttp

from ghrecon.utils.logger import get_logger
from ghrecon.utils.token_pool import TokenPool
from ghrecon.config import GHReconConfig

logger = get_logger("ghrecon.enumerator")

GITHUB_API = "https://api.github.com"
GITHUB_GRAPHQL = "https://api.github.com/graphql"


class GitHubEnumerator:
    """Enumerates GitHub repositories for a given target."""

    def __init__(self, config: GHReconConfig, token_pool: TokenPool):
        self.config = config
        self.token_pool = token_pool
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={"Accept": "application/vnd.github.v3+json"}
        )
        return self

    async def __aexit__(self, *args):
        if self._session:
            await self._session.close()

    async def _api_call(self, url: str, method: str = "GET",
                        json_data: Optional[dict] = None,
                        max_retries: int = 3) -> Optional[dict | list]:
        """Make an authenticated GitHub API call with retry and token rotation."""
        for attempt in range(max_retries):
            token = await self.token_pool.get_healthy_token()
            headers = {"Authorization": f"token {token}"}

            try:
                if method == "POST":
                    async with self._session.post(url, headers=headers, json=json_data) as resp:
                        await self.token_pool.update_health(token, dict(resp.headers))
                        if resp.status == 200:
                            return await resp.json()
                        elif resp.status in (403, 429):
                            await self.token_pool.mark_error(token, resp.status)
                            await asyncio.sleep(2 ** attempt)
                            continue
                        elif resp.status in (404, 401):
                            if resp.status == 401:
                                await self.token_pool.mark_error(token, 401)
                            return None
                        else:
                            logger.error(f"API {resp.status}: {url}")
                            return None
                else:
                    async with self._session.get(url, headers=headers) as resp:
                        await self.token_pool.update_health(token, dict(resp.headers))
                        if resp.status == 200:
                            return await resp.json()
                        elif resp.status in (403, 429):
                            await self.token_pool.mark_error(token, resp.status)
                            await asyncio.sleep(2 ** attempt)
                            continue
                        elif resp.status in (404, 401):
                            if resp.status == 401:
                                await self.token_pool.mark_error(token, 401)
                            return None
                        else:
                            logger.error(f"API {resp.status}: {url}")
                            return None
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.warning(f"Request error (attempt {attempt+1}): {e}")
                await asyncio.sleep(2 ** attempt)

        return None

    async def _paginated_api(self, url: str, max_pages: int = 100) -> list[dict]:
        """Fetch all pages of a paginated GitHub API endpoint."""
        results = []
        page = 1
        per_page = 100

        while page <= max_pages:
            sep = "&" if "?" in url else "?"
            page_url = f"{url}{sep}per_page={per_page}&page={page}"
            data = await self._api_call(page_url)

            if not data or not isinstance(data, list) or len(data) == 0:
                break

            results.extend(data)
            page += 1

            if self.config.stealth.enabled:
                await asyncio.sleep(random.uniform(0.5, 2.0))

        return results

    # ---- GraphQL Bulk Fetching ----

    async def _graphql_repos(self, owner: str, owner_type: str = "organization",
                              cursor: Optional[str] = None) -> dict:
        """Fetch repositories via GraphQL (100 per call)."""
        if owner_type == "organization":
            query = """
            query($owner: String!, $cursor: String) {
              organization(login: $owner) {
                repositories(first: 100, after: $cursor, orderBy: {field: PUSHED_AT, direction: DESC}) {
                  pageInfo { hasNextPage endCursor }
                  nodes {
                    name nameWithOwner url description
                    isFork isArchived
                    diskUsage pushedAt defaultBranchRef { name }
                    stargazerCount
                    primaryLanguage { name }
                    languages(first: 10) { nodes { name } }
                  }
                }
              }
            }"""
        else:
            query = """
            query($owner: String!, $cursor: String) {
              user(login: $owner) {
                repositories(first: 100, after: $cursor, orderBy: {field: PUSHED_AT, direction: DESC}) {
                  pageInfo { hasNextPage endCursor }
                  nodes {
                    name nameWithOwner url description
                    isFork isArchived
                    diskUsage pushedAt defaultBranchRef { name }
                    stargazerCount
                    primaryLanguage { name }
                    languages(first: 10) { nodes { name } }
                  }
                }
              }
            }"""

        variables = {"owner": owner, "cursor": cursor}
        result = await self._api_call(GITHUB_GRAPHQL, method="POST",
                                       json_data={"query": query, "variables": variables})
        return result or {}

    async def enumerate_graphql(self, owner: str, owner_type: str = "organization") -> list[dict]:
        """Enumerate all repos via GraphQL pagination."""
        all_repos = []
        cursor = None

        while True:
            data = await self._graphql_repos(owner, owner_type, cursor)
            root = data.get("data", {}).get(
                "organization" if owner_type == "organization" else "user", {}
            )
            repos_data = root.get("repositories", {})
            nodes = repos_data.get("nodes", [])

            if not nodes:
                break

            for node in nodes:
                repo = self._normalize_graphql_repo(node, owner)
                all_repos.append(repo)

            page_info = repos_data.get("pageInfo", {})
            if not page_info.get("hasNextPage"):
                break
            cursor = page_info.get("endCursor")

            if self.config.stealth.enabled:
                await asyncio.sleep(random.uniform(1, 3))

        logger.info(f"GraphQL enumerated {len(all_repos)} repos for {owner}")
        return all_repos

    def _normalize_graphql_repo(self, node: dict, owner: str) -> dict:
        """Convert GraphQL repo node to standard format."""
        languages = [l["name"] for l in node.get("languages", {}).get("nodes", [])]
        return {
            "name": node.get("name", ""),
            "full_name": node.get("nameWithOwner", ""),
            "url": node.get("url", ""),
            "owner": owner,
            "description": node.get("description", ""),
            "is_fork": node.get("isFork", False),
            "is_archived": node.get("isArchived", False),
            "size_mb": round((node.get("diskUsage", 0) or 0) / 1024, 2),
            "last_push": node.get("pushedAt"),
            "default_branch": (node.get("defaultBranchRef") or {}).get("name", "main"),
            "stars": node.get("stargazerCount", 0),
            "languages": languages,
            "primary_language": (node.get("primaryLanguage") or {}).get("name"),
        }

    # ---- REST API Enumeration ----

    async def enumerate_org_repos(self, org: str) -> list[dict]:
        """Enumerate all repos in an organization via REST."""
        raw_repos = await self._paginated_api(f"{GITHUB_API}/orgs/{org}/repos?type=all")
        return [self._normalize_rest_repo(r) for r in raw_repos]

    async def enumerate_user_repos(self, user: str) -> list[dict]:
        """Enumerate all repos for a user via REST."""
        raw_repos = await self._paginated_api(f"{GITHUB_API}/users/{user}/repos?type=all")
        return [self._normalize_rest_repo(r) for r in raw_repos]

    async def enumerate_org_members(self, org: str) -> list[dict]:
        """Enumerate organization members and their repos."""
        members = await self._paginated_api(f"{GITHUB_API}/orgs/{org}/members")
        all_repos = []
        for member in members:
            login = member.get("login")
            if login:
                user_repos = await self.enumerate_user_repos(login)
                all_repos.extend(user_repos)
                if self.config.stealth.enabled:
                    await asyncio.sleep(random.uniform(2, 5))
        return all_repos

    async def search_repos(self, query: str, max_repos: int = 100) -> list[dict]:
        """Search repositories using GitHub search API."""
        results = []
        page = 1
        per_page = min(100, max_repos)

        while len(results) < max_repos:
            url = f"{GITHUB_API}/search/repositories?q={query}&per_page={per_page}&page={page}"
            data = await self._api_call(url)
            if not data or "items" not in data:
                break

            for item in data["items"]:
                results.append(self._normalize_rest_repo(item))
                if len(results) >= max_repos:
                    break

            if len(data["items"]) < per_page:
                break
            page += 1
            await asyncio.sleep(2)  # Search API is more rate-limited

        logger.info(f"Search found {len(results)} repos for query: {query}")
        return results

    async def get_single_repo(self, repo_url: str) -> Optional[dict]:
        """Get info for a single repository URL."""
        match = re.match(r'https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?$', repo_url)
        if not match:
            logger.error(f"Invalid repo URL: {repo_url}")
            return None
        owner, name = match.groups()
        data = await self._api_call(f"{GITHUB_API}/repos/{owner}/{name}")
        return self._normalize_rest_repo(data) if data else None

    async def get_repo_branches(self, full_name: str) -> list[str]:
        """Get all branches for a repository."""
        branches = await self._paginated_api(f"{GITHUB_API}/repos/{full_name}/branches")
        return [b.get("name", "") for b in branches if b.get("name")]

    async def get_repo_tags(self, full_name: str) -> list[str]:
        """Get all tags for a repository."""
        tags = await self._paginated_api(f"{GITHUB_API}/repos/{full_name}/tags")
        return [t.get("name", "") for t in tags if t.get("name")]

    async def get_repo_prs(self, full_name: str, state: str = "closed",
                           max_prs: int = 50) -> list[dict]:
        """Get pull requests for a repository."""
        prs = await self._paginated_api(
            f"{GITHUB_API}/repos/{full_name}/pulls?state={state}&sort=updated&direction=desc",
            max_pages=max_prs // 100 + 1
        )
        return prs[:max_prs]

    async def get_workflow_runs(self, full_name: str, max_runs: int = 20) -> list[dict]:
        """Get GitHub Actions workflow runs."""
        data = await self._api_call(
            f"{GITHUB_API}/repos/{full_name}/actions/runs?per_page={min(max_runs, 100)}"
        )
        if data and "workflow_runs" in data:
            return data["workflow_runs"][:max_runs]
        return []

    async def get_packages(self, org: str, package_type: str = "container") -> list[dict]:
        """List packages for an organization."""
        return await self._paginated_api(
            f"{GITHUB_API}/orgs/{org}/packages?package_type={package_type}"
        )

    def _normalize_rest_repo(self, repo: dict) -> dict:
        """Convert REST API repo to standard format."""
        return {
            "name": repo.get("name", ""),
            "full_name": repo.get("full_name", ""),
            "url": repo.get("html_url") or repo.get("url", ""),
            "clone_url": repo.get("clone_url", ""),
            "owner": repo.get("owner", {}).get("login", ""),
            "description": repo.get("description", ""),
            "is_fork": repo.get("fork", False),
            "is_archived": repo.get("archived", False),
            "size_mb": round((repo.get("size", 0) or 0) / 1024, 2),
            "last_push": repo.get("pushed_at"),
            "default_branch": repo.get("default_branch", "main"),
            "stars": repo.get("stargazers_count", 0),
            "languages": [],
            "primary_language": repo.get("language"),
        }

    # ---- Filtering ----

    def filter_repos(self, repos: list[dict]) -> list[dict]:
        """Apply configured filters to repository list."""
        cfg = self.config.scanning
        filtered = []

        for repo in repos:
            if cfg.skip_forks and repo.get("is_fork"):
                continue
            if cfg.skip_archived and repo.get("is_archived"):
                continue
            if cfg.max_repo_size_mb and repo.get("size_mb", 0) > cfg.max_repo_size_mb:
                continue
            if cfg.min_stars and repo.get("stars", 0) < cfg.min_stars:
                continue
            if cfg.filter_languages:
                repo_langs = repo.get("languages", [])
                primary = repo.get("primary_language")
                if primary:
                    repo_langs = [primary] + repo_langs
                if not any(l.lower() in [fl.lower() for fl in cfg.filter_languages]
                           for l in repo_langs):
                    continue
            if cfg.last_push_within_days and repo.get("last_push"):
                try:
                    push_date = datetime.fromisoformat(
                        repo["last_push"].replace("Z", "+00:00"))
                    cutoff = datetime.now(timezone.utc) - timedelta(days=cfg.last_push_within_days)
                    if push_date < cutoff:
                        continue
                except (ValueError, TypeError):
                    pass

            filtered.append(repo)

        # Prioritize by language and activity
        filtered.sort(key=lambda r: self._priority_score(r), reverse=True)

        if cfg.max_repos > 0:
            filtered = filtered[:cfg.max_repos]

        skipped = len(repos) - len(filtered)
        logger.info(f"Filtered {len(repos)} -> {len(filtered)} repos ({skipped} skipped)")
        return filtered

    def _priority_score(self, repo: dict) -> float:
        """Score repo for priority (higher = more interesting)."""
        score = 0.0
        priority_langs = [l.lower() for l in self.config.scanning.priority_languages]

        primary = (repo.get("primary_language") or "").lower()
        if primary in priority_langs:
            score += 10

        for lang in repo.get("languages", []):
            if lang.lower() in priority_langs:
                score += 3

        score += min(repo.get("stars", 0) / 100, 5)
        score += repo.get("size_mb", 0) / 100

        if repo.get("last_push"):
            try:
                push = datetime.fromisoformat(repo["last_push"].replace("Z", "+00:00"))
                days_ago = (datetime.now(timezone.utc) - push).days
                score += max(0, 10 - days_ago / 30)
            except (ValueError, TypeError):
                pass

        return score

    # ---- High-level Enumeration ----

    async def enumerate(self, target: str, target_type: str) -> list[dict]:
        """Main enumeration entry point."""
        repos = []

        if target_type == "repo":
            repo = await self.get_single_repo(target)
            if repo:
                repos = [repo]
        elif target_type == "org":
            if self.config.github.graphql_enabled:
                repos = await self.enumerate_graphql(target, "organization")
            else:
                repos = await self.enumerate_org_repos(target)
        elif target_type == "user":
            if self.config.github.graphql_enabled:
                repos = await self.enumerate_graphql(target, "user")
            else:
                repos = await self.enumerate_user_repos(target)
        elif target_type == "search":
            max_repos = self.config.scanning.max_repos or 100
            repos = await self.search_repos(target, max_repos)
        elif target_type == "file":
            repos = await self._enumerate_from_file(target)

        return self.filter_repos(repos)

    async def _enumerate_from_file(self, filepath: str) -> list[dict]:
        """Enumerate repos from a file (one URL per line)."""
        repos = []
        with open(filepath, "r") as f:
            urls = [l.strip() for l in f if l.strip() and not l.startswith("#")]

        for url in urls:
            repo = await self.get_single_repo(url)
            if repo:
                repos.append(repo)
            if self.config.stealth.enabled:
                await asyncio.sleep(random.uniform(1, 3))

        return repos

    @staticmethod
    def detect_target_type(target: str) -> str:
        """Auto-detect whether target is a repo URL, org, user, search query, or file."""
        if target.startswith("http"):
            parts = target.rstrip("/").split("/")
            if len(parts) >= 5:
                return "repo"
            return "org"
        if os.path.isfile(target):
            return "file"
        if ":" in target or " " in target:
            return "search"
        # Default: try org first, then user
        return "org"


import os  # noqa: E402 (needed for detect_target_type)
