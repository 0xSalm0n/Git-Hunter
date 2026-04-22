"""
GitHub token validation: checks /user endpoint, scopes, and org access.
"""

import aiohttp

from ghrecon.utils.logger import get_logger

logger = get_logger("ghrecon.validators.github")


async def validate_github_token(token: str) -> dict:
    """
    Validate a GitHub token using the /user endpoint.
    This endpoint doesn't count against rate limits for PATs.
    """
    token = token.strip()
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}

    try:
        async with aiohttp.ClientSession() as session:
            # 1. Verify token and get user info
            async with session.get("https://api.github.com/user",
                                    headers=headers,
                                    timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 401:
                    return {"valid": False, "error": "Invalid token", "high_value": False, "privilege_level": "unknown"}
                if resp.status != 200:
                    return {"valid": False, "error": f"HTTP {resp.status}", "high_value": False, "privilege_level": "unknown"}

                user_data = await resp.json()

                # 2. Extract scopes from response headers
                scopes_header = resp.headers.get("X-OAuth-Scopes", "")
                scopes = [s.strip() for s in scopes_header.split(",") if s.strip()]

                # 3. Determine privilege level
                high_value_scopes = {"repo", "admin:org", "delete_repo",
                                      "admin:public_key", "admin:org_hook",
                                      "admin:repo_hook", "write:packages"}
                has_high_value = bool(set(scopes) & high_value_scopes)

                if has_high_value:
                    priv = "admin"
                elif "repo" in scopes or "public_repo" in scopes:
                    priv = "write"
                elif scopes:
                    priv = "read"
                else:
                    priv = "read"

                # 4. Enumerate accessible orgs
                orgs = []
                if "read:org" in scopes or "admin:org" in scopes:
                    try:
                        async with session.get("https://api.github.com/user/orgs",
                                                headers=headers,
                                                timeout=aiohttp.ClientTimeout(total=10)) as org_resp:
                            if org_resp.status == 200:
                                org_data = await org_resp.json()
                                orgs = [o.get("login", "") for o in org_data]
                    except Exception:
                        pass

                return {
                    "valid": True,
                    "username": user_data.get("login", ""),
                    "user_id": user_data.get("id"),
                    "name": user_data.get("name", ""),
                    "email": user_data.get("email"),
                    "scopes": scopes,
                    "organizations": orgs,
                    "high_value": has_high_value,
                    "privilege_level": priv,
                    "account_info": f"{user_data.get('login', '')} (ID: {user_data.get('id', '')})",
                    "permissions": scopes,
                }

    except aiohttp.ClientError as e:
        logger.error(f"GitHub validation network error: {e}")
        return {"valid": None, "error": str(e), "high_value": False, "privilege_level": "unknown"}
    except Exception as e:
        logger.error(f"GitHub validation error: {e}")
        return {"valid": None, "error": str(e), "high_value": False, "privilege_level": "unknown"}
