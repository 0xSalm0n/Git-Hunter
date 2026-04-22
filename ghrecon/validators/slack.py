"""
Slack token validation using auth.test API.
"""

import aiohttp
from ghrecon.utils.logger import get_logger

logger = get_logger("ghrecon.validators.slack")


async def validate_slack_token(token: str) -> dict:
    """Validate a Slack token using the auth.test endpoint."""
    token = token.strip()
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://slack.com/api/auth.test",
                headers={"Authorization": f"Bearer {token}"},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status != 200:
                    return {"valid": False, "error": f"HTTP {resp.status}", "high_value": False, "privilege_level": "unknown"}

                data = await resp.json()

                if data.get("ok"):
                    is_admin = "admin" in token or data.get("is_admin", False)
                    return {
                        "valid": True,
                        "team": data.get("team", ""),
                        "team_id": data.get("team_id", ""),
                        "user": data.get("user", ""),
                        "user_id": data.get("user_id", ""),
                        "url": data.get("url", ""),
                        "high_value": token.startswith("xoxb-") or token.startswith("xoxp-"),
                        "privilege_level": "admin" if is_admin else "write",
                        "account_info": f"{data.get('user', '')}@{data.get('team', '')}",
                    }
                else:
                    return {
                        "valid": False,
                        "error": data.get("error", "unknown"),
                        "high_value": False,
                        "privilege_level": "unknown"
                    }

    except Exception as e:
        logger.error(f"Slack validation error: {e}")
        return {"valid": None, "error": str(e), "high_value": False, "privilege_level": "unknown"}
