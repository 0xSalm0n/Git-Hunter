"""
Google API key validation using a lightweight API call.
"""

import aiohttp
from ghrecon.utils.logger import get_logger

logger = get_logger("ghrecon.validators.google")


async def validate_google_api_key(api_key: str) -> dict:
    """Validate a Google API key using the Maps Geocoding API (lightweight check)."""
    api_key = api_key.strip()
    try:
        # Use a minimal API call to check key validity
        url = f"https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=test&key={api_key}"

        async with aiohttp.ClientSession() as session:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                data = await resp.json()

                # A valid key will return a specific error, not "keyInvalid"
                if resp.status == 400:
                    error = data.get("error", {})
                    errors = error.get("errors", [{}])
                    reason = errors[0].get("reason", "") if errors else ""

                    if reason == "keyInvalid":
                        return {"valid": False, "error": "Invalid API key",
                                "high_value": False, "privilege_level": "unknown"}
                    else:
                        # Key is valid but request is bad (expected)
                        return {
                            "valid": True,
                            "note": "API key accepted by Google",
                            "high_value": True,
                            "privilege_level": "read",
                            "account_info": f"Google API Key: {api_key[:8]}...",
                        }
                elif resp.status == 403:
                    return {"valid": True, "note": "Key valid but restricted",
                            "high_value": False, "privilege_level": "read"}
                else:
                    return {"valid": True, "high_value": True,
                            "privilege_level": "read",
                            "account_info": f"Google API Key: {api_key[:8]}..."}

    except Exception as e:
        logger.error(f"Google validation error: {e}")
        return {"valid": None, "error": str(e), "high_value": False, "privilege_level": "unknown"}
