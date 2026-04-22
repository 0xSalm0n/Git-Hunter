"""
Stripe API key validation using /v1/charges endpoint (read-only check).
"""

import aiohttp
from ghrecon.utils.logger import get_logger

logger = get_logger("ghrecon.validators.stripe")


async def validate_stripe_key(api_key: str) -> dict:
    """Validate a Stripe API key using a minimal API call."""
    api_key = api_key.strip()
    try:
        async with aiohttp.ClientSession() as session:
            # Use /v1/balance which is read-only
            async with session.get(
                "https://api.stripe.com/v1/balance",
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    is_live = api_key.startswith("sk_live_") or api_key.startswith("rk_live_")
                    return {
                        "valid": True,
                        "live_mode": is_live,
                        "high_value": is_live,
                        "privilege_level": "write" if api_key.startswith("sk_") else "read",
                        "account_info": f"Stripe {'Live' if is_live else 'Test'} Key",
                    }
                elif resp.status == 401:
                    return {"valid": False, "error": "Invalid API key",
                            "high_value": False, "privilege_level": "unknown"}
                else:
                    return {"valid": False, "error": f"HTTP {resp.status}",
                            "high_value": False, "privilege_level": "unknown"}

    except Exception as e:
        logger.error(f"Stripe validation error: {e}")
        return {"valid": None, "error": str(e), "high_value": False, "privilege_level": "unknown"}
