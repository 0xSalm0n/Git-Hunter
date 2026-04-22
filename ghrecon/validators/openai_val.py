"""
OpenAI API key validation using /v1/models endpoint.
"""

import aiohttp
from ghrecon.utils.logger import get_logger

logger = get_logger("ghrecon.validators.openai_val")


async def validate_openai_key(api_key: str) -> dict:
    """Validate an OpenAI API key using the /v1/models endpoint."""
    api_key = api_key.strip()
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "https://api.openai.com/v1/models",
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    models = [m.get("id", "") for m in data.get("data", [])[:10]]
                    has_gpt4 = any("gpt-4" in m for m in models)
                    return {
                        "valid": True,
                        "models_available": len(data.get("data", [])),
                        "sample_models": models,
                        "has_gpt4": has_gpt4,
                        "high_value": True,
                        "privilege_level": "write",
                        "account_info": f"OpenAI Key ({len(data.get('data', []))} models)",
                    }
                elif resp.status == 401:
                    return {"valid": False, "error": "Invalid API key",
                            "high_value": False, "privilege_level": "unknown"}
                elif resp.status == 429:
                    return {"valid": True, "error": "Rate limited but valid",
                            "high_value": True, "privilege_level": "write"}
                else:
                    return {"valid": False, "error": f"HTTP {resp.status}",
                            "high_value": False, "privilege_level": "unknown"}

    except Exception as e:
        logger.error(f"OpenAI validation error: {e}")
        return {"valid": None, "error": str(e), "high_value": False, "privilege_level": "unknown"}
