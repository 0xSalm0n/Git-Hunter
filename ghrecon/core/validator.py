"""
Credential validation orchestrator.
Dispatches secrets to type-specific validators and aggregates results.
"""

import asyncio
from typing import Optional

from ghrecon.utils.logger import get_logger
from ghrecon.config import GHReconConfig

logger = get_logger("ghrecon.validator")


class SecretValidator:
    """Orchestrates credential validation across all supported platforms."""

    def __init__(self, config: GHReconConfig):
        self.config = config
        self._validators: dict = {}
        self._init_validators()

    def _init_validators(self) -> None:
        """Initialize platform-specific validators based on config."""
        from ghrecon.validators.aws import validate_aws_credentials
        from ghrecon.validators.github_val import validate_github_token
        from ghrecon.validators.slack import validate_slack_token
        from ghrecon.validators.google import validate_google_api_key
        from ghrecon.validators.stripe import validate_stripe_key
        from ghrecon.validators.openai_val import validate_openai_key

        v = self.config.validation
        if v.validate_aws:
            self._validators["aws_access_key"] = validate_aws_credentials
            self._validators["aws_secret"] = validate_aws_credentials
        if v.validate_github:
            self._validators["github_pat"] = validate_github_token
            self._validators["github_oauth"] = validate_github_token
            self._validators["github_app"] = validate_github_token
            self._validators["github_refresh"] = validate_github_token
        if v.validate_slack:
            self._validators["slack_token"] = validate_slack_token
        if v.validate_stripe:
            self._validators["stripe_live"] = validate_stripe_key
            self._validators["stripe_restricted"] = validate_stripe_key
        if v.validate_google:
            self._validators["google_api"] = validate_google_api_key
        if v.validate_openai:
            self._validators["openai_api"] = validate_openai_key
            self._validators["openai_api_v2"] = validate_openai_key

    async def validate_secret(self, secret_type: str, secret_value: str) -> dict:
        """Validate a single secret. Returns validation result dict."""
        validator = self._validators.get(secret_type)
        if not validator:
            return {
                "valid": None,
                "error": f"No validator for type: {secret_type}",
                "high_value": False,
                "privilege_level": "unknown"
            }

        try:
            result = await asyncio.wait_for(
                validator(secret_value),
                timeout=self.config.validation.timeout
            )
            return result
        except asyncio.TimeoutError:
            logger.warning(f"Validation timeout for {secret_type}")
            return {"valid": None, "error": "timeout", "high_value": False, "privilege_level": "unknown"}
        except Exception as e:
            logger.error(f"Validation error for {secret_type}: {e}")
            return {"valid": None, "error": str(e), "high_value": False, "privilege_level": "unknown"}

    async def validate_batch(self, secrets: list[dict],
                              max_parallel: int = 10) -> list[dict]:
        """Validate multiple secrets in parallel with semaphore."""
        semaphore = asyncio.Semaphore(max_parallel)
        results = []

        async def validate_one(secret: dict) -> dict:
            async with semaphore:
                result = await self.validate_secret(
                    secret.get("secret_type", ""),
                    secret.get("secret_value", "") or secret.get("value", "")
                )
                return {
                    "secret_id": secret.get("secret_id"),
                    "secret_type": secret.get("secret_type", ""),
                    "validation": result
                }

        tasks = [validate_one(s) for s in secrets]
        completed = await asyncio.gather(*tasks, return_exceptions=True)

        for item in completed:
            if isinstance(item, Exception):
                logger.error(f"Validation task error: {item}")
                results.append({"validation": {"valid": None, "error": str(item)}})
            else:
                results.append(item)

        valid_count = sum(1 for r in results
                          if r.get("validation", {}).get("valid") is True)
        logger.info(f"Validated {len(results)} secrets: {valid_count} valid")
        return results

    def can_validate(self, secret_type: str) -> bool:
        """Check if a validator exists for the given secret type."""
        return secret_type in self._validators
