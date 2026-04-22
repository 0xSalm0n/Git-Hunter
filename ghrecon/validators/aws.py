"""
AWS credential validation using STS GetCallerIdentity (read-only).
"""

import re
import hashlib
import hmac
from datetime import datetime, timezone
from urllib.parse import quote

import aiohttp

from ghrecon.utils.logger import get_logger

logger = get_logger("ghrecon.validators.aws")


def _sign_aws_request(access_key: str, secret_key: str, region: str = "us-east-1") -> dict:
    """Generate AWS Signature V4 headers for STS GetCallerIdentity."""
    service = "sts"
    host = "sts.amazonaws.com"
    endpoint = "https://sts.amazonaws.com"
    method = "POST"
    body = "Action=GetCallerIdentity&Version=2011-06-15"
    content_type = "application/x-www-form-urlencoded; charset=utf-8"

    now = datetime.now(timezone.utc)
    datestamp = now.strftime("%Y%m%d")
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    credential_scope = f"{datestamp}/{region}/{service}/aws4_request"

    canonical_headers = (
        f"content-type:{content_type}\n"
        f"host:{host}\n"
        f"x-amz-date:{amz_date}\n"
    )
    signed_headers = "content-type;host;x-amz-date"

    payload_hash = hashlib.sha256(body.encode()).hexdigest()
    canonical_request = (
        f"{method}\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    )

    string_to_sign = (
        f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n"
        f"{hashlib.sha256(canonical_request.encode()).hexdigest()}"
    )

    def _sign(key, msg):
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    k_date = _sign(f"AWS4{secret_key}".encode(), datestamp)
    k_region = _sign(k_date, region)
    k_service = _sign(k_region, service)
    k_signing = _sign(k_service, "aws4_request")

    signature = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()

    authorization = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    return {
        "Content-Type": content_type,
        "Host": host,
        "X-Amz-Date": amz_date,
        "Authorization": authorization,
    }


async def validate_aws_credentials(credential: str) -> dict:
    """
    Validate AWS credentials using STS GetCallerIdentity.
    Expects credential in format 'AKIAXXXXXX' (access key) — looks for
    a paired secret key in context, or validates access key existence only.
    """
    # Try to extract access key
    access_key_match = re.search(r'(AKIA[0-9A-Z]{16})', credential)
    if not access_key_match:
        return {"valid": False, "error": "No valid AWS access key found", "high_value": False, "privilege_level": "unknown"}

    access_key = access_key_match.group(1)

    # Try to find a secret key nearby (common co-occurrence)
    secret_match = re.search(r'([A-Za-z0-9/+=]{40})', credential)
    if not secret_match or secret_match.group(1) == access_key:
        # Can't validate without secret key, but access key format is valid
        return {
            "valid": None,
            "access_key": access_key[:8] + "..." + access_key[-4:],
            "error": "Secret key not found — cannot fully validate",
            "high_value": False,
            "privilege_level": "unknown",
            "note": "Access key format is valid (AKIA prefix)"
        }

    secret_key = secret_match.group(1)

    try:
        headers = _sign_aws_request(access_key, secret_key)
        body = "Action=GetCallerIdentity&Version=2011-06-15"

        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://sts.amazonaws.com",
                headers=headers,
                data=body,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                response_text = await resp.text()

                if resp.status == 200 and "<GetCallerIdentityResult>" in response_text:
                    # Parse response
                    account = _extract_xml(response_text, "Account")
                    arn = _extract_xml(response_text, "Arn")
                    user_id = _extract_xml(response_text, "UserId")

                    # Determine privilege level from ARN
                    high_value = False
                    priv = "read"
                    if arn:
                        if ":root" in arn:
                            high_value = True
                            priv = "admin"
                        elif "admin" in arn.lower() or "power" in arn.lower():
                            high_value = True
                            priv = "admin"

                    return {
                        "valid": True,
                        "account_id": account,
                        "arn": arn,
                        "user_id": user_id,
                        "access_key": access_key[:8] + "...",
                        "high_value": high_value,
                        "privilege_level": priv,
                    }
                else:
                    return {
                        "valid": False,
                        "error": f"STS returned {resp.status}",
                        "high_value": False,
                        "privilege_level": "unknown"
                    }

    except Exception as e:
        logger.error(f"AWS validation error: {e}")
        return {"valid": False, "error": str(e), "high_value": False, "privilege_level": "unknown"}


def _extract_xml(text: str, tag: str) -> str:
    """Extract value from simple XML tag."""
    match = re.search(rf'<{tag}>([^<]+)</{tag}>', text)
    return match.group(1) if match else ""
