"""HMAC-SHA256 signing utilities for webhook validation.

Used for:
- Inbound: Verifying GitHub/GitLab webhook signatures.
- Outbound: Signing CodeGuard callback payloads.
"""

from __future__ import annotations

import hashlib
import hmac


def compute_hmac_sha256(payload: str | bytes, secret: str) -> str:
    """Compute HMAC-SHA256 hex digest.

    Args:
        payload: The message body to sign.
        secret: Pre-shared secret key.

    Returns:
        Hex-encoded HMAC-SHA256 digest.
    """
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    secret_bytes = secret.encode("utf-8")
    return hmac.new(secret_bytes, payload, hashlib.sha256).hexdigest()


def verify_signature(payload: str | bytes, secret: str, signature: str) -> bool:
    """Verify an HMAC-SHA256 signature using constant-time comparison.

    Args:
        payload: The raw request body.
        secret: Pre-shared secret key.
        signature: The signature to verify (hex string, with or without 'sha256=' prefix).

    Returns:
        True if the signature is valid.
    """
    expected = compute_hmac_sha256(payload, secret)
    # Strip "sha256=" prefix if present (GitHub format)
    actual = signature.removeprefix("sha256=")
    return hmac.compare_digest(expected, actual)


def generate_callback_signature(payload: str | bytes, pre_shared_key: str) -> tuple[str, str]:
    """Generate the CodeGuard callback signature header.

    Args:
        payload: The callback request body.
        pre_shared_key: The pre-shared key configured for the callback receiver.

    Returns:
        (header_name, header_value) tuple.
        e.g., ("X-CodeGuard-Signature-256", "sha256=abc123...")
    """
    digest = compute_hmac_sha256(payload, pre_shared_key)
    return ("X-CodeGuard-Signature-256", f"sha256={digest}")
