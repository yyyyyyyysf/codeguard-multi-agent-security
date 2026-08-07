"""Repository URL safety validation (SSRF prevention).

All repo clone URLs MUST pass this check before being handed to
GitPython Repo.clone_from. GitPython accepts file://, ssh://, and
git:// protocols which allow arbitrary filesystem reads and internal
network probes.
"""

from __future__ import annotations

import os
from urllib.parse import urlparse


def repo_url_is_safe(url: str) -> bool:
    """Reject non-HTTPS, unauthorized hosts, and credential-injected URLs.

    Only https:// URLs whose hostname matches the configured whitelist
    are allowed. Userinfo (``user:pass@``) and explicit non-443 ports
    are rejected regardless of host — they are classic SSRF bypass
    vectors (e.g. ``https://github.com@127.0.0.1:8000/x``).

    Configure allowed hosts via ``CODEGUARD_ALLOWED_REPO_HOSTS``
    (comma separated, default ``github.com,gitlab.com``).
    """
    if not url.startswith("https://"):
        return False

    parsed = urlparse(url)

    # Reject userinfo: https://github.com@evil.internal:8000/
    if parsed.username is not None or parsed.password is not None:
        return False

    # Reject explicit port (only default 443 is acceptable)
    if parsed.port is not None and parsed.port != 443:
        return False

    hostname = parsed.hostname
    if not hostname:
        return False

    allowed = os.environ.get(
        "CODEGUARD_ALLOWED_REPO_HOSTS", "github.com,gitlab.com"
    )
    allowed_hosts = [h.strip() for h in allowed.split(",") if h.strip()]

    # Exact hostname match required — no substring tricks.
    return hostname in allowed_hosts


def assert_repo_url_safe(url: str) -> None:
    """Raise ``ValueError`` if *url* fails the safety check.

    Suitable for Pydantic validators and early-exit guards.
    """
    if not repo_url_is_safe(url):
        allowed = os.environ.get(
            "CODEGUARD_ALLOWED_REPO_HOSTS", "github.com,gitlab.com"
        )
        raise ValueError(
            f"repo_url is not allowed. Only https:// URLs with host in "
            f"[{allowed}] are permitted (no userinfo, no custom port)."
        )
