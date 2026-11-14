"""Input validation for Headscale Monitor."""

from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit, urlunsplit


def normalize_url(value: str) -> str:
    """Return a canonical HTTPS origin without trailing slash."""
    parsed = urlsplit(value.strip())
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("embedded credentials are not allowed")
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("URL must use HTTPS and include a host")
    if parsed.query or parsed.fragment:
        raise ValueError("query strings and fragments are not allowed")
    if parsed.path not in {"", "/"}:
        raise ValueError("URL must not include a path")
    path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, "", ""))


def validate_scan_interval(value: int) -> int:
    """Validate polling interval bounds."""
    interval = int(value)
    if not 30 <= interval <= 3600:
        raise ValueError("scan interval must be between 30 and 3600 seconds")
    return interval


def validate_entry_transport(data: Mapping[str, Any]) -> str:
    """Reject insecure transport settings in legacy config entries."""
    if data.get("verify_tls", True) is not True:
        raise ValueError("TLS certificate verification is required")
    return normalize_url(str(data.get("url", "")))
