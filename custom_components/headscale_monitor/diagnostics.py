"""Diagnostics with recursive secret and PII redaction."""

from dataclasses import asdict
from typing import Any

_REDACT = {
    "api_key",
    "apikey",
    "machinekey",
    "nodekey",
    "discokey",
    "preauthkey",
    "pre_auth_key",
    "email",
    "ipaddresses",
    "ip_addresses",
    "lastseen",
    "last_seen",
    "user",
    "hostname",
    "givenname",
    "name",
}


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: ("**REDACTED**" if k.lower() in _REDACT else redact(v)) for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, tuple):
        return tuple(redact(v) for v in value)
    return value


def diagnostic_payload(entry_data: dict[str, Any], snapshot: Any) -> dict[str, Any]:
    """Build serializable diagnostics while removing credentials and PII."""
    return {"entry": redact(entry_data), "snapshot": redact(asdict(snapshot))}


async def async_get_config_entry_diagnostics(hass, entry):
    snapshot = hass.data["headscale_monitor"][entry.entry_id].data
    return diagnostic_payload(dict(entry.data), snapshot)
