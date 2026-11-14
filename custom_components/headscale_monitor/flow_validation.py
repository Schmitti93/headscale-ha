"""Connection validation shared by the config flow and tests."""

from typing import Any

from .api import HeadscaleAuthError, HeadscaleConnectionError, HeadscaleError
from .models import Snapshot, parse_snapshot


async def async_validate_connection(client: Any) -> Snapshot:
    """Fetch and parse every resource required by the integration."""
    version = await client.async_get_version()
    nodes = await client.async_get_nodes()
    return parse_snapshot(
        {"version": version, "nodes": nodes.get("nodes", nodes.get("node", []))}
    )


def config_flow_error(exc: HeadscaleError) -> str:
    """Map API failures to user-facing config-flow errors."""
    if isinstance(exc, HeadscaleAuthError):
        return "invalid_auth"
    if isinstance(exc, HeadscaleConnectionError):
        return "cannot_connect"
    return "invalid_data"
