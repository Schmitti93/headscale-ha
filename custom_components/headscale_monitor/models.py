"""Defensive parsing for Headscale data."""

from dataclasses import dataclass
from typing import Any

from .api import HeadscaleMalformedResponse


@dataclass(frozen=True)
class Node:
    id: int
    name: str
    online: bool
    ip_addresses: tuple[str, ...]
    last_seen: str | None
    user_display_name: str | None
    expiration: str | None
    approved_routes: tuple[str, ...]
    available_routes: tuple[str, ...]
    registration_method: str | None


@dataclass(frozen=True)
class Snapshot:
    version: str
    nodes: tuple[Node, ...]


def parse_snapshot(raw: dict[str, Any]) -> Snapshot:
    version_obj = raw.get("version", {})
    version = (
        version_obj.get("version", "unknown") if isinstance(version_obj, dict) else str(version_obj)
    )
    items = raw.get("nodes", [])
    if not isinstance(items, list):
        raise HeadscaleMalformedResponse("nodes must be a list")
    nodes = []
    for item in items:
        if not isinstance(item, dict) or "id" not in item:
            raise HeadscaleMalformedResponse("node id is required")
        try:
            node_id = int(item["id"])
        except (TypeError, ValueError) as exc:
            raise HeadscaleMalformedResponse("node id must be numeric") from exc
        raw_user = item.get("user")
        user: dict[str, Any] = raw_user if isinstance(raw_user, dict) else {}
        display = user.get("displayName") or user.get("name")
        nodes.append(
            Node(
                node_id,
                str(item.get("name") or f"Node {node_id}"),
                bool(item.get("online", False)),
                tuple(map(str, item.get("ipAddresses") or [])),
                item.get("lastSeen"),
                display,
                item.get("expiry") or item.get("expiration"),
                tuple(map(str, item.get("approvedRoutes") or [])),
                tuple(map(str, item.get("availableRoutes") or [])),
                item.get("registerMethod") or item.get("registrationMethod"),
            )
        )
    return Snapshot(str(version), tuple(nodes))
