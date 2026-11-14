"""Defensive parsing for Headscale data."""

from dataclasses import dataclass
from datetime import datetime
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
    last_update: datetime | None = None


def extract_node_items(response: dict[str, Any]) -> Any:
    """Return the supported node collection or reject a malformed envelope."""
    if "nodes" in response:
        return response["nodes"]
    if "node" in response:
        return response["node"]
    raise HeadscaleMalformedResponse("response must contain nodes or node")


def _string_list(item: dict[str, Any], field: str) -> tuple[str, ...]:
    value = item.get(field, [])
    if not isinstance(value, list):
        raise HeadscaleMalformedResponse(f"{field} must be a list")
    return tuple(map(str, value))


def build_snapshot(nodes: dict, version: dict, refreshed_at: datetime) -> Snapshot:
    snapshot = parse_snapshot({"nodes": extract_node_items(nodes), "version": version})
    return Snapshot(snapshot.version, snapshot.nodes, refreshed_at)


def parse_snapshot(raw: dict[str, Any]) -> Snapshot:
    version_obj = raw.get("version")
    if isinstance(version_obj, dict):
        version = version_obj.get("version")
        if not isinstance(version, str) or not version:
            raise HeadscaleMalformedResponse("version must be a non-empty string")
    elif isinstance(version_obj, str) and version_obj:
        version = version_obj
    else:
        raise HeadscaleMalformedResponse("version must be a non-empty string")
    items = raw.get("nodes", [])
    if not isinstance(items, list):
        raise HeadscaleMalformedResponse("nodes must be a list")
    nodes = []
    seen_ids: set[int] = set()
    for item in items:
        if not isinstance(item, dict) or "id" not in item:
            raise HeadscaleMalformedResponse("node id is required")
        raw_id = item["id"]
        if isinstance(raw_id, bool) or not isinstance(raw_id, (int, str)):
            raise HeadscaleMalformedResponse("node id must be a positive integer")
        try:
            node_id = int(raw_id)
        except (TypeError, ValueError) as exc:
            raise HeadscaleMalformedResponse("node id must be numeric") from exc
        if node_id <= 0:
            raise HeadscaleMalformedResponse("node id must be a positive integer")
        if node_id in seen_ids:
            raise HeadscaleMalformedResponse(f"duplicate node id: {node_id}")
        seen_ids.add(node_id)
        raw_user = item.get("user")
        user: dict[str, Any] = raw_user if isinstance(raw_user, dict) else {}
        display = user.get("display_name") or user.get("name")
        nodes.append(
            Node(
                node_id,
                str(item.get("name") or f"Node {node_id}"),
                bool(item.get("online", False)),
                _string_list(item, "ip_addresses"),
                item.get("last_seen"),
                display,
                item.get("expiry") or item.get("expiration"),
                _string_list(item, "approved_routes"),
                _string_list(item, "available_routes"),
                item.get("register_method"),
            )
        )
    return Snapshot(str(version), tuple(nodes))
