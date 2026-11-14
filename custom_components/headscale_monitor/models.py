"""Defensive parsing for Headscale data."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from time import monotonic
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
    tags: tuple[str, ...] = ()
    subnet_routes: tuple[str, ...] = ()


@dataclass(frozen=True)
class Snapshot:
    version: str
    nodes: tuple[Node, ...]
    last_update: datetime | None = None
    user_count: int = 0
    preauth_key_count: int = 0
    active_preauth_key_count: int = 0
    api_key_count: int = 0
    api_keys_expiring_30_days: int = 0
    policy_hash: str | None = None
    policy_updated_at: datetime | None = None
    database_connectivity: bool | None = None
    response_time_ms: float | None = None


def extract_node_items(response: dict[str, Any]) -> Any:
    """Return the supported node collection or reject a malformed envelope."""
    if "nodes" in response:
        return response["nodes"]
    if "node" in response:
        return response["node"]
    raise HeadscaleMalformedResponse("response must contain nodes or node")


def _value(item: dict[str, Any], snake: str, camel: str) -> Any:
    return item[camel] if camel in item else item.get(snake)


def _string_list(item: dict[str, Any], field: str, camel: str | None = None) -> tuple[str, ...]:
    value = _value(item, field, camel or field) or []
    if not isinstance(value, list):
        raise HeadscaleMalformedResponse(f"{field} must be a list")
    return tuple(map(str, value))


def _items(response: dict[str, Any] | None, *fields: str) -> list[Any]:
    if response is None:
        return []
    value: Any = []
    for field in fields:
        if field in response:
            value = response[field]
            break
    if not isinstance(value, list):
        raise HeadscaleMalformedResponse(f"{fields[0]} must be a list")
    return value


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed
    except ValueError:
        return None


def _optional_bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def build_snapshot(
    nodes: dict,
    version: dict,
    refreshed_at: datetime,
    *,
    users: dict[str, Any] | None = None,
    preauth_keys: dict[str, Any] | None = None,
    api_keys: dict[str, Any] | None = None,
    policy: dict[str, Any] | None = None,
    health: dict[str, Any] | None = None,
    response_time_ms: float | None = None,
) -> Snapshot:
    policy_data = policy or {}
    snapshot = parse_snapshot({
        "nodes": extract_node_items(nodes),
        "version": version,
        "policy": policy_data.get("policy"),
    })
    preauth_items = _items(preauth_keys, "preAuthKeys", "pre_auth_keys")
    api_items = _items(api_keys, "apiKeys", "api_keys")
    horizon = refreshed_at + timedelta(days=30)
    active_preauth = sum(
        not bool(item.get("used"))
        and (
            (expiration := _parse_time(item.get("expiration"))) is None
            or expiration > refreshed_at
        )
        for item in preauth_items
        if isinstance(item, dict)
    )
    expiring_api = sum(
        (expiration := _parse_time(item.get("expiration"))) is not None
        and refreshed_at <= expiration <= horizon
        for item in api_items
        if isinstance(item, dict)
    )
    return Snapshot(
        snapshot.version,
        snapshot.nodes,
        refreshed_at,
        len(_items(users, "users")),
        len(preauth_items),
        active_preauth,
        len(api_items),
        expiring_api,
        snapshot.policy_hash,
        _parse_time(policy_data.get("updatedAt") or policy_data.get("updated_at")),
        _optional_bool(
            (health or {}).get(
                "databaseConnectivity", (health or {}).get("database_connectivity")
            )
        ),
        response_time_ms,
    )


async def async_fetch_snapshot(
    client: Any, refreshed_at: datetime, *, timer: Any = monotonic
) -> Snapshot:
    """Fetch all read-only resources and build one sanitized snapshot."""
    started = timer()
    nodes = await client.async_get_nodes()
    version = await client.async_get_version()
    users = await client.async_get_users()
    preauth_keys = await client.async_get_preauth_keys()
    api_keys = await client.async_get_api_keys()
    policy = await client.async_get_policy()
    health = await client.async_get_health()
    elapsed_ms = (timer() - started) * 1000
    return build_snapshot(
        nodes,
        version,
        refreshed_at,
        users=users,
        preauth_keys=preauth_keys,
        api_keys=api_keys,
        policy=policy,
        health=health,
        response_time_ms=elapsed_ms,
    )


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
        display = user.get("displayName") or user.get("display_name") or user.get("name")
        approved_routes = _string_list(item, "approved_routes", "approvedRoutes")
        available_routes = _string_list(item, "available_routes", "availableRoutes")
        nodes.append(
            Node(
                node_id,
                str(item.get("name") or f"Node {node_id}"),
                bool(item.get("online", False)),
                _string_list(item, "ip_addresses", "ipAddresses"),
                _value(item, "last_seen", "lastSeen"),
                display,
                item.get("expiry") or item.get("expiration"),
                approved_routes,
                available_routes,
                _value(item, "register_method", "registerMethod"),
                _string_list(item, "tags"),
                _string_list(item, "subnet_routes", "subnetRoutes"),
            )
        )
    policy = raw.get("policy")
    policy_hash = sha256(policy.encode()).hexdigest() if isinstance(policy, str) else None
    return Snapshot(str(version), tuple(nodes), policy_hash=policy_hash)


def diff_events(old: Snapshot, new: Snapshot) -> tuple[tuple[str, dict[str, Any]], ...]:
    """Describe safe, secret-free changes between successful refreshes."""
    old_nodes = {node.id: node for node in old.nodes}
    new_nodes = {node.id: node for node in new.nodes}
    events: list[tuple[str, dict[str, Any]]] = []
    for node_id in sorted(new_nodes.keys() - old_nodes.keys()):
        node = new_nodes[node_id]
        events.append(("node_added", {"node_id": node.id, "node_name": node.name}))
    for node_id in sorted(old_nodes.keys() - new_nodes.keys()):
        node = old_nodes[node_id]
        events.append(("node_removed", {"node_id": node.id, "node_name": node.name}))
    for node_id in sorted(old_nodes.keys() & new_nodes.keys()):
        before, after = old_nodes[node_id], new_nodes[node_id]
        if before.online != after.online:
            event = "node_online" if after.online else "node_offline"
            events.append((event, {"node_id": after.id, "node_name": after.name}))
    if old.policy_hash != new.policy_hash and (old.policy_hash or new.policy_hash):
        events.append(("policy_changed", {
            "old_policy_hash": old.policy_hash,
            "new_policy_hash": new.policy_hash,
        }))
    return tuple(events)
