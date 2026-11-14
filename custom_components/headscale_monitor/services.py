"""Validated direct-control services for Headscale."""

from __future__ import annotations

import ipaddress
import logging
import re
from collections.abc import Sequence

from .const import DOMAIN

SERVICE_NAMES = (
    "approve_registration",
    "reject_registration",
    "set_approved_routes",
    "rename_node",
    "set_tags",
    "expire_node",
)

_AUTH_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_LOGGER = logging.getLogger(__name__)

_NODE_NAME_RE = re.compile(r"^(?=.{1,63}$)[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$")
_TAG_RE = re.compile(r"^tag:[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")


def validate_node_id(value: object) -> int:
    """Require a positive integer node identifier."""
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError("node_id must be a positive integer")
    return value


def validate_auth_id(value: object) -> str:
    """Require a bounded conservative Headscale auth identifier."""
    if not isinstance(value, str) or _AUTH_ID_RE.fullmatch(value) is None:
        raise ValueError("auth_id contains invalid characters or length")
    return value


def validate_node_name(value: object) -> str:
    """Require one conservative DNS label accepted by Headscale."""
    if not isinstance(value, str) or _NODE_NAME_RE.fullmatch(value) is None:
        raise ValueError("new_name must be a single DNS label of at most 63 characters")
    return value


def _require_string_sequence(value: object, field: str) -> Sequence[str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError(f"{field} must be a list of strings")
    if any(not isinstance(item, str) for item in value):
        raise ValueError(f"{field} must be a list of strings")
    return value


def validate_routes(value: object) -> list[str]:
    """Validate and canonicalize IPv4/IPv6 network routes."""
    routes = _require_string_sequence(value, "routes")
    try:
        return [str(ipaddress.ip_network(route, strict=False)) for route in routes]
    except ValueError as exc:
        raise ValueError("routes must contain valid IP networks") from exc


def validate_tags(value: object) -> list[str]:
    """Require Headscale tags with a conservative character set."""
    tags = _require_string_sequence(value, "tags")
    if not tags or any(_TAG_RE.fullmatch(tag) is None for tag in tags):
        raise ValueError("tags must start with tag: and use conservative characters")
    return list(tags)


def validate_confirmation(value: object) -> bool:
    """Require an explicit true value for destructive actions."""
    if value is not True:
        raise ValueError("confirm must be true")
    return True


def _coordinator_for_call(hass, data):
    from homeassistant.exceptions import ServiceValidationError

    entry_id = data.get("config_entry_id")
    if not isinstance(entry_id, str) or not entry_id:
        raise ServiceValidationError("config_entry_id is required")
    coordinator = hass.data.get(DOMAIN, {}).get(entry_id)
    if coordinator is None:
        raise ServiceValidationError("config_entry_id is not a loaded Headscale entry")
    return coordinator


def _validated(data, key, validator):
    from homeassistant.exceptions import ServiceValidationError

    try:
        return validator(data.get(key))
    except ValueError as exc:
        raise ServiceValidationError(str(exc)) from exc


async def _require_admin(hass, call) -> None:
    """Allow mutations only for an authenticated Home Assistant administrator."""
    from homeassistant.exceptions import ServiceValidationError

    user_id = getattr(getattr(call, "context", None), "user_id", None)
    user = await hass.auth.async_get_user(user_id) if user_id is not None else None
    if user is None or not user.is_admin:
        raise ServiceValidationError(
            "Headscale actions require an authenticated Home Assistant administrator"
        )


async def _run_action(hass, action: str, call) -> None:
    await _require_admin(hass, call)
    data = call.data
    coordinator = _coordinator_for_call(hass, data)
    node_id = None
    try:
        if action in ("approve_registration", "reject_registration"):
            auth_id = _validated(data, "auth_id", validate_auth_id)
            method = getattr(coordinator.client, f"async_{action}")
            await method(auth_id)
        else:
            node_id = _validated(data, "node_id", validate_node_id)
            if action == "set_approved_routes":
                await coordinator.client.async_set_approved_routes(
                    node_id, _validated(data, "routes", validate_routes)
                )
            elif action == "rename_node":
                await coordinator.client.async_rename_node(
                    node_id, _validated(data, "new_name", validate_node_name)
                )
            elif action == "set_tags":
                await coordinator.client.async_set_tags(
                    node_id, _validated(data, "tags", validate_tags)
                )
            elif action == "expire_node":
                _validated(data, "confirm", validate_confirmation)
                await coordinator.client.async_expire_node(node_id)
    except Exception:
        event = {"action": action, "success": False}
        if node_id is not None:
            event["node_id"] = node_id
        hass.bus.async_fire(f"{DOMAIN}_action", event)
        raise
    event = {"action": action, "success": True}
    if node_id is not None:
        event["node_id"] = node_id
    hass.bus.async_fire(f"{DOMAIN}_action", event)
    try:
        await coordinator.async_request_refresh()
    except Exception:
        _LOGGER.warning("Headscale %s succeeded, but the post-action refresh failed", action)


def async_register_services(hass) -> None:
    """Register direct-control services once for all loaded entries."""
    import voluptuous as vol

    schemas = {
        "approve_registration": vol.Schema(
            {vol.Required("config_entry_id"): str, vol.Required("auth_id"): str}
        ),
        "reject_registration": vol.Schema(
            {vol.Required("config_entry_id"): str, vol.Required("auth_id"): str}
        ),
        "set_approved_routes": vol.Schema(
            {
                vol.Required("config_entry_id"): str,
                vol.Required("node_id"): int,
                vol.Required("routes"): list,
            }
        ),
        "rename_node": vol.Schema(
            {
                vol.Required("config_entry_id"): str,
                vol.Required("node_id"): int,
                vol.Required("new_name"): str,
            }
        ),
        "set_tags": vol.Schema(
            {
                vol.Required("config_entry_id"): str,
                vol.Required("node_id"): int,
                vol.Required("tags"): list,
            }
        ),
        "expire_node": vol.Schema(
            {
                vol.Required("config_entry_id"): str,
                vol.Required("node_id"): int,
                vol.Required("confirm"): bool,
            }
        ),
    }
    for action in SERVICE_NAMES:
        if hass.services.has_service(DOMAIN, action):
            continue

        async def handler(call, service_action=action):
            await _run_action(hass, service_action, call)

        hass.services.async_register(DOMAIN, action, handler, schema=schemas[action])


def async_unregister_services(hass) -> None:
    """Remove services after the final integration entry unloads."""
    if hass.data.get(DOMAIN):
        return
    for action in SERVICE_NAMES:
        if hass.services.has_service(DOMAIN, action):
            hass.services.async_remove(DOMAIN, action)
