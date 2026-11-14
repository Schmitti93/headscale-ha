"""Stable identity helpers and coordinator entity base."""

from .const import DOMAIN


def unique_id(entry_id: str, kind: str, object_id: int | str, metric: str) -> str:
    return f"{entry_id}_{kind}_{object_id}_{metric}"


def hub_device_info(entry_id: str) -> dict:
    return {
        "identifiers": {(DOMAIN, entry_id)},
        "name": "Headscale",
        "manufacturer": "Headscale",
        "model": "Control server",
    }


def node_device_info(entry_id: str, node_id: int, name: str) -> dict:
    return {
        "identifiers": {(DOMAIN, f"{entry_id}_node_{node_id}")},
        "via_device": (DOMAIN, entry_id),
        "name": name,
        "manufacturer": "Headscale",
        "model": "Node",
    }


try:
    from homeassistant.helpers.update_coordinator import CoordinatorEntity

    class HeadscaleEntity(CoordinatorEntity):
        _attr_has_entity_name = True

        def __init__(self, coordinator, entry):
            super().__init__(coordinator)
            self.entry = entry
except ImportError:

    class HeadscaleEntity:  # type: ignore[no-redef]
        pass
