"""Headscale hub and node sensors."""

from homeassistant.components.sensor import SensorEntity

from .const import DOMAIN
from .entity import (
    HeadscaleEntity,
    NodeEntityMixin,
    hub_device_info,
    new_node_ids,
    node_device_info,
    unique_id,
)


async def async_setup_entry(hass, entry, async_add_entities):
    c = hass.data[DOMAIN][entry.entry_id]
    entities = []
    for metric in ("version", "total", "online", "offline", "last_update"):
        entities.append(HubSensor(c, entry, metric))
    added_ids = {n.id for n in c.data.nodes}
    for n in c.data.nodes:
        for metric in (
            "ips",
            "last_seen",
            "user_display_name",
            "expiration",
            "approved_routes",
            "available_routes",
            "registration_method",
        ):
            entities.append(NodeSensor(c, entry, n.id, metric))
    async_add_entities(entities)

    def add_discovered_nodes():
        discovered = new_node_ids(c.data, added_ids)
        if not discovered:
            return
        added_ids.update(discovered)
        async_add_entities(
            [
                NodeSensor(c, entry, node_id, metric)
                for node_id in discovered
                for metric in (
                    "ips",
                    "last_seen",
                    "user_display_name",
                    "expiration",
                    "approved_routes",
                    "available_routes",
                    "registration_method",
                )
            ]
        )

    entry.async_on_unload(c.async_add_listener(add_discovered_nodes))


class HubSensor(HeadscaleEntity, SensorEntity):
    def __init__(self, c, e, metric):
        super().__init__(c, e)
        self.metric = metric
        self._attr_unique_id = unique_id(e.entry_id, "hub", "main", metric)
        self._attr_name = metric.replace("_", " ").title()
        self._attr_device_info = hub_device_info(e.entry_id)

    @property
    def native_value(self):
        nodes = self.coordinator.data.nodes
        return {
            "version": self.coordinator.data.version,
            "total": len(nodes),
            "online": sum(n.online for n in nodes),
            "offline": sum(not n.online for n in nodes),
            "last_update": self.coordinator.data.last_update,
        }[self.metric]


class NodeSensor(NodeEntityMixin, HeadscaleEntity, SensorEntity):
    def __init__(self, c, e, node_id, metric):
        super().__init__(c, e)
        self.node_id = node_id
        self.metric = metric
        n = self.node
        if n is None:
            raise ValueError(f"node {node_id} is not present")
        self._attr_unique_id = unique_id(e.entry_id, "node", node_id, metric)
        self._attr_name = metric.replace("_", " ").title()
        self._attr_device_info = node_device_info(e.entry_id, node_id, n.name)

    @property
    def native_value(self):
        n = self.node
        if n is None:
            return None
        value = {
            "ips": n.ip_addresses,
            "last_seen": n.last_seen,
            "user_display_name": n.user_display_name,
            "expiration": n.expiration,
            "approved_routes": n.approved_routes,
            "available_routes": n.available_routes,
            "registration_method": n.registration_method,
        }[self.metric]
        return ", ".join(value) if isinstance(value, tuple) else value
