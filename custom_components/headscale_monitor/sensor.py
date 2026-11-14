"""Headscale hub and node sensors."""

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
from homeassistant.const import UnitOfTime

from .const import DOMAIN
from .entity import (
    HeadscaleEntity,
    NodeEntityMixin,
    hub_device_info,
    new_node_ids,
    node_device_info,
    unique_id,
)

HUB_METRICS = (
    "version",
    "total",
    "online",
    "offline",
    "last_update",
    "users",
    "preauth_keys",
    "active_preauth_keys",
    "api_keys",
    "api_keys_expiring_30_days",
    "policy_hash",
    "policy_updated_time",
    "api_response_time",
)
NODE_METRICS = (
    "ips",
    "last_seen",
    "user_display_name",
    "expiration",
    "approved_routes",
    "available_routes",
    "registration_method",
    "tags",
    "subnet_routes",
)


async def async_setup_entry(hass, entry, async_add_entities):
    c = hass.data[DOMAIN][entry.entry_id]
    entities = [HubSensor(c, entry, metric) for metric in HUB_METRICS]
    added_ids = {n.id for n in c.data.nodes}
    entities.extend(
        NodeSensor(c, entry, node.id, metric) for node in c.data.nodes for metric in NODE_METRICS
    )
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
                for metric in NODE_METRICS
            ]
        )

    entry.async_on_unload(c.async_add_listener(add_discovered_nodes))


class HubSensor(HeadscaleEntity, SensorEntity):
    def __init__(self, c, e, metric):
        super().__init__(c, e)
        self.metric = metric
        self._attr_unique_id = unique_id(e.entry_id, "hub", "main", metric)
        self._attr_name = metric.replace("_", " ").title()
        self._attr_translation_key = metric
        self._attr_device_info = hub_device_info(e.entry_id)
        if metric in ("last_update", "policy_updated_time"):
            self._attr_device_class = SensorDeviceClass.TIMESTAMP
        elif metric == "api_response_time":
            self._attr_device_class = SensorDeviceClass.DURATION
            self._attr_native_unit_of_measurement = UnitOfTime.MILLISECONDS

    @property
    def native_value(self):
        snapshot = self.coordinator.data
        nodes = snapshot.nodes
        return {
            "version": snapshot.version,
            "total": len(nodes),
            "online": sum(n.online for n in nodes),
            "offline": sum(not n.online for n in nodes),
            "last_update": snapshot.last_update,
            "users": snapshot.user_count,
            "preauth_keys": snapshot.preauth_key_count,
            "active_preauth_keys": snapshot.active_preauth_key_count,
            "api_keys": snapshot.api_key_count,
            "api_keys_expiring_30_days": snapshot.api_keys_expiring_30_days,
            "policy_hash": snapshot.policy_hash,
            "policy_updated_time": snapshot.policy_updated_at,
            "api_response_time": snapshot.response_time_ms,
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
        self._attr_translation_key = metric
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
            "tags": n.tags,
            "subnet_routes": n.subnet_routes,
        }[self.metric]
        return ", ".join(value) if isinstance(value, tuple) else value
