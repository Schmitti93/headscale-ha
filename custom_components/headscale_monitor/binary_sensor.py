"""Node online status."""

from homeassistant.components.binary_sensor import BinarySensorDeviceClass, BinarySensorEntity

from .const import DOMAIN
from .entity import HeadscaleEntity, NodeEntityMixin, new_node_ids, node_device_info, unique_id


async def async_setup_entry(hass, entry, async_add_entities):
    c = hass.data[DOMAIN][entry.entry_id]
    added_ids = {n.id for n in c.data.nodes}
    async_add_entities([NodeOnline(c, entry, n.id) for n in c.data.nodes])

    def add_discovered_nodes():
        discovered = new_node_ids(c.data, added_ids)
        if not discovered:
            return
        added_ids.update(discovered)
        async_add_entities([NodeOnline(c, entry, node_id) for node_id in discovered])

    entry.async_on_unload(c.async_add_listener(add_discovered_nodes))


class NodeOnline(NodeEntityMixin, HeadscaleEntity, BinarySensorEntity):
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY

    def __init__(self, c, e, node_id):
        super().__init__(c, e)
        self.node_id = node_id
        n = self.node
        if n is None:
            raise ValueError(f"node {node_id} is not present")
        self._attr_unique_id = unique_id(e.entry_id, "node", node_id, "online")
        self._attr_name = "Online"
        self._attr_device_info = node_device_info(e.entry_id, node_id, n.name)

    @property
    def is_on(self):
        return self.node.online if self.node is not None else None
