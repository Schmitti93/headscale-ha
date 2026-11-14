"""Node online status."""

from homeassistant.components.binary_sensor import BinarySensorDeviceClass, BinarySensorEntity

from .const import DOMAIN
from .entity import HeadscaleEntity, node_device_info, unique_id


async def async_setup_entry(hass, entry, async_add_entities):
    c = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([NodeOnline(c, entry, n.id) for n in c.data.nodes])


class NodeOnline(HeadscaleEntity, BinarySensorEntity):
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY

    def __init__(self, c, e, node_id):
        super().__init__(c, e)
        self.node_id = node_id
        n = self.node
        self._attr_unique_id = unique_id(e.entry_id, "node", node_id, "online")
        self._attr_name = "Online"
        self._attr_device_info = node_device_info(e.entry_id, node_id, n.name)

    @property
    def node(self):
        return next(n for n in self.coordinator.data.nodes if n.id == self.node_id)

    @property
    def is_on(self):
        return self.node.online
