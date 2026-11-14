"""DataUpdateCoordinator for read-only Headscale polling."""

from datetime import timedelta

from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import HeadscaleError
from .models import parse_snapshot


class HeadscaleCoordinator(DataUpdateCoordinator):
    def __init__(self, hass, client, interval):
        self.client = client
        super().__init__(hass, __name__, update_interval=timedelta(seconds=interval))

    async def _async_update_data(self):
        try:
            nodes = await self.client.async_get_nodes()
            version = await self.client.async_get_version()
            return parse_snapshot(
                {"nodes": nodes.get("nodes", nodes.get("node", [])), "version": version}
            )
        except HeadscaleError as exc:
            raise UpdateFailed(str(exc)) from exc
