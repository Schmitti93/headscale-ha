"""DataUpdateCoordinator for read-only Headscale polling."""

import logging
from datetime import timedelta

from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import HeadscaleError
from .models import build_snapshot

_LOGGER = logging.getLogger(__name__)


class HeadscaleCoordinator(DataUpdateCoordinator):
    def __init__(self, hass, client, interval):
        self.client = client
        super().__init__(
            hass,
            _LOGGER,
            name=__name__,
            update_interval=timedelta(seconds=interval),
        )

    async def _async_update_data(self):
        try:
            nodes = await self.client.async_get_nodes()
            version = await self.client.async_get_version()
            from homeassistant.util import dt as dt_util

            return build_snapshot(nodes, version, dt_util.utcnow())
        except HeadscaleError as exc:
            raise UpdateFailed(str(exc)) from exc
