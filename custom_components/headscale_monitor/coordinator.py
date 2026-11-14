"""DataUpdateCoordinator for read-only Headscale polling."""

import logging
from datetime import timedelta

from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import HeadscaleError
from .const import DOMAIN
from .models import async_fetch_snapshot, diff_events

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
            from homeassistant.util import dt as dt_util

            previous = self.data
            snapshot = await async_fetch_snapshot(self.client, dt_util.utcnow())
            if previous is not None:
                for event, data in diff_events(previous, snapshot):
                    self.hass.bus.async_fire(f"{DOMAIN}_{event}", data)
            return snapshot
        except HeadscaleError as exc:
            raise UpdateFailed(str(exc)) from exc
