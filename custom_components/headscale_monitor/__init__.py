"""Headscale Monitor integration."""

from .const import DOMAIN, PLATFORMS


async def async_setup_entry(hass, entry):
    from homeassistant.const import CONF_URL
    from homeassistant.helpers.aiohttp_client import async_get_clientsession

    from .api import HeadscaleApiClient
    from .const import CONF_API_KEY, CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL
    from .coordinator import HeadscaleCoordinator

    client = HeadscaleApiClient(
        entry.data[CONF_URL],
        entry.data[CONF_API_KEY],
        async_get_clientsession(hass),
        True,
    )
    coordinator = HeadscaleCoordinator(
        hass,
        client,
        entry.options.get(
            CONF_SCAN_INTERVAL, entry.data.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
        ),
    )
    await coordinator.async_config_entry_first_refresh()
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator
    entry.async_on_unload(entry.add_update_listener(_async_reload))
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def _async_reload(hass, entry):
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass, entry):
    ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return ok
