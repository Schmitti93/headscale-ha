"""Headscale Monitor integration."""

from .const import DOMAIN, PLATFORMS


async def async_setup_entry(hass, entry):
    from homeassistant.exceptions import ConfigEntryError
    from homeassistant.helpers.aiohttp_client import async_get_clientsession

    from .api import HeadscaleApiClient, create_ssl_context
    from .const import (
        CONF_API_KEY,
        CONF_CA_CERTIFICATE,
        CONF_SCAN_INTERVAL,
        DEFAULT_SCAN_INTERVAL,
    )
    from .coordinator import HeadscaleCoordinator
    from .validation import validate_entry_transport

    try:
        url = validate_entry_transport(entry.data)
        ca_certificate = entry.data.get(CONF_CA_CERTIFICATE)
        ssl_context = None
        if ca_certificate:
            ssl_context = await hass.async_add_executor_job(create_ssl_context, ca_certificate)
    except ValueError as exc:
        raise ConfigEntryError(f"Insecure or invalid Headscale config entry: {exc}") from exc

    client = HeadscaleApiClient(
        url,
        entry.data[CONF_API_KEY],
        async_get_clientsession(hass),
        ssl_context=ssl_context,
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
