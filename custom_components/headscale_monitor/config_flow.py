"""Config flow for Headscale Monitor."""

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_URL
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import HeadscaleApiClient, HeadscaleError
from .const import CONF_API_KEY, CONF_SCAN_INTERVAL, CONF_VERIFY_TLS, DEFAULT_SCAN_INTERVAL, DOMAIN
from .flow_validation import async_validate_connection, config_flow_error
from .validation import normalize_url, validate_scan_interval


class HeadscaleConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):  # type: ignore[call-arg]
    VERSION = 1

    async def async_step_user(self, user_input=None):
        errors = {}
        if user_input is not None:
            try:
                url = normalize_url(user_input[CONF_URL])
                interval = validate_scan_interval(user_input[CONF_SCAN_INTERVAL])
                client = HeadscaleApiClient(
                    url,
                    user_input[CONF_API_KEY],
                    async_get_clientsession(self.hass),
                    True,
                )
                await async_validate_connection(client)
                await self.async_set_unique_id(url)
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=url,
                    data={
                        CONF_URL: url,
                        CONF_API_KEY: user_input[CONF_API_KEY],
                        CONF_VERIFY_TLS: True,
                        CONF_SCAN_INTERVAL: interval,
                    },
                )
            except HeadscaleError as exc:
                errors["base"] = config_flow_error(exc)
            except ValueError:
                errors["base"] = "invalid_data"
        schema = vol.Schema(
            {
                vol.Required(CONF_URL): str,
                vol.Required(CONF_API_KEY): str,
                vol.Required(CONF_SCAN_INTERVAL, default=DEFAULT_SCAN_INTERVAL): vol.All(
                    int, vol.Range(min=30, max=3600)
                ),
            }
        )
        return self.async_show_form(
            step_id="user",
            data_schema=schema,  # type: ignore[arg-type]
            errors=errors,
        )
