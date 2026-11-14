"""Config flow for Headscale Monitor."""

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_URL
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.selector import TextSelector, TextSelectorConfig

from .api import HeadscaleApiClient, HeadscaleError, create_ssl_context
from .const import (
    CONF_API_KEY,
    CONF_CA_CERTIFICATE,
    CONF_SCAN_INTERVAL,
    CONF_VERIFY_TLS,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
)
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
                ca_certificate = user_input.get(CONF_CA_CERTIFICATE, "").strip()
                ssl_context = None
                if ca_certificate:
                    ssl_context = await self.hass.async_add_executor_job(
                        create_ssl_context, ca_certificate
                    )
                client = HeadscaleApiClient(
                    url,
                    user_input[CONF_API_KEY],
                    async_get_clientsession(self.hass),
                    ssl_context=ssl_context,
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
                        CONF_CA_CERTIFICATE: ca_certificate,
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
                vol.Optional(CONF_CA_CERTIFICATE, default=""): vol.All(
                    TextSelector(TextSelectorConfig(multiline=True)), vol.Length(max=65_536)
                ),
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
