"""Tests for direct Headscale control services."""

from __future__ import annotations

import sys
import types

import pytest

from custom_components.headscale_monitor.api import HeadscaleConnectionError
from custom_components.headscale_monitor.const import DOMAIN
from custom_components.headscale_monitor.services import (
    SERVICE_NAMES,
    async_register_services,
    async_unregister_services,
)


class FakeVoluptuous(types.ModuleType):
    ALLOW_EXTRA = object()

    class Required:
        def __init__(self, key):
            self.key = key

    class Schema:
        def __init__(self, schema, extra=None):
            self.schema = schema
            self.extra = extra


class FakeServices:
    def __init__(self):
        self.handlers = {}
        self.removed = []

    def async_register(self, domain, name, handler, schema=None):
        self.handlers[(domain, name)] = (handler, schema)

    def async_remove(self, domain, name):
        self.removed.append((domain, name))
        self.handlers.pop((domain, name), None)

    def has_service(self, domain, name):
        return (domain, name) in self.handlers


class FakeBus:
    def __init__(self):
        self.events = []

    def async_fire(self, event, data):
        self.events.append((event, data))


class FakeHass:
    def __init__(self, coordinators):
        self.data = {DOMAIN: coordinators}
        self.services = FakeServices()
        self.bus = FakeBus()
        self.auth = FakeAuth()


class FakeUser:
    def __init__(self, is_admin):
        self.is_admin = is_admin


class FakeAuth:
    async def async_get_user(self, user_id):
        return FakeUser(user_id == "admin") if user_id is not None else None


class FakeCoordinator:
    def __init__(self, client):
        self.client = client
        self.refreshes = 0

    async def async_request_refresh(self):
        self.refreshes += 1


class FakeCall:
    def __init__(self, data, user_id: str | None = "admin"):
        self.data = data
        self.context = types.SimpleNamespace(user_id=user_id)


@pytest.fixture
def fake_ha_modules(monkeypatch):
    vol = FakeVoluptuous("voluptuous")
    exceptions = types.ModuleType("homeassistant.exceptions")

    class ServiceValidationError(Exception):
        pass

    exceptions.ServiceValidationError = ServiceValidationError
    monkeypatch.setitem(sys.modules, "voluptuous", vol)
    monkeypatch.setitem(sys.modules, "homeassistant.exceptions", exceptions)
    return ServiceValidationError


@pytest.mark.asyncio
async def test_services_register_once_for_multiple_entries_and_unregister_last(fake_ha_modules):
    hass = FakeHass({"entry-1": FakeCoordinator(object())})

    async_register_services(hass)
    async_register_services(hass)

    assert {name for domain, name in hass.services.handlers if domain == DOMAIN} == set(
        SERVICE_NAMES
    )
    hass.data[DOMAIN]["entry-2"] = FakeCoordinator(object())
    async_unregister_services(hass)
    assert hass.services.removed == []

    hass.data[DOMAIN].clear()
    async_unregister_services(hass)
    assert set(hass.services.removed) == {(DOMAIN, name) for name in SERVICE_NAMES}


@pytest.mark.asyncio
async def test_service_requires_loaded_config_entry_and_never_leaks_inputs(fake_ha_modules):
    class Client:
        async def async_set_tags(self, node_id, tags):
            assert (node_id, tags) == (7, ["tag:router"])
            return {}

    coordinator = FakeCoordinator(Client())
    hass = FakeHass({"entry-1": coordinator})
    async_register_services(hass)
    handler, _ = hass.services.handlers[(DOMAIN, "set_tags")]

    await handler(
        FakeCall(
            {
                "config_entry_id": "entry-1",
                "node_id": 7,
                "tags": ["tag:router"],
            }
        )
    )

    assert coordinator.refreshes == 1
    assert hass.bus.events == [
        ("headscale_monitor_action", {"action": "set_tags", "node_id": 7, "success": True})
    ]
    assert "router" not in repr(hass.bus.events)

    with pytest.raises(fake_ha_modules, match="config_entry_id"):
        await handler(FakeCall({"node_id": 7, "tags": ["tag:router"]}))
    with pytest.raises(fake_ha_modules, match="loaded"):
        await handler(
            FakeCall(
                {
                    "config_entry_id": "not-loaded",
                    "node_id": 7,
                    "tags": ["tag:router"],
                }
            )
        )


@pytest.mark.asyncio
async def test_service_failure_event_is_secret_free_and_does_not_refresh(fake_ha_modules):
    class Client:
        async def async_approve_registration(self, auth_id):
            raise HeadscaleConnectionError(f"failed for {auth_id}")

    coordinator = FakeCoordinator(Client())
    hass = FakeHass({"entry-1": coordinator})
    async_register_services(hass)
    handler, _ = hass.services.handlers[(DOMAIN, "approve_registration")]

    with pytest.raises(HeadscaleConnectionError):
        await handler(
            FakeCall(
                {
                    "config_entry_id": "entry-1",
                    "auth_id": "01234567-89ab-cdef-0123-456789abcdef",
                }
            )
        )

    assert coordinator.refreshes == 0
    assert hass.bus.events == [
        ("headscale_monitor_action", {"action": "approve_registration", "success": False})
    ]
    assert "01234567" not in repr(hass.bus.events)


@pytest.mark.asyncio
async def test_expire_service_requires_explicit_confirmation(fake_ha_modules):
    class Client:
        calls = 0

        async def async_expire_node(self, node_id):
            self.calls += 1

    client = Client()
    hass = FakeHass({"entry-1": FakeCoordinator(client)})
    async_register_services(hass)
    handler, _ = hass.services.handlers[(DOMAIN, "expire_node")]

    with pytest.raises(fake_ha_modules, match="confirm"):
        await handler(FakeCall({"config_entry_id": "entry-1", "node_id": 7}))
    assert client.calls == 0

    await handler(FakeCall({"config_entry_id": "entry-1", "node_id": 7, "confirm": True}))
    assert client.calls == 1


@pytest.mark.asyncio
async def test_services_require_an_administrator(fake_ha_modules):
    hass = FakeHass({"entry-1": FakeCoordinator(object())})
    async_register_services(hass)
    handler, _ = hass.services.handlers[(DOMAIN, "expire_node")]

    for user_id in (None, "normal-user"):
        with pytest.raises(fake_ha_modules, match="administrator"):
            await handler(
                FakeCall(
                    {"config_entry_id": "entry-1", "node_id": 7, "confirm": True},
                    user_id=user_id,
                )
            )


@pytest.mark.asyncio
async def test_refresh_failure_does_not_report_mutation_failure(fake_ha_modules):
    class Client:
        async def async_set_tags(self, node_id, tags):
            return {}

    coordinator = FakeCoordinator(Client())

    async def failed_refresh():
        raise RuntimeError("refresh failed")

    coordinator.async_request_refresh = failed_refresh
    hass = FakeHass({"entry-1": coordinator})
    async_register_services(hass)
    handler, _ = hass.services.handlers[(DOMAIN, "set_tags")]

    await handler(FakeCall({"config_entry_id": "entry-1", "node_id": 7, "tags": ["tag:router"]}))
    assert hass.bus.events == [
        ("headscale_monitor_action", {"action": "set_tags", "node_id": 7, "success": True})
    ]
