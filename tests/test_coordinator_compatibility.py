"""Behavioral compatibility checks for the Home Assistant coordinator API."""

import importlib
import sys
import types


def test_coordinator_uses_2026_11_constructor_contract(monkeypatch) -> None:
    """Pass logger positionally and name by keyword, as HA 2026.11 requires."""
    calls = []

    class DataUpdateCoordinator:
        def __init__(self, hass, logger, *, name, update_interval):
            calls.append((hass, logger, name, update_interval))
            self.hass = hass
            self.data = None

    class UpdateFailed(Exception):
        pass

    homeassistant = types.ModuleType("homeassistant")
    helpers = types.ModuleType("homeassistant.helpers")
    update_coordinator = types.ModuleType("homeassistant.helpers.update_coordinator")
    update_coordinator.DataUpdateCoordinator = DataUpdateCoordinator  # type: ignore[attr-defined]
    update_coordinator.UpdateFailed = UpdateFailed  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "homeassistant", homeassistant)
    monkeypatch.setitem(sys.modules, "homeassistant.helpers", helpers)
    monkeypatch.setitem(sys.modules, "homeassistant.helpers.update_coordinator", update_coordinator)
    sys.modules.pop("custom_components.headscale_monitor.coordinator", None)

    module = importlib.import_module("custom_components.headscale_monitor.coordinator")
    hass = object()
    module.HeadscaleCoordinator(hass, object(), 60)

    assert len(calls) == 1
    assert calls[0][0] is hass
    assert calls[0][2] == "custom_components.headscale_monitor.coordinator"
    assert calls[0][3].total_seconds() == 60
