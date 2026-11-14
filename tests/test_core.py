import json

import pytest

from custom_components.headscale_monitor.api import (
    HeadscaleApiClient,
    HeadscaleAuthError,
    HeadscaleMalformedResponse,
    HeadscaleResponseTooLarge,
)
from custom_components.headscale_monitor.diagnostics import diagnostic_payload, redact
from custom_components.headscale_monitor.models import parse_snapshot
from custom_components.headscale_monitor.validation import normalize_url, validate_scan_interval


def test_url_normalization_and_interval_bounds() -> None:
    assert normalize_url(" HTTPS://Example.COM/ ") == "https://example.com"
    assert validate_scan_interval(30) == 30
    assert validate_scan_interval(3600) == 3600
    with pytest.raises(ValueError):
        normalize_url("ftp://example.com")
    with pytest.raises(ValueError):
        normalize_url("https://example.com/?token=x")
    with pytest.raises(ValueError):
        normalize_url("https://example.com/unexpected/path")
    with pytest.raises(ValueError):
        validate_scan_interval(29)


def test_parse_snapshot_handles_headscale_v1_fields() -> None:
    raw = {
        "version": {"version": "0.29.3"},
        "nodes": [
            {
                "id": "42",
                "name": "laptop",
                "online": True,
                "ipAddresses": ["100.64.0.1"],
                "lastSeen": "2026-01-02T03:04:05Z",
                "user": {
                    "id": "7",
                    "name": "Alice",
                    "displayName": "Alice A",
                    "email": "alice@example.com",
                },
                "expiry": "2027-01-01T00:00:00Z",
                "approvedRoutes": ["10.0.0.0/24"],
                "availableRoutes": ["0.0.0.0/0"],
                "registerMethod": "auth-key",
                "machineKey": "mkey:secret",
                "nodeKey": "nodekey:secret",
                "discoKey": "discokey:secret",
            }
        ],
    }
    snapshot = parse_snapshot(raw)
    node = snapshot.nodes[0]
    assert (snapshot.version, node.id, node.user_display_name) == ("0.29.3", 42, "Alice A")
    assert node.approved_routes == ("10.0.0.0/24",)


def test_parse_snapshot_rejects_missing_stable_id() -> None:
    with pytest.raises(HeadscaleMalformedResponse, match="id"):
        parse_snapshot({"version": {"version": "0.29.3"}, "nodes": [{"name": "bad"}]})


def test_redaction_is_recursive_and_preserves_safe_data() -> None:
    value = {
        "api_key": "secret",
        "machineKey": "m",
        "email": "a@b",
        "name": "safe",
        "nested": [{"preAuthKey": "p", "ipAddresses": ["100.64.0.1"]}],
    }
    result = redact(value)
    assert result["api_key"] == "**REDACTED**"
    assert result["machineKey"] == "**REDACTED**"
    assert result["email"] == "**REDACTED**"
    assert result["name"] == "**REDACTED**"
    assert result["nested"][0]["ipAddresses"] == "**REDACTED**"


def test_diagnostic_payload_converts_snapshot_and_redacts_pii() -> None:
    snapshot = parse_snapshot(
        {
            "version": {"version": "0.29.3"},
            "nodes": [{"id": 1, "name": "private-host", "ipAddresses": ["100.64.0.1"]}],
        }
    )
    result = diagnostic_payload({"api_key": "secret"}, snapshot)
    assert result["entry"]["api_key"] == "**REDACTED**"
    assert result["snapshot"]["nodes"][0]["name"] == "**REDACTED**"


class FakeResponse:
    def __init__(self, status: int, body: bytes, content_length: int | None = None):
        self.status, self._body, self.content_length = status, body, content_length

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def read(self):
        return self._body


class FakeSession:
    def __init__(self, response):
        self.response, self.calls = response, []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.response


@pytest.mark.asyncio
async def test_api_uses_bearer_auth_and_read_only_get() -> None:
    session = FakeSession(FakeResponse(200, json.dumps({"nodes": []}).encode()))
    client = HeadscaleApiClient("https://hs.example", "top-secret", session)
    assert await client.async_get_nodes() == {"nodes": []}
    url, kwargs = session.calls[0]
    assert url == "https://hs.example/api/v1/node"
    assert kwargs["headers"]["Authorization"] == "Bearer top-secret"


@pytest.mark.asyncio
async def test_api_maps_auth_and_size_errors() -> None:
    client = HeadscaleApiClient("https://hs.example", "x", FakeSession(FakeResponse(401, b"")))
    with pytest.raises(HeadscaleAuthError):
        await client.async_get_nodes()
    client = HeadscaleApiClient(
        "https://hs.example", "x", FakeSession(FakeResponse(200, b"{}", 2_000_000))
    )
    with pytest.raises(HeadscaleResponseTooLarge):
        await client.async_get_nodes()
