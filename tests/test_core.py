import json
from datetime import UTC, datetime

import pytest

from custom_components.headscale_monitor.api import (
    HeadscaleApiClient,
    HeadscaleAuthError,
    HeadscaleMalformedResponse,
    HeadscaleResponseTooLarge,
)
from custom_components.headscale_monitor.diagnostics import diagnostic_payload, redact
from custom_components.headscale_monitor.flow_validation import (
    async_validate_connection,
    config_flow_error,
)
from custom_components.headscale_monitor.models import build_snapshot, parse_snapshot
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


def test_api_client_rejects_insecure_transport_settings() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        HeadscaleApiClient("http://hs.example", "secret", FakeSession(FakeResponse(200, b"{}")))
    with pytest.raises(ValueError, match="certificate verification"):
        HeadscaleApiClient(
            "https://hs.example",
            "secret",
            FakeSession(FakeResponse(200, b"{}")),
            verify_tls=False,
        )


def test_parse_snapshot_handles_headscale_0293_snake_case_fields() -> None:
    raw = {
        "version": {"version": "0.29.3"},
        "nodes": [
            {
                "id": "42",
                "name": "laptop",
                "online": True,
                "ip_addresses": ["100.64.0.1"],
                "last_seen": "2026-01-02T03:04:05Z",
                "user": {
                    "id": "7",
                    "name": "Alice",
                    "display_name": "Alice A",
                    "email": "alice@example.com",
                },
                "expiry": "2027-01-01T00:00:00Z",
                "approved_routes": ["10.0.0.0/24"],
                "available_routes": ["0.0.0.0/0"],
                "register_method": "auth-key",
                "machine_key": "mkey:secret",
                "node_key": "nodekey:secret",
                "disco_key": "discokey:secret",
            }
        ],
    }
    snapshot = parse_snapshot(raw)
    node = snapshot.nodes[0]
    assert (snapshot.version, node.id, node.user_display_name) == ("0.29.3", 42, "Alice A")
    assert node.ip_addresses == ("100.64.0.1",)
    assert node.approved_routes == ("10.0.0.0/24",)


def test_parse_snapshot_rejects_missing_stable_id() -> None:
    with pytest.raises(HeadscaleMalformedResponse, match="id"):
        parse_snapshot({"version": {"version": "0.29.3"}, "nodes": [{"name": "bad"}]})


@pytest.mark.parametrize("node_id", [0, -1, True, 1.5, "not-a-number"])
def test_parse_snapshot_rejects_invalid_ids(node_id) -> None:
    with pytest.raises(HeadscaleMalformedResponse, match="id"):
        parse_snapshot({"version": "0.29.3", "nodes": [{"id": node_id}]})


def test_parse_snapshot_rejects_duplicate_ids_and_non_list_fields() -> None:
    with pytest.raises(HeadscaleMalformedResponse, match="duplicate"):
        parse_snapshot({"version": "0.29.3", "nodes": [{"id": 1}, {"id": "1"}]})
    with pytest.raises(HeadscaleMalformedResponse, match="ip_addresses"):
        parse_snapshot({"version": "0.29.3", "nodes": [{"id": 1, "ip_addresses": "x"}]})


def test_redaction_is_recursive_and_covers_topology() -> None:
    value = {
        "api_key": "secret",
        "url": "https://private.example",
        "machine_key": "m",
        "email": "a@b",
        "name": "private-host",
        "nested": [{"pre_auth_key": "p", "ip_addresses": ["100.64.0.1"]}],
        "approved_routes": ["10.0.0.0/24"],
        "available_routes": ["0.0.0.0/0"],
    }
    result = redact(value)
    for key in ("api_key", "url", "machine_key", "email", "name"):
        assert result[key] == "**REDACTED**"
    assert result["nested"][0]["ip_addresses"] == "**REDACTED**"
    assert result["approved_routes"] == "**REDACTED**"
    assert result["available_routes"] == "**REDACTED**"


def test_diagnostic_payload_converts_snapshot_and_redacts_pii() -> None:
    snapshot = parse_snapshot(
        {
            "version": {"version": "0.29.3"},
            "nodes": [{"id": 1, "name": "private-host", "ip_addresses": ["100.64.0.1"]}],
        }
    )
    result = diagnostic_payload({"api_key": "secret", "url": "https://private"}, snapshot)
    assert result["entry"]["api_key"] == "**REDACTED**"
    assert result["entry"]["url"] == "**REDACTED**"
    assert result["snapshot"]["nodes"] == "**REDACTED**"


class FakeResponse:
    def __init__(self, status: int, body: bytes, content_length: int | None = None):
        self.status, self._body, self.content_length = status, body, content_length

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def read(self):
        raise AssertionError("responses must be streamed, not read unbounded")

    @property
    def content(self):
        response = self

        class Content:
            async def iter_chunked(self, size):
                for offset in range(0, len(response._body), size):
                    yield response._body[offset : offset + size]

        return Content()


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
    assert kwargs["ssl"] is True


@pytest.mark.asyncio
async def test_api_fetches_version_from_root_version_endpoint() -> None:
    session = FakeSession(FakeResponse(200, b'{"version":"0.29.3"}'))
    client = HeadscaleApiClient("https://hs.example", "secret", session)
    assert await client.async_get_version() == {"version": "0.29.3"}
    assert session.calls[0][0] == "https://hs.example/version"


@pytest.mark.asyncio
@pytest.mark.parametrize("version", [{}, {"version": None}, {"version": 29}, {"version": ""}])
async def test_flow_validation_rejects_missing_or_invalid_version(version) -> None:
    class Client:
        async def async_get_version(self):
            return version

        async def async_get_nodes(self):
            return {"nodes": []}

    with pytest.raises(HeadscaleMalformedResponse, match="version"):
        await async_validate_connection(Client())


@pytest.mark.asyncio
async def test_flow_validation_fetches_both_resources_and_builds_snapshot() -> None:
    class Client:
        def __init__(self):
            self.calls = []

        async def async_get_version(self):
            self.calls.append("version")
            return {"version": "0.29.3"}

        async def async_get_nodes(self):
            self.calls.append("nodes")
            return {"nodes": [{"id": 1, "name": "node"}]}

    client = Client()
    snapshot = await async_validate_connection(client)
    assert client.calls == ["version", "nodes"]
    assert snapshot.version == "0.29.3"
    assert snapshot.nodes[0].id == 1


@pytest.mark.asyncio
async def test_flow_validation_rejects_missing_nodes_envelope_field() -> None:
    class Client:
        async def async_get_version(self):
            return {"version": "0.29.3"}

        async def async_get_nodes(self):
            return {}

    with pytest.raises(HeadscaleMalformedResponse, match="nodes or node"):
        await async_validate_connection(Client())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "nodes",
    [
        {"nodes": [{"name": "missing-id"}]},
        {"nodes": [{"id": 1}, {"id": "1"}]},
        {"nodes": "not-a-list"},
    ],
)
async def test_flow_validation_rejects_malformed_node_schema(nodes) -> None:
    class Client:
        async def async_get_version(self):
            return {"version": "0.29.3"}

        async def async_get_nodes(self):
            return nodes

    with pytest.raises(HeadscaleMalformedResponse):
        await async_validate_connection(Client())


def test_response_too_large_is_a_controlled_config_flow_error() -> None:
    assert config_flow_error(HeadscaleResponseTooLarge("too large")) == "invalid_data"
    assert config_flow_error(HeadscaleAuthError("bad auth")) == "invalid_auth"


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


@pytest.mark.asyncio
async def test_api_aborts_stream_over_limit_without_content_length() -> None:
    body = b"x" * (1_048_576 + 1)
    client = HeadscaleApiClient("https://hs.example", "x", FakeSession(FakeResponse(200, body)))
    with pytest.raises(HeadscaleResponseTooLarge):
        await client.async_get_nodes()


def test_successful_refresh_timestamp_is_stored_in_snapshot() -> None:
    refreshed_at = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    snapshot = build_snapshot({"nodes": []}, {"version": "0.29.3"}, refreshed_at)
    assert snapshot.last_update == refreshed_at


def test_runtime_refresh_rejects_missing_nodes_envelope() -> None:
    refreshed_at = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    with pytest.raises(HeadscaleMalformedResponse, match="nodes or node"):
        build_snapshot({"unrelated": []}, {"version": "0.29.3"}, refreshed_at)
