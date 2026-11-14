import json
import ssl
from datetime import UTC, datetime

import pytest

from custom_components.headscale_monitor.api import (
    HeadscaleApiClient,
    HeadscaleAuthError,
    HeadscaleMalformedResponse,
    HeadscaleResponseTooLarge,
    create_ssl_context,
)
from custom_components.headscale_monitor.diagnostics import diagnostic_payload, redact
from custom_components.headscale_monitor.flow_validation import (
    async_validate_connection,
    config_flow_error,
)
from custom_components.headscale_monitor.models import build_snapshot, parse_snapshot
from custom_components.headscale_monitor.validation import normalize_url, validate_scan_interval

TEST_CA = """-----BEGIN CERTIFICATE-----
MIIDGTCCAgGgAwIBAgIULgOuguT9UkSlulZ7zTtEhxal0xgwDQYJKoZIhvcNAQEL
BQAwHDEaMBgGA1UEAwwRSGVhZHNjYWxlIFRlc3QgQ0EwHhcNMjYxMTE0MTEyNTI0
WhcNMzYxMTExMTEyNTI0WjAcMRowGAYDVQQDDBFIZWFkc2NhbGUgVGVzdCBDQTCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMXc4tLt/5UZS8PeywNHM83V
LF7Jp7zsgUxJ5bY+IR/rQOgtw7jnzFyYvAZ/yq/yN4tPwLmPXwULzcLXzZzFIZsd
FjawjzNGwRY4j+sOizw2kzkik6x5L4HA1ARumg44XB6xpN3iQLoJE4NQDMqPaGbY
IQ/7ztF2cIy335Pz4M9/M8migYqkrQ39xoJa9/ZXJdvTPX6flHTct20PT41A9hdg
wOmLpkVSjYH2IIXE2c2DgN/aVFkGIOC29Jbm14pVIolNZY57sSfdQIsrsp49r4VH
SsjFP/jFq2VhqaanlK+xNnWauWqqw1xZZsOcjphV8tOBvIJE1IYlt8w06VDfgCEC
AwEAAaNTMFEwHQYDVR0OBBYEFCpTHUiFRSVNQsGzstixljYLbngTMB8GA1UdIwQY
MBaAFCpTHUiFRSVNQsGzstixljYLbngTMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZI
hvcNAQELBQADggEBADQvtDeGZ+JkzbwVOkgHlrbnqi17bVIR29dW7UQmYTrwf9pK
N5iC2LMJ+JzzMuZeyIsX5DRP9Sja7zuEN9oBG6/t2Bdl6lECcio3bs4CmR+PjOG+
HZxN2XUj5NIzVYJFX/uBQe6AQnRBoBEiYZPLja9aOGKY7+WaPuJ9ihDvCZQG2BVd
nozkqzmhYOh7zO0FF7+eYVixQOQWBHvg/jou/tnxSp/9yBbSpcaEANvCHrPomXZ5
mOONCtEQmPTfgC9faP45DHQQH9LYfJYnM1umrxlU/m48wHPLl6pdkmTNlFqqytHP
nT6a18zs84JM1l2ZFZhls85ga+YM1LVKZVz96GI=
-----END CERTIFICATE-----"""


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


def test_api_client_rejects_malformed_custom_ca_cleanly() -> None:
    with pytest.raises(ValueError, match="CA certificate"):
        create_ssl_context("not a PEM certificate")


def test_custom_ca_rejects_key_material() -> None:
    forbidden_marker = "PRIVATE" + " KEY"
    pem = f"{TEST_CA}\n-----BEGIN {forbidden_marker}-----\nnot-key-material"
    with pytest.raises(ValueError, match="private key"):
        create_ssl_context(pem)


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


def test_diagnostics_redact_custom_ca_certificate() -> None:
    result = redact({"ca_certificate": TEST_CA})
    assert result["ca_certificate"] == "**REDACTED**"


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
async def test_api_uses_hostname_verifying_context_with_custom_ca() -> None:
    session = FakeSession(FakeResponse(200, b'{"version":"0.29.3"}'))
    context = create_ssl_context(TEST_CA)
    client = HeadscaleApiClient("https://hs.example", "secret", session, ssl_context=context)

    await client.async_get_version()

    request_context = session.calls[0][1]["ssl"]
    assert request_context is context
    assert isinstance(request_context, ssl.SSLContext)
    assert request_context.verify_mode is ssl.CERT_REQUIRED
    assert request_context.check_hostname is True
    subjects = [str(cert.get("subject")) for cert in request_context.get_ca_certs()]
    assert any("Headscale Test CA" in subject for subject in subjects)


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
