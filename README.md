# Headscale Monitor for Home Assistant

A private, HACS-compatible, **read-only** custom integration for Headscale REST API v1, developed against Headscale 0.29.3. It polls server version and nodes and creates a hub device plus a device for each stable numeric node ID.

## Security model and threat model

The integration only issues authenticated HTTP `GET` requests to `/version` and `/api/v1/node`. It registers no services and contains no create, update, delete, route-change, or node-control operation. Responses are streamed in bounded chunks and aborted above 1 MiB, including when `Content-Length` is absent. Requests use finite connect/total timeouts, Bearer authentication, mandatory HTTPS, and mandatory certificate verification. URLs are restricted to an HTTPS origin with no credentials, path, query, or fragment. The API key is stored in the Home Assistant config entry and never intentionally logged. Diagnostics recursively redact the URL, API key, routes, machine/node/discovery keys, pre-auth keys, email, IP addresses, user data, hostnames, and topology.

**Critical caveat:** Headscale API keys are full-power credentials; Headscale 0.29.3 does not provide read-only API scopes. “Read-only” describes this integration's code, not the authority of the credential. For isolated testing, create a short-lived test key and revoke it immediately afterward. For production, the recommended future architecture is a narrow read-only gateway/proxy that exposes only the two required GET resources with a separate least-privilege credential. Protect Home Assistant backups because config entries contain the key.

Threats considered include a malicious/compromised Headscale endpoint returning oversized or malformed data, accidental secret/PII/topology disclosure through logs or diagnostics, credential leakage through URL user-info or plaintext HTTP, excessive polling, and accidental control functionality. TLS verification cannot be disabled in the v1 config flow.

## Entities

Hub: version, total nodes, online nodes, offline nodes, last update. Each node: online, IP addresses, last seen, user display name, expiration, approved routes, available routes, and registration method. Unique IDs derive from the config-entry ID and stable numeric node ID.

## Installation

Copy `custom_components/headscale_monitor` into Home Assistant's `custom_components`, restart Home Assistant, then add **Headscale Monitor** through Settings → Devices & services. HACS users may add the private repository as an Integration. Configure an HTTPS URL, API key, and interval (30–3600 seconds). Certificate verification is always enabled.

## Isolated Home Assistant test instance

`docker-compose.test.yml` pins Home Assistant `2025.2.5` and nginx `1.27.4-alpine` by image digest, declares only a `127.0.0.1:18123` host binding, and uses one internal Docker network. A locally built HTTPS mock exposes authenticated `/version` and `/api/v1/node` responses only on that network. Home Assistant receives the test CA explicitly through `SSL_CERT_FILE`; no real credentials, LAN endpoint, internet endpoint, privileged mode, host networking, or Docker socket is used. Containers drop all Linux capabilities and enable `no-new-privileges`.

```sh
docker compose -f docker-compose.test.yml up
```

Home Assistant itself requires a writable `/config` for onboarding, `.storage`, logs, and its database, so the compose file provides a dedicated named test volume. The test image copies the integration and CA into that volume at container initialization. Run `docker exec -e PYTHONPATH=/config headscale-ha-homeassistant-test-1 python /opt/compose_smoke.py` to exercise both API resources through the integration client. This stack must never be pointed at production HAOS.

Docker network isolation alone is not a strict outbound-LAN security boundary on every host configuration. Use host firewall rules (for example DOCKER-USER chain policy) when strict egress denial is required.

## Development and tests

Unit tests perform no real network requests.

HA-level tests using `pytest-homeassistant-custom-component` require a compatible Python/Home Assistant dependency set. The unit suite covers API transport enforcement, config-flow connection validation, parsing, discovery, removal, timestamps, and redaction; the isolated Compose smoke test runs the real client inside Home Assistant against the pinned HTTPS mock.

```sh
python -m venv .venv
.venv/bin/python -m pip install pytest pytest-asyncio aiohttp yarl ruff mypy bandit detect-secrets
.venv/bin/python -m pytest -q
.venv/bin/ruff check .
.venv/bin/mypy custom_components/headscale_monitor
.venv/bin/bandit -q -r custom_components/headscale_monitor
.venv/bin/python scripts/check_secrets.py
.venv/bin/python scripts/prove_detect_secrets_fail_closed.py
```

## License

MIT
