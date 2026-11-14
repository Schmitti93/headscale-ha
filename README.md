# Headscale Monitor for Home Assistant

A private, HACS-compatible, **read-only** custom integration for Headscale REST API v1, developed against Headscale 0.29.3. It polls server version and nodes and creates a hub device plus a device for each stable numeric node ID.

## Security model and threat model

The integration only issues authenticated HTTP `GET` requests to `/api/v1/version` and `/api/v1/node`. It registers no services and contains no create, update, delete, route-change, or node-control operation. Requests use finite connect/total timeouts, a 1 MiB response limit, Bearer authentication, and TLS verification by default. URLs are restricted to an HTTP(S) origin with no credentials, path, query, or fragment. The API key is stored in the Home Assistant config entry and never intentionally logged. Diagnostics recursively redact the API key, machine/node/discovery keys, pre-auth keys, email, IP addresses, user data, hostnames, and other PII.

**Critical caveat:** Headscale API keys are full-power credentials; Headscale 0.29.3 does not provide read-only API scopes. “Read-only” describes this integration's code, not the authority of the credential. For isolated testing, create a short-lived test key and revoke it immediately afterward. For production, the recommended future architecture is a narrow read-only gateway/proxy that exposes only the two required GET resources with a separate least-privilege credential. Protect Home Assistant backups because config entries contain the key.

Threats considered include a malicious/compromised Headscale endpoint returning oversized or malformed data, accidental secret/PII disclosure through logs or diagnostics, credential leakage through URL user-info, insecure TLS bypass, excessive polling, and accidental control functionality. Disabling TLS verification weakens transport security and should only be used on a trusted isolated network with compensating controls.

## Entities

Hub: version, total nodes, online nodes, offline nodes, last update. Each node: online, IP addresses, last seen, user display name, expiration, approved routes, available routes, and registration method. Unique IDs derive from the config-entry ID and stable numeric node ID.

## Installation

Copy `custom_components/headscale_monitor` into Home Assistant's `custom_components`, restart Home Assistant, then add **Headscale Monitor** through Settings → Devices & services. HACS users may add the private repository as an Integration. Configure URL, API key, TLS verification (default on), and interval (30–3600 seconds).

## Isolated Home Assistant test instance

`docker-compose.test.yml` binds only `127.0.0.1:18123`, does not use privileged mode, host networking, or the Docker socket, drops all Linux capabilities, enables `no-new-privileges`, mounts this integration read-only, and uses a restricted tmpfs for `/tmp`.

```sh
docker compose -f docker-compose.test.yml up
```

Home Assistant itself requires a writable `/config` for onboarding, `.storage`, logs, and its database, so the compose file provides a dedicated named test volume. The integration source mount is read-only. This project does not start this stack automatically and it must never be pointed at production HAOS.

## Development and tests

Unit tests perform no real network requests.

```sh
python -m venv .venv
.venv/bin/python -m pip install pytest pytest-asyncio aiohttp yarl ruff mypy bandit detect-secrets
.venv/bin/python -m pytest -q
.venv/bin/ruff check .
.venv/bin/mypy custom_components/headscale_monitor
.venv/bin/bandit -q -r custom_components/headscale_monitor
.venv/bin/detect-secrets scan --all-files --exclude-files '\.venv/'
```

## License

MIT
