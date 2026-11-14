# Headscale Monitor for Home Assistant

A Marketplace-compatible, **read-only** custom integration for Headscale REST API v1. It polls the server version and nodes and creates a hub device plus a device for each stable numeric node ID. The live contract test currently covers Headscale `0.29.6` and Home Assistant `2025.2.5`.

> [!IMPORTANT]
> This project is not affiliated with or endorsed by the Headscale or Home Assistant projects.

## Security model and threat model

The integration only issues authenticated HTTP `GET` requests to `/version` and `/api/v1/node`. It registers no services and contains no create, update, delete, route-change, or node-control operation. Responses are streamed in bounded chunks and aborted above 1 MiB, including when `Content-Length` is absent. Requests use finite connect/total timeouts, Bearer authentication, mandatory HTTPS, hostname verification, and mandatory certificate verification. URLs are restricted to an HTTPS origin with no credentials, path, query, or fragment. The API key and optional custom CA certificate are stored in the Home Assistant config entry and never intentionally logged. Diagnostics recursively redact the URL, API key, CA certificate, routes, machine/node/discovery keys, pre-auth keys, email, IP addresses, user data, hostnames, and topology.

**Critical caveat:** Headscale API keys are full-power credentials; Headscale 0.29.3 does not provide read-only API scopes. “Read-only” describes this integration's code, not the authority of the credential. For isolated testing, create a short-lived test key and revoke it immediately afterward. For production, use a narrow read-only gateway/proxy that exposes only the two required GET resources with a separate least-privilege credential. A private gateway CA can be pasted during setup in PEM format; it is added to the system trust store for this integration's HTTPS requests without disabling normal verification. Protect Home Assistant backups because config entries contain the key and may contain the CA certificate.

Threats considered include a malicious/compromised Headscale endpoint returning oversized or malformed data, accidental secret/PII/topology disclosure through logs or diagnostics, credential leakage through URL user-info or plaintext HTTP, excessive polling, and accidental control functionality. TLS verification cannot be disabled in the v1 config flow.

## Entities

Hub: version, total nodes, online nodes, offline nodes, last update. Each node: online, IP addresses, last seen, user display name, expiration, approved routes, available routes, and registration method. Unique IDs derive from the config-entry ID and stable numeric node ID.

## Installation

### Home Assistant Marketplace

1. Open **Settings → Apps → Marketplace** in Home Assistant.
2. Add `https://github.com/Schmitti93/headscale-ha` as a custom **Integration** repository if it is not listed yet.
3. Install **Headscale Monitor** and restart Home Assistant when prompted.
4. Open **Settings → Devices & services → Add integration** and select **Headscale Monitor**.

### Manual installation

Copy `custom_components/headscale_monitor` into Home Assistant's `custom_components` directory and restart Home Assistant.

Configure an HTTPS origin URL, API key or gateway token, polling interval (30–3600 seconds), and optionally the private gateway's PEM CA certificate. Leave the CA field empty to use the system trust store. Certificate and hostname verification are always enabled; there is no `verify_tls` bypass.

## Supported connection modes

- **Recommended:** a narrow HTTPS gateway that exposes only `GET /version` and `GET /api/v1/node` under a separate client credential.
- **Direct API:** the native Headscale API over HTTPS. Be aware that native Headscale API keys may carry full administrative authority even though this integration only sends GET requests.

For the recommended production container, see the separate [Headscale Read-only Gateway](https://github.com/Schmitti93/headscale-readonly-gateway) project. The local [gateway example](docs/READ_ONLY_GATEWAY.md) documents the required controls and credential-rotation model.

Plain HTTP, embedded URL credentials, URLs with a path/query/fragment, and disabled TLS verification are intentionally unsupported.

## Credential lifecycle

- Create a dedicated credential for this integration; never reuse a personal or unrelated automation credential.
- Rotate credentials immediately after suspected exposure and periodically according to your local policy.
- Removing the integration does **not** revoke a Headscale API key or gateway token. Revoke it separately on Headscale or the gateway.
- Protect and preferably encrypt Home Assistant backups because config entries contain the configured credential and may contain a private CA certificate.

## Troubleshooting

- **Cannot connect:** verify DNS, routing, firewall rules, port, and that the configured value is an HTTPS origin without a path.
- **Invalid authentication:** rotate or correct the API key/gateway token and verify that the gateway replaces it with a valid upstream Headscale key.
- **Certificate error:** ensure the URL hostname or IP is present in the server certificate and paste only the issuing CA certificate in PEM format.
- **Invalid response:** confirm the target implements Headscale REST API v1 and permits `GET /version` and `GET /api/v1/node`.
- **Timeout:** check the gateway and Headscale logs; the integration intentionally uses finite connection and request timeouts.
- **Oversized response:** the integration rejects responses larger than 1 MiB. Investigate the endpoint rather than disabling the limit.

## Updating

Marketplace installations receive updates from tagged GitHub releases. Review the changelog before updating and keep a current Home Assistant backup.

## Support and security reports

- Use GitHub Issues for reproducible bugs and feature requests.
- Do not post API keys, gateway tokens, certificates containing private keys, diagnostics with topology data, or Home Assistant backups in public issues.
- Report suspected vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md).

## Isolated Home Assistant test instance

`docker-compose.test.yml` pins Home Assistant `2025.2.5` and nginx `1.27.4-alpine` by image digest and uses one internal Docker network with no host-published port. A locally built HTTPS mock exposes authenticated `/version` and `/api/v1/node` responses only on that network. Home Assistant receives the test CA explicitly through `SSL_CERT_FILE`; no real credentials, LAN endpoint, internet endpoint, privileged mode, host networking, or Docker socket is used. Containers drop all Linux capabilities and enable `no-new-privileges`.

```sh
docker compose -f docker-compose.test.yml up
```

Home Assistant itself requires a writable `/config` for onboarding, `.storage`, logs, and its database, so the compose file provides a dedicated named test volume. The test image copies the integration and CA into that volume at container initialization. Run `docker compose -f docker-compose.test.yml exec -T homeassistant-test python /opt/compose_smoke.py` to exercise both API resources through the integration client. Verify Home Assistant readiness from inside the isolated container at `http://127.0.0.1:8123/`; the UI is deliberately not exposed to the host. This stack must never be pointed at production HAOS.

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
