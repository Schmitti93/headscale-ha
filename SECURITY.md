# Security Policy

## Supported versions

Only the latest tagged release is supported with security fixes.

## Reporting a vulnerability

Do not open a public issue for suspected vulnerabilities or exposed credentials.
Use GitHub's **Report a vulnerability** function in the repository Security tab.
Include the affected version, impact, reproduction steps, and any proposed mitigation.

Do not include live Headscale API keys, gateway tokens, private keys, Home Assistant
backups, or unredacted diagnostics. Revoke any credential that may have been exposed.

## Security boundaries

Headscale Monitor only implements authenticated HTTPS GET requests for `/version`
and `/api/v1/node`. It does not register Home Assistant services or implement
Headscale mutation operations. This does not reduce the authority of a native
Headscale API key. Use a narrow read-only gateway with a separate credential when
possible, and protect Home Assistant backups because config entries contain the
configured credential.
