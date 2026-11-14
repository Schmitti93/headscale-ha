# Read-only gateway example

Headscale API keys may carry administrative authority. This example places a small
HTTPS policy gateway in front of Headscale and gives Home Assistant a separate
client token. It is an example architecture, not a replacement for host firewall
rules and normal secret management.

## Required behavior

A suitable gateway must:

- listen on HTTPS with a certificate trusted by Home Assistant;
- authenticate Home Assistant with a separate high-entropy client token;
- permit only `GET /version` and `GET /api/v1/node`;
- replace the client credential with the Headscale API key upstream;
- reject every other method and path;
- limit request and response sizes and apply finite timeouts;
- be reachable only from the Home Assistant address or network.

## Minimal Caddy example

Store both environment variables outside the Caddyfile and restrict their file
permissions. Do not commit either value.

```caddyfile
headscale-gateway.example.internal {
    @unauthorized not header Authorization "Bearer {$CLIENT_TOKEN}"
    respond @unauthorized 401

    @version {
        method GET
        path /version
    }
    handle @version {
        reverse_proxy http://127.0.0.1:8080 {
            header_up Authorization "Bearer {$HEADSCALE_API_KEY}"
        }
    }

    @nodes {
        method GET
        path /api/v1/node
    }
    handle @nodes {
        reverse_proxy http://127.0.0.1:8080 {
            header_up Authorization "Bearer {$HEADSCALE_API_KEY}"
        }
    }

    handle {
        respond 404
    }
}
```

This minimal example does not implement the integration's 1 MiB upstream response
limit at the proxy. The integration still enforces its own streaming limit, but a
production gateway should additionally enforce a response limit and timeouts.

Restrict the listener with the host firewall so only Home Assistant can connect.
For private PKI, paste the issuing CA certificate—not a private key—into the
integration's custom CA field.

## Rotation

1. Create a replacement Headscale API key.
2. Replace the upstream key in the gateway and reload it.
3. Verify both allowed GET endpoints through the gateway.
4. Revoke the old Headscale key.
5. To rotate the client token, update the gateway and reconfigure the Home Assistant
   integration in one maintenance window.

Removing the Home Assistant integration does **not** revoke either credential.
Revoke unused Headscale keys and gateway tokens separately.
