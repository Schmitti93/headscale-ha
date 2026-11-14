"""Small, read-only Headscale v1 API client."""

from __future__ import annotations

import json
import ssl
from typing import Any
from urllib.parse import quote

import aiohttp

from .validation import normalize_url

MAX_RESPONSE_BYTES = 1_048_576
RESPONSE_CHUNK_BYTES = 64 * 1024


class HeadscaleError(Exception):
    pass


class HeadscaleAuthError(HeadscaleError):
    pass


class HeadscaleConnectionError(HeadscaleError):
    pass


class HeadscaleMalformedResponse(HeadscaleError):
    pass


class HeadscaleResponseTooLarge(HeadscaleError):
    pass


def create_ssl_context(ca_certificate: str) -> ssl.SSLContext:
    """Build a hostname-verifying client context with an additional private CA."""
    if "PRIVATE KEY" in ca_certificate.upper():
        raise ValueError("CA certificate must not contain private key material")
    context = ssl.create_default_context()
    try:
        context.load_verify_locations(cadata=ca_certificate)
    except (ssl.SSLError, ValueError) as exc:
        raise ValueError("invalid CA certificate PEM") from exc
    return context


class HeadscaleApiClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        session: Any,
        *,
        verify_tls: bool = True,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        if not verify_tls:
            raise ValueError("TLS certificate verification is required")
        self._base_url = normalize_url(base_url)
        self._api_key = api_key
        self._session = session
        self._ssl: bool | ssl.SSLContext = ssl_context or True

    async def _request(
        self, method: str, path: str, *, json_body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        try:
            request = getattr(self._session, method)
            kwargs: dict[str, Any] = {
                "headers": {
                    "Authorization": f"Bearer {self._api_key}",
                    "Accept": "application/json",
                },
                "ssl": self._ssl,
                "timeout": aiohttp.ClientTimeout(total=15, connect=5),
            }
            if json_body is not None:
                kwargs["json"] = json_body
            async with request(
                self._base_url + path,
                **kwargs,
            ) as response:
                if response.status in (401, 403):
                    raise HeadscaleAuthError("authentication failed")
                if response.status >= 400:
                    raise HeadscaleConnectionError(f"Headscale returned HTTP {response.status}")
                if (
                    response.content_length is not None
                    and response.content_length > MAX_RESPONSE_BYTES
                ):
                    raise HeadscaleResponseTooLarge("response exceeds size limit")
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.content.iter_chunked(RESPONSE_CHUNK_BYTES):
                    size += len(chunk)
                    if size > MAX_RESPONSE_BYTES:
                        raise HeadscaleResponseTooLarge("response exceeds size limit")
                    chunks.append(chunk)
                body = b"".join(chunks)
        except HeadscaleError:
            raise
        except (TimeoutError, aiohttp.ClientError) as exc:
            raise HeadscaleConnectionError("unable to reach Headscale") from exc
        try:
            value = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HeadscaleMalformedResponse("invalid JSON response") from exc
        if not isinstance(value, dict):
            raise HeadscaleMalformedResponse("response must be an object")
        return value

    async def _get(self, path: str) -> dict[str, Any]:
        return await self._request("get", path)

    async def _post(self, path: str, *, json_body: dict[str, Any] | None = None) -> dict[str, Any]:
        return await self._request("post", path, json_body=json_body)

    async def async_get_nodes(self):
        return await self._get("/api/v1/node")

    async def async_get_version(self):
        return await self._get("/version")

    async def async_get_health(self):
        return await self._get("/api/v1/health")

    async def async_get_users(self):
        return await self._get("/api/v1/user")

    async def async_get_preauth_keys(self):
        return await self._get("/api/v1/preauthkey")

    async def async_get_api_keys(self):
        return await self._get("/api/v1/apikey")

    async def async_get_policy(self):
        return await self._get("/api/v1/policy")

    async def async_approve_registration(self, auth_id: str):
        return await self._post("/api/v1/auth/approve", json_body={"authId": auth_id})

    async def async_reject_registration(self, auth_id: str):
        return await self._post("/api/v1/auth/reject", json_body={"authId": auth_id})

    async def async_set_approved_routes(self, node_id: int, routes: list[str]):
        return await self._post(
            f"/api/v1/node/{node_id}/approve_routes", json_body={"routes": routes}
        )

    async def async_rename_node(self, node_id: int, new_name: str):
        encoded_name = quote(new_name, safe="")
        return await self._post(f"/api/v1/node/{node_id}/rename/{encoded_name}")

    async def async_set_tags(self, node_id: int, tags: list[str]):
        return await self._post(f"/api/v1/node/{node_id}/tags", json_body={"tags": tags})

    async def async_expire_node(self, node_id: int):
        return await self._post(f"/api/v1/node/{node_id}/expire")
