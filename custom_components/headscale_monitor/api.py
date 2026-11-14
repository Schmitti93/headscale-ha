"""Small, read-only Headscale v1 API client."""

from __future__ import annotations

import json
from typing import Any

import aiohttp

MAX_RESPONSE_BYTES = 1_048_576


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


class HeadscaleApiClient:
    def __init__(self, base_url: str, api_key: str, session: Any, verify_tls: bool = True) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._session = session
        self._verify_tls = verify_tls

    async def _get(self, path: str) -> dict[str, Any]:
        try:
            async with self._session.get(
                self._base_url + path,
                headers={"Authorization": f"Bearer {self._api_key}", "Accept": "application/json"},
                ssl=self._verify_tls,
                timeout=aiohttp.ClientTimeout(total=15, connect=5),
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
                body = await response.read()
                if len(body) > MAX_RESPONSE_BYTES:
                    raise HeadscaleResponseTooLarge("response exceeds size limit")
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

    async def async_get_nodes(self):
        return await self._get("/api/v1/node")

    async def async_get_version(self):
        return await self._get("/api/v1/version")
