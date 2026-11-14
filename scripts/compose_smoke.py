"""Exercise the integration client against the isolated Compose mock."""

import asyncio
from datetime import UTC, datetime

import aiohttp

from custom_components.headscale_monitor.api import HeadscaleApiClient
from custom_components.headscale_monitor.models import async_fetch_snapshot


async def main() -> None:
    async with aiohttp.ClientSession() as session:
        client = HeadscaleApiClient("https://headscale-mock:8443", "integration-test", session)
        snapshot = await async_fetch_snapshot(client, datetime.now(UTC))
    if (
        snapshot.version != "0.29.3"
        or [node.id for node in snapshot.nodes] != [1]
        or snapshot.user_count != 1
        or snapshot.database_connectivity is not True
    ):
        raise RuntimeError("mock returned an unexpected Headscale snapshot")
    print("isolated HTTPS smoke passed: version=0.29.3 nodes=1 users=1 database=up")


if __name__ == "__main__":
    asyncio.run(main())
