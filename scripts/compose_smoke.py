"""Exercise the integration client against the isolated Compose mock."""

import asyncio

import aiohttp

from custom_components.headscale_monitor.api import HeadscaleApiClient
from custom_components.headscale_monitor.flow_validation import async_validate_connection


async def main() -> None:
    async with aiohttp.ClientSession() as session:
        client = HeadscaleApiClient(
            "https://headscale-mock:8443", "integration-test", session
        )
        snapshot = await async_validate_connection(client)
    if snapshot.version != "0.29.3" or [node.id for node in snapshot.nodes] != [1]:
        raise RuntimeError("mock returned an unexpected Headscale snapshot")
    print("isolated HTTPS smoke passed: version=0.29.3 nodes=1")


if __name__ == "__main__":
    asyncio.run(main())
