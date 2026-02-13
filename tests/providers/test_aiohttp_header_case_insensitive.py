import aiohttp
from aioresponses import aioresponses


async def test_aiohttp_response_headers_are_case_insensitive_with_aioresponses() -> None:
    url = "http://example.local/test"

    with aioresponses() as mocked:
        mocked.get(url, status=200, body="ok", headers={"eth-consensus-version": "electra"})

        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                assert resp.headers["Eth-Consensus-Version"] == "electra"
                assert resp.headers.get("Eth-Consensus-Version") == "electra"
                assert resp.headers["eth-consensus-version"] == "electra"
