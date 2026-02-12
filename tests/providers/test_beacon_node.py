import contextlib
import re
from contextlib import AsyncExitStack
from copy import copy

import pytest
from aioresponses import CallbackResult, aioresponses

from providers import BeaconNode, Vero
from spec.base import Version
from spec.common import UInt64SerializedAsString


@pytest.mark.parametrize(
    "spec_mismatch",
    [
        pytest.param(False, id="match"),
        pytest.param(True, id="mismatch"),
    ],
)
@pytest.mark.parametrize(
    argnames="cli_args",
    argvalues=[
        pytest.param(
            {
                "ignore_spec_mismatch": False,
            },
            id="spec mismatch not ignored",
        ),
        pytest.param(
            {
                "ignore_spec_mismatch": True,
            },
            id="spec mismatch ignored",
        ),
    ],
    indirect=["cli_args"],
)
async def test_initialize_spec_mismatch(
    spec_mismatch: bool,
    vero: Vero,
) -> None:
    """The BeaconNode should fail to initialize on a spec mismatch."""
    with contextlib.ExitStack() as stack:
        m = stack.enter_context(aioresponses())

        spec_to_return = vero.spec
        if spec_mismatch:
            spec_to_return = copy(vero.spec)
            spec_to_return.SLOTS_PER_EPOCH = UInt64SerializedAsString(5)
            spec_to_return.ELECTRA_FORK_VERSION = Version("0x00abcdef")

        m.get(
            url=re.compile(r"http://beacon-node-\w:1234/eth/v1/config/spec"),
            callback=lambda *args, **kwargs: CallbackResult(
                payload=dict(data=spec_to_return.to_obj()),
            ),
        )

        bn = BeaconNode(
            base_url="http://beacon-node-a:1234",
            vero=vero,
        )
        if not spec_mismatch or vero.cli_args.ignore_spec_mismatch:
            # No mismatch, or mismatch explicitly ignored -> init should not raise
            await bn._initialize_full()
        else:
            with pytest.raises(
                ValueError,
                match="Spec values returned by beacon node beacon-node-a not equal to hardcoded spec values",
            ):
                await bn._initialize_full()


async def test_make_request_returns_bytes_content_type_and_headers(vero: Vero) -> None:
    async with AsyncExitStack() as stack:
        m = stack.enter_context(aioresponses())

        m.get(
            "http://beacon-node-a:1234/eth/v1/node/version",
            status=200,
            body=b'{"data": {"version": "vero/test"}}',
            headers={
                "Content-Type": "application/json",
                "X-Test-Header": "yes",
            },
        )

        bn = BeaconNode(
            base_url="http://beacon-node-a:1234",
            vero=vero,
        )
        await stack.enter_async_context(bn.client_session)

        resp_body, content_type, headers = await bn._make_request(
            method="GET",
            endpoint="/eth/v1/node/version",
        )

        assert isinstance(resp_body, bytes)
        assert resp_body == b'{"data": {"version": "vero/test"}}'
        assert content_type == "application/json"
        assert headers["Content-Type"] == "application/json"
        assert headers["X-Test-Header"] == "yes"
