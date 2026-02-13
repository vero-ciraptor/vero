import pytest

import spec
from spec import SpecAttestation, SpecBeaconBlock
from spec.configs import Network, get_network_spec
from utils.ssz_fast_block import (
    beacon_block_from_contents_json,
    has_rust_block_ssz,
    initialize_rust_block_ssz,
    is_rust_beacon_block,
)


@pytest.mark.skipif(not has_rust_block_ssz(), reason="Rust SSZ extension not available")
def test_beacon_block_from_contents_json_returns_rust_block_with_expected_roots(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = get_network_spec(network=Network.MAINNET)
    SpecAttestation.initialize(spec=spec)
    SpecBeaconBlock.initialize(spec=spec)
    initialize_rust_block_ssz("mainnet")

    contents = SpecBeaconBlock.ElectraBlockContents.from_obj(
        {
            "block": {
                "slot": 42,
                "proposer_index": 7,
                "parent_root": "0x" + "11" * 32,
                "state_root": "0x" + "22" * 32,
            },
            "kzg_proofs": [],
            "blobs": [],
        }
    )

    def _forbidden_python_bridge(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("Python spec bridge should not be used for JSON block decoding")

    monkeypatch.setattr(
        spec.SpecBeaconBlock.ElectraBlockContents,
        "from_obj",
        _forbidden_python_bridge,
        raising=True,
    )

    rust_block = beacon_block_from_contents_json(contents.to_obj())
    py_block = contents.block

    assert is_rust_beacon_block(rust_block)
    assert rust_block.slot() == py_block.slot
    assert rust_block.proposer_index() == py_block.proposer_index
    assert rust_block.body_root_hex() == f"0x{py_block.body.hash_tree_root().hex()}"
    assert rust_block.hash_tree_root_hex() == f"0x{py_block.hash_tree_root().hex()}"
