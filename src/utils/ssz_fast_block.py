from __future__ import annotations

import msgspec.json

from spec.configs import Network

try:
    from vero_ssz_grandine_py import (
        GrandineBeaconBlockElectra,
        beacon_block_body_root_hex_from_ssz_active,
        beacon_block_from_contents_json_active,
        beacon_block_from_contents_ssz_active,
        initialize_active_preset,
        sign_block_contents_ssz_active,
    )
except ImportError:  # pragma: no cover
    GrandineBeaconBlockElectra = None
    beacon_block_body_root_hex_from_ssz_active = None
    beacon_block_from_contents_json_active = None
    beacon_block_from_contents_ssz_active = None
    initialize_active_preset = None
    sign_block_contents_ssz_active = None


def has_rust_block_ssz() -> bool:
    return (
        initialize_active_preset is not None
        and beacon_block_body_root_hex_from_ssz_active is not None
        and beacon_block_from_contents_ssz_active is not None
        and beacon_block_from_contents_json_active is not None
        and GrandineBeaconBlockElectra is not None
        and sign_block_contents_ssz_active is not None
    )


def network_to_preset(network: Network) -> str:
    if network in (Network.GNOSIS, Network.CHIADO):
        return "gnosis"
    if network == Network._TESTS:  # noqa: SLF001
        return "minimal"
    return "mainnet"


def initialize_rust_block_ssz(preset: str) -> None:
    if initialize_active_preset is None:
        raise RuntimeError("Grandine Rust SSZ extension not available")
    initialize_active_preset(preset)


def beacon_block_body_root_from_ssz(ssz_bytes: bytes) -> str:
    if beacon_block_body_root_hex_from_ssz_active is None:
        raise RuntimeError("Grandine Rust SSZ extension not available")
    return str(beacon_block_body_root_hex_from_ssz_active(ssz_bytes))


def beacon_block_from_contents_ssz(ssz_bytes: bytes) -> object:
    if beacon_block_from_contents_ssz_active is None:
        raise RuntimeError("Grandine Rust SSZ extension not available")
    return beacon_block_from_contents_ssz_active(ssz_bytes)


def beacon_block_from_contents_json(contents_json_obj: dict[str, object]) -> object:
    if beacon_block_from_contents_json_active is None:
        raise RuntimeError("Grandine Rust SSZ extension not available")
    return beacon_block_from_contents_json_active(msgspec.json.encode(contents_json_obj))


def sign_block_contents_ssz(ssz_bytes: bytes, signature: str) -> bytes:
    if sign_block_contents_ssz_active is None:
        raise RuntimeError("Grandine Rust SSZ extension not available")
    return bytes(sign_block_contents_ssz_active(ssz_bytes, signature))


def is_rust_beacon_block(value: object) -> bool:
    return GrandineBeaconBlockElectra is not None and isinstance(
        value, GrandineBeaconBlockElectra
    )
