from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from spec.attestation import AttestationData

try:
    from vero_ssz import (
        attestation_data_hash_tree_root_from_ssz as _attestation_data_hash_tree_root_from_ssz,
    )
except ImportError:  # pragma: no cover - optional acceleration
    _attestation_data_hash_tree_root_from_ssz = None


def has_rust_ssz() -> bool:
    return _attestation_data_hash_tree_root_from_ssz is not None


def attestation_data_root_hex_from_ssz_bytes(ssz_bytes: bytes) -> str:
    if _attestation_data_hash_tree_root_from_ssz is not None:
        root_bytes = bytes(_attestation_data_hash_tree_root_from_ssz(ssz_bytes))
        return "0x" + root_bytes.hex()

    # Fallback to the current Python path.
    att_data = AttestationData.decode_bytes(ssz_bytes)
    return "0x" + att_data.hash_tree_root().hex()


def attestation_data_root_hex(attestation_data: Mapping[str, Any]) -> str:
    att_data = AttestationData.from_obj(dict(attestation_data))
    return attestation_data_root_hex_from_ssz_bytes(bytes(att_data.encode_bytes()))
