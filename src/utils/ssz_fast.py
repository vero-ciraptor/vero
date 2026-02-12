from __future__ import annotations

import json
from typing import Any

from spec.attestation import AttestationData
from utils.ssz_fast_zig import (
    attestation_data_root_hex_from_response_json_bytes_zig,
    attestation_data_root_hex_from_ssz_bytes_zig,
    has_zig_ssz,
)

try:
    from vero_ssz_grandine_py import (
        RustAttestationDataFromResponseJson as _RustAttestationDataFromResponseJson,
    )
    from vero_ssz_grandine_py import (
        attestation_data_hash_tree_root_from_response_json as _attestation_data_hash_tree_root_from_response_json,
    )
    from vero_ssz_grandine_py import (
        attestation_data_hash_tree_root_from_ssz as _attestation_data_hash_tree_root_from_ssz,
    )
except ImportError:  # pragma: no cover - optional acceleration
    _RustAttestationDataFromResponseJson = None
    _attestation_data_hash_tree_root_from_response_json = None
    _attestation_data_hash_tree_root_from_ssz = None


def has_rust_ssz() -> bool:
    return _attestation_data_hash_tree_root_from_ssz is not None


def has_native_ssz() -> bool:
    return has_zig_ssz() or has_rust_ssz()


def attestation_data_root_hex_from_ssz_bytes(ssz_bytes: bytes) -> str:
    if has_zig_ssz():
        try:
            return attestation_data_root_hex_from_ssz_bytes_zig(ssz_bytes)
        except RuntimeError:
            pass

    if _attestation_data_hash_tree_root_from_ssz is not None:
        root_bytes = bytes(_attestation_data_hash_tree_root_from_ssz(ssz_bytes))
        return str("0x" + root_bytes.hex())

    # Fallback to the current Python path.
    att_data = AttestationData.decode_bytes(ssz_bytes)
    return "0x" + bytes(att_data.hash_tree_root()).hex()


def attestation_data_root_hex(attestation_data: dict[str, Any]) -> str:
    att_data = AttestationData.from_obj(dict(attestation_data))
    return attestation_data_root_hex_from_ssz_bytes(bytes(att_data.encode_bytes()))


def has_rust_attestation_json() -> bool:
    return _RustAttestationDataFromResponseJson is not None


def attestation_data_root_hex_from_response_json_bytes(
    response_json_bytes: bytes,
) -> str:
    if has_zig_ssz():
        try:
            return attestation_data_root_hex_from_response_json_bytes_zig(
                response_json_bytes
            )
        except RuntimeError:
            pass

    if _RustAttestationDataFromResponseJson is not None:
        obj = _RustAttestationDataFromResponseJson.from_response_json_bytes(
            response_json_bytes
        )
        return str(obj.hash_tree_root_hex())

    if _attestation_data_hash_tree_root_from_response_json is not None:
        root_bytes = bytes(
            _attestation_data_hash_tree_root_from_response_json(response_json_bytes)
        )
        return str("0x" + root_bytes.hex())

    decoded = json.loads(response_json_bytes)
    att_data = AttestationData.from_obj(decoded["data"])
    return "0x" + bytes(att_data.hash_tree_root()).hex()
