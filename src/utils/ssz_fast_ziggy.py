from __future__ import annotations

"""Experimental Zig/Pydust SSZ path.

This module is intentionally isolated from the existing Rust-backed path.
It provides a class-oriented API backed by Zig bindings when available, while
keeping hash-tree-root correctness via Python fallback logic for now.
"""

import json
from typing import Any

from spec.attestation import AttestationData

try:
    from vero_ssz_ziggy import (
        ZigAttestationData as _ZigAttestationDataNative,
    )
    from vero_ssz_ziggy import (
        zig_attestation_data_from_response_json_bytes as _zig_attestation_data_from_response_json_bytes,
    )
    from vero_ssz_ziggy import (
        zig_attestation_data_from_ssz_bytes as _zig_attestation_data_from_ssz_bytes,
    )
except ImportError:  # pragma: no cover - optional acceleration
    _ZigAttestationDataNative = None
    _zig_attestation_data_from_response_json_bytes = None
    _zig_attestation_data_from_ssz_bytes = None


class ZigAttestationData:
    """Python wrapper for a Zig-backed attestation object.

    Current phase keeps hashing behavior implemented in Python for correctness,
    while object creation is handled by Zig bindings.
    """

    def __init__(self, native_obj: object, payload: bytes, kind: str) -> None:
        self._native_obj = native_obj
        self._payload = payload
        self._kind = kind

    @classmethod
    def from_ssz_bytes(cls, ssz_bytes: bytes) -> "ZigAttestationData":
        if _zig_attestation_data_from_ssz_bytes is None:
            raise RuntimeError("ziggy bindings not available")
        native = _zig_attestation_data_from_ssz_bytes(ssz_bytes)
        return cls(native, ssz_bytes, "ssz")

    @classmethod
    def from_response_json_bytes(cls, response_json_bytes: bytes) -> "ZigAttestationData":
        if _zig_attestation_data_from_response_json_bytes is None:
            raise RuntimeError("ziggy bindings not available")
        native = _zig_attestation_data_from_response_json_bytes(
            response_json_bytes
        )
        return cls(native, response_json_bytes, "response_json")

    def hash_tree_root_hex(self) -> str:
        try:
            return str(getattr(self._native_obj, "hash_tree_root_hex")())
        except Exception:
            # Safety fallback while integrating native path.
            if self._kind == "ssz":
                att_data = AttestationData.decode_bytes(self._payload)
                return "0x" + bytes(att_data.hash_tree_root()).hex()

            decoded = json.loads(self._payload)
            att_data = AttestationData.from_obj(decoded["data"])
            return "0x" + bytes(att_data.hash_tree_root()).hex()


def has_ziggy_ssz() -> bool:
    return _ZigAttestationDataNative is not None


def attestation_data_root_hex_from_ssz_bytes(ssz_bytes: bytes) -> str:
    if has_ziggy_ssz():
        try:
            obj = ZigAttestationData.from_ssz_bytes(ssz_bytes)
            return obj.hash_tree_root_hex()
        except Exception:
            pass

    att_data = AttestationData.decode_bytes(ssz_bytes)
    return "0x" + bytes(att_data.hash_tree_root()).hex()


def attestation_data_root_hex(attestation_data: dict[str, Any]) -> str:
    att_data = AttestationData.from_obj(dict(attestation_data))
    return attestation_data_root_hex_from_ssz_bytes(bytes(att_data.encode_bytes()))


def attestation_data_root_hex_from_response_json_bytes(
    response_json_bytes: bytes,
) -> str:
    if has_ziggy_ssz():
        try:
            obj = ZigAttestationData.from_response_json_bytes(response_json_bytes)
            return obj.hash_tree_root_hex()
        except Exception:
            pass

    decoded = json.loads(response_json_bytes)
    att_data = AttestationData.from_obj(decoded["data"])
    return "0x" + bytes(att_data.hash_tree_root()).hex()
