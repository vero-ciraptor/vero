from __future__ import annotations

try:
    from vero_ssz_ziggy import (
        zig_beacon_block_body_root_from_ssz_bytes as _zig_beacon_block_body_root_from_ssz_bytes,
    )
except ImportError:  # pragma: no cover - optional acceleration
    _zig_beacon_block_body_root_from_ssz_bytes = None


def has_ziggy_block_ssz() -> bool:
    return _zig_beacon_block_body_root_from_ssz_bytes is not None


def beacon_block_body_root_from_ssz_ziggy(ssz_bytes: bytes) -> str:
    if _zig_beacon_block_body_root_from_ssz_bytes is None:
        raise RuntimeError("ziggy block ssz extension not available")
    return str(_zig_beacon_block_body_root_from_ssz_bytes(ssz_bytes))
