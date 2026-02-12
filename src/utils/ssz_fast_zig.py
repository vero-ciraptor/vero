from __future__ import annotations

import ctypes
import os
from ctypes import c_int, c_size_t, c_ubyte
from pathlib import Path


class _ZigSszLibrary:
    def __init__(self, lib: ctypes.CDLL) -> None:
        self._lib = lib

        self._from_ssz = lib.vero_attestation_data_root_from_ssz
        self._from_ssz.argtypes = [
            ctypes.POINTER(c_ubyte),
            c_size_t,
            ctypes.POINTER(c_ubyte),
            ctypes.POINTER(c_ubyte),
            c_size_t,
        ]
        self._from_ssz.restype = c_int

        self._from_json = lib.vero_attestation_data_root_from_response_json
        self._from_json.argtypes = [
            ctypes.POINTER(c_ubyte),
            c_size_t,
            ctypes.POINTER(c_ubyte),
            ctypes.POINTER(c_ubyte),
            c_size_t,
        ]
        self._from_json.restype = c_int

    @staticmethod
    def _call(func: object, payload: bytes) -> bytes:
        in_buf = (c_ubyte * len(payload)).from_buffer_copy(payload)
        out_buf = (c_ubyte * 32)()
        err_buf = (c_ubyte * 256)()

        rc = func(in_buf, len(payload), out_buf, err_buf, len(err_buf))
        if rc != 0:
            err = ctypes.string_at(ctypes.addressof(err_buf), len(err_buf))
            msg = err.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
            raise RuntimeError(msg or f"zig_ssz error code: {rc}")

        return bytes(out_buf)

    def attestation_root_from_ssz(self, payload: bytes) -> bytes:
        return self._call(self._from_ssz, payload)

    def attestation_root_from_response_json(self, payload: bytes) -> bytes:
        return self._call(self._from_json, payload)


def _candidate_paths() -> list[Path]:
    env_path = os.getenv("VERO_ZIG_SSZ_LIB")
    if env_path:
        return [Path(env_path)]

    project_root = Path(__file__).resolve().parents[2]
    base = project_root / "zig" / "vero_ssz_zig" / "zig-out" / "lib"

    return [
        base / "libvero_ssz_zig.so",
        base / "libvero_ssz_zig.dylib",
        base / "vero_ssz_zig.dll",
    ]


def _load() -> _ZigSszLibrary | None:
    for path in _candidate_paths():
        if not path.exists():
            continue

        try:
            return _ZigSszLibrary(ctypes.CDLL(str(path)))
        except OSError:
            continue

    return None


_LIB = _load()


def has_zig_ssz() -> bool:
    return _LIB is not None


def attestation_data_root_hex_from_ssz_bytes_zig(ssz_bytes: bytes) -> str:
    if _LIB is None:
        raise RuntimeError("zig ssz library not available")

    root = _LIB.attestation_root_from_ssz(ssz_bytes)
    return "0x" + root.hex()


def attestation_data_root_hex_from_response_json_bytes_zig(response_json: bytes) -> str:
    if _LIB is None:
        raise RuntimeError("zig ssz library not available")

    root = _LIB.attestation_root_from_response_json(response_json)
    return "0x" + root.hex()
