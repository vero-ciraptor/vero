# Zig SSZ acceleration plan (ChainSafe lodestar-z)

## Goal
Replace remerkleable for performance-intensive SSZ operations via a Zig native library, keeping Python fallback paths safe.

## Decision
Use a minimal, hand-rolled C ABI (stable and packaging-friendly) instead of framework-specific Python bindings.

## ABI v0
Exported functions (all return `0` on success, non-zero on error):

- `vero_attestation_data_root_from_ssz(input_ptr, input_len, out_ptr, err_ptr, err_len)`
- `vero_attestation_data_root_from_response_json(input_ptr, input_len, out_ptr, err_ptr, err_len)`

Conventions:
- `out_ptr` points to 32 writable bytes.
- `err_ptr` is optional UTF-8 null-terminated error message buffer.
- Python loader must treat non-zero return code as a soft failure and use existing fallback.

## Current status
- Added Zig shared library scaffold at `zig/vero_ssz_zig`.
- Added Python ctypes loader/wrapper at `src/utils/ssz_fast_zig.py`.
- Wired `src/utils/ssz_fast.py` to attempt Zig first, then Rust, then Python fallback.
- Zig functions currently return `not implemented` (no behavior change in production paths).

## Next implementation steps
1. Vendor/import ChainSafe `lodestar-z/src/ssz` as pinned dependency.
2. Implement SSZ decode + `hash_tree_root` for `AttestationData` in Zig.
3. Implement JSON-bytes fast path (or JSON->Python->SSZ bytes first, then Zig root).
4. Add parity tests and benchmark harness (`N=300`, JSON-bytes start).
5. Add Docker/uv integration to build and load the Zig shared library in CI.
