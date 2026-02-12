from __future__ import annotations

from spec.configs import Network

try:
    from vero_ssz_grandine_py import GrandineSszContext
except ImportError:  # pragma: no cover
    GrandineSszContext = None


def has_rust_block_ssz() -> bool:
    return GrandineSszContext is not None


def network_to_preset(network: Network) -> str:
    if network in (Network.GNOSIS, Network.CHIADO):
        return "gnosis"
    if network == Network._TESTS:  # noqa: SLF001
        return "minimal"
    return "mainnet"


def make_rust_ssz_context(preset: str):
    if GrandineSszContext is None:
        raise RuntimeError("Grandine Rust SSZ extension not available")
    return GrandineSszContext.from_preset(preset)


def beacon_block_body_root_from_ssz(
    ssz_bytes: bytes,
    preset: str,
    ctx: object | None = None,
) -> str:
    rust_ctx = ctx if ctx is not None else make_rust_ssz_context(preset)
    rust_block = rust_ctx.beacon_block_from_ssz_bytes(ssz_bytes)
    return rust_block.body_root_hex()
