from __future__ import annotations

import argparse
import statistics
import time
from collections.abc import Callable

from spec import SpecAttestation, SpecBeaconBlock, SpecSyncCommittee
from spec.configs import Network, get_network_spec
from utils.ssz_fast_block import beacon_block_body_root_from_ssz, make_rust_ssz_context
from utils.ssz_fast_block_ziggy import (
    beacon_block_body_root_from_ssz_ziggy,
    has_ziggy_block_ssz,
)


def percentile(sorted_vals: list[float], p: float) -> float:
    if not sorted_vals:
        return float("nan")
    k = (len(sorted_vals) - 1) * p
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return sorted_vals[f]
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)


def bench(name: str, fn: Callable[[], str], iterations: int) -> None:
    timings_ms: list[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        _ = fn()
        timings_ms.append((time.perf_counter() - t0) * 1000.0)

    timings_ms.sort()
    mean = statistics.fmean(timings_ms)
    med = statistics.median(timings_ms)
    p95 = percentile(timings_ms, 0.95)
    p99 = percentile(timings_ms, 0.99)
    total_s = sum(timings_ms) / 1000.0

    print(
        f"{name}: total={total_s:.3f}s mean={mean:.3f}ms "
        f"median={med:.3f}ms p95={p95:.3f}ms p99={p99:.3f}ms"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark BeaconBlock body root paths")
    parser.add_argument("--tx-count", type=int, default=350)
    parser.add_argument("--tx-bytes", type=int, default=180)
    parser.add_argument("--iterations", type=int, default=300)
    args = parser.parse_args()

    spec = get_network_spec(network=Network.MAINNET, network_custom_config_path=None)
    SpecAttestation.initialize(spec=spec)
    SpecBeaconBlock.initialize(spec=spec)
    SpecSyncCommittee.initialize(spec=spec)

    beacon_block_t = SpecBeaconBlock.ElectraBlockSigned.fields()["message"]
    block = beacon_block_t()

    tx = bytes.fromhex("ab" * args.tx_bytes)
    for _ in range(args.tx_count):
        block.body.execution_payload.transactions.append(tx)

    ssz_bytes = bytes(block.encode_bytes())
    rust_ctx = make_rust_ssz_context("mainnet")

    py_root = "0x" + bytes(beacon_block_t.decode_bytes(ssz_bytes).body.hash_tree_root()).hex()
    rust_root = beacon_block_body_root_from_ssz(
        ssz_bytes=ssz_bytes,
        preset="mainnet",
        ctx=rust_ctx,
    )
    if py_root != rust_root:
        raise RuntimeError("Python vs Rust root mismatch")

    zig_ok = has_ziggy_block_ssz()
    if zig_ok:
        zig_root = beacon_block_body_root_from_ssz_ziggy(ssz_bytes)
        if py_root != zig_root:
            raise RuntimeError("Python vs Zig root mismatch")

    print(
        f"correctness: OK | zig_available={zig_ok} | tx_count={args.tx_count} "
        f"tx_bytes={args.tx_bytes} block_ssz_size={len(ssz_bytes)} iterations={args.iterations}"
    )

    bench(
        "python_beacon_block_body_root_from_ssz",
        lambda: "0x" + bytes(beacon_block_t.decode_bytes(ssz_bytes).body.hash_tree_root()).hex(),
        args.iterations,
    )
    bench(
        "rust_beacon_block_body_root_from_ssz",
        lambda: beacon_block_body_root_from_ssz(
            ssz_bytes=ssz_bytes,
            preset="mainnet",
            ctx=rust_ctx,
        ),
        args.iterations,
    )

    if zig_ok:
        bench(
            "ziggy_beacon_block_body_root_from_ssz",
            lambda: beacon_block_body_root_from_ssz_ziggy(ssz_bytes),
            args.iterations,
        )


if __name__ == "__main__":
    main()
