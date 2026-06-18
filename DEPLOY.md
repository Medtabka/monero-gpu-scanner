# Design & handoff notes

Deeper background on the scanner than the [README](README.md). If you just
want to build and run it, start there.

GPU-accelerated Monero wallet scanning: find all outputs owned by a wallet
given only its **private view key** and **public spend key** — the workload of
wallet restore and of `monero-lws` server-side sync. Measured **~220× faster
than the single-threaded reference** on an RTX 3060 Ti over the full stagenet
chain.

## What was built

1. **`scan_cpu`** (`scan_cpu.c`) — reference scanner on Monero's own
   unmodified ref10 (`crypto-ops.c`) + keccak. Ground truth **by definition**.
   The self-test plants outputs for a synthetic wallet among decoys; the found
   set must equal the planted set. 10 seeds, all PASS.

2. **`gpu_scan`** (`gpu_scan.cu`) — CUDA scanner, three modes:
   - `scan` — single wallet, output identical to `scan_cpu`.
   - `scanmulti` — up to 256 wallets in one pass over chain data uploaded to
     VRAM once (the `monero-lws` worker shape).
   - `scansub` — subaddress scanning: recovers `C = out_key − H_s(D‖i)·G` per
     output and binary-searches a precomputed subaddress table.

   The curve math is **not reimplemented**: `gen_device_crypto.py` mechanically
   converts the vendored ref10 sources to CUDA device code (adds `__device__`
   qualifiers, changes nothing else), so GPU results are bit-identical to the
   CPU reference by construction. Keccak (view tags, derived scalars) runs
   on-GPU. Two kernels per chunk: `k_derive` = `D = 8·(a·R)` per `(tx,wallet)`;
   `k_check` = view-tag filter + derived-key compare per `(output,wallet)`.

3. **`scan_sub`** (`scan_sub.c`) — CPU reference for subaddress mode.
   **`subaddr_table`** (`subaddr_table.c`) — precomputes subaddress spend keys
   `B + H_s("SubAddr\0"‖a‖maj‖min)·G` over a `(major×minor)` range.

4. **Exporters** — `export_chain.py` (sequential, fixture-tested) and
   `export_chain_fast.py` (parallel, retrying; output byte-identical to the
   sequential one — verified by diff). Both dump `(tx pubkey, output keys, view
   tags)` from any `monerod` RPC into the flat `XMRSCAN1` format.

5. **Test generators** — `gen_bench.c` (large synthetic chains with planted
   outputs), `gen_bench_sub.c` (subaddress plants incl. real `R = r·B_sub`
   subaddress-style sends), `keys_for_seed.c` (self-test wallet keys),
   `keys_tool.c` (pubkeys + mainnet/stagenet address from private keys).

## Verification status (all gates green, 2026-06-10)

| Gate | Result |
|---|---|
| CPU self-test, 10 seeds | 10/10 PASS |
| GPU == CPU on self-test fixtures (`make gputest`) | 10/10 byte-identical |
| GPU == CPU, full real stagenet chain (10M outputs) | identical (incl. all counters) |
| Multi-wallet: per-wallet GPU sets == per-wallet CPU runs (3-wallet fixture) | identical |
| 64-wallet batch, 192M wallet-checks | 0 false positives; the 1 planted wallet found exactly (215/215, == its single-wallet run) |
| Subaddress synthetic (338 plants on 3×4 grid) | planted == CPU == GPU |
| Subaddress (0,0) cross-check vs `scan_cpu` | identical (26/26) |
| End-to-end vs real wallet (stagenet faucet) | scanners found exactly the wallet's outputs: 2 primary @ 2138073 + subaddr 0/1 @ 2138294, matching `get_transfers` |
| Determinism | repeated runs byte-identical |
| Malformed input (bad magic / truncation) | detected, clean error, no crash |

## Measured performance (RTX 3060 Ti, sm_86, CUDA 12.4, WSL2)

Full real stagenet chain: 491 MB, 4,107,343 txs, 9,986,034 outputs.

| Configuration | Time | Throughput |
|---|---|---|
| `scan_cpu` (1 thread, reference) | ~730 s | 13.7k outputs/s |
| `gpu_scan`, warm cache | 3.3–3.6 s | up to 2.9M outputs/s |
| → ratio | | **~220× end-to-end, ~298× kernel-only** |
| `gpu_scan scanmulti`, 64 wallets × 3M outputs | 33.3 s | **5.77M wallet-checks/s** |

~80% of GPU time is `k_derive` (the unavoidable per-tx scalar mult);
multi-wallet batching amortizes everything else, hence the higher per-check
rate. Mainnet projection (~120M outputs): minutes on GPU vs hours per CPU core.

## Setting up a new machine

Requirements: Linux (native or WSL2), `gcc`, `python3`, NVIDIA GPU + driver,
CUDA toolkit 12.x (`nvcc`).

```sh
# If the GPU is NOT an RTX 30-series, set ARCH:
#   RTX 40xx: sm_89   RTX 20xx: sm_75   A100: sm_80   H100: sm_90
#   or simply: make ARCH=native  (builds for whatever GPU is present)
make            # builds all CPU tools + gpu_scan
make test       # 10x CPU self-test   -> all PASS
make gputest    # GPU==CPU gate        -> all PASS, 10/10
```

Optional, saves hours: copy a prebuilt `chain.bin` (full stagenet export) to
skip running a stagenet node entirely; the scanners need only that file plus
keys.

### Quick live demo without any node (~1 min)

```sh
./gen_bench 42 1000000 bench.bin            # plants 215 outputs
./keys_for_seed 42                          # prints view_priv + spend_pub
time ./scan_cpu scan bench.bin <view_priv> <spend_pub>
time ./gpu_scan  scan bench.bin <view_priv> <spend_pub>   # same 215, far faster
```

### Real-chain demo (throwaway stagenet wallet)

With a `chain.bin` exported from a synced stagenet node. These are disposable
**stagenet** test keys — safe to publish; never reuse this pattern with mainnet
keys.

```sh
./gpu_scan scan chain.bin \
  3d9be46053edb2153e49fc3ece0c8ee4dfcec34952514f1e33005751220bb00f \
  5ade2563c6e69a1fc8d3cc13cd0790b21a416db999e2334fbbe54ed967ddaf1d
# -> OWNED: height 2138073, output 0 + output 1 (the faucet outputs)
```

Subaddresses / multi-wallet / fresh export: see the [README](README.md).

## Known limitations / next steps

- **Additional tx pubkeys (extra tag `0x04`)** — txs paying 2+ distinct
  subaddress destinations carry one `R` per output; `XMRSCAN1` doesn't store
  them, so such outputs are invisible to the scanner. Needs an `XMRSCAN2`
  format rev (optional per-output `R`). This is the main gap for production lws
  use; single-destination subaddress payments (the common case, incl. the
  faucet test) work.
- `scanmulti` and `scansub` are separate modes; combined multi-wallet×subaddr
  is a straightforward merge (per-wallet table sections).
- No async H2D/kernel overlap yet (pinned memory + streams ≈ shave the ~0.1 s
  transfer + overlap chunks); `k_derive` itself is the next real optimization
  target (batched / Montgomery tricks).
- CPU reference is deliberately unoptimized (it's ground truth, not a
  competitor).

## The one rule

`scan_cpu.c`'s results are correct by definition. Every change to GPU code must
keep `make gputest` green and, ideally, re-diff against a full-chain CPU run.
A mismatch is a GPU bug. No exceptions.
