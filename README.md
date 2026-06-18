# gpu-scan-kit

[![CI](https://github.com/Medtabka/monero-gpu-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/Medtabka/monero-gpu-scanner/actions/workflows/ci.yml)

**GPU-accelerated Monero wallet output scanning.** Given only a wallet's
**private view key** and **public spend key**, find every on-chain output that
belongs to it — the exact workload of a wallet restore / rescan and of
[`monero-lws`](https://github.com/vtnerd/monero-lws) server-side sync — but run
in parallel on a CUDA GPU instead of one CPU core.

Measured **~220× faster end-to-end** than the single-threaded reference scanner
on an RTX 3060 Ti over the full Monero stagenet chain (~10M outputs).

> **What this is — and isn't.** This accelerates the *view-key scan* step:
> deciding which outputs a wallet owns. That is the slow part of wallet
> restore and of light-wallet servers. It is **not** a Monero node, it does
> **not** verify blocks or do RandomX proof-of-work, and it does **not** change
> how the daemon syncs the blockchain. You still need a synced `monerod` (or a
> chain export) as the data source. Scanning needs only the *view* key, so it
> never touches spendable key material.

## How it works

Ownership of a Monero output is the standard CryptoNote test, computed with
Monero's own ed25519 reference code (ref10):

```
D  = 8 * (view_priv * R)                      # key derivation (R = tx public key)
vt = keccak("view_tag" || D || varint(i))[0]  # 1-byte view-tag prefilter
s  = sc_reduce32(keccak(D || varint(i)))       # derivation-to-scalar
P' = s*G + spend_pub                            # expected output key
own output  ⟺  P' == out_key   (and vt matches, when present)
```

`scan_cpu.c` implements exactly this on Monero's **unmodified** `crypto-ops.c`
+ `keccak.c`, and is treated as **ground truth by definition**.

`gpu_scan.cu` runs the same math on the GPU. The curve code is *not*
reimplemented: `gen_device_crypto.py` mechanically converts the vendored ref10
sources to CUDA device code by adding `__device__` qualifiers and **nothing
else**, so GPU results are bit-identical to the CPU reference by construction.
Keccak runs on the GPU too (the view-tag prefilter needs one hash per output
before anything else is known). Two kernels per chunk:

- `k_derive` — `D = 8·(a·R)` per `(tx, wallet)` (the dominant cost: one scalar
  mult per transaction)
- `k_check` — view-tag filter, then derived-key compare per `(output, wallet)`

Chain data is uploaded to VRAM once; each extra wallet in a batch costs only
64 key bytes, which is why multi-wallet scanning reaches a higher per-check
rate (the `monero-lws` worker shape).

## Build

Requirements: Linux (native or WSL2), `gcc`, `python3`, and — for the GPU
scanner — an NVIDIA GPU with CUDA toolkit 12.x or 13.x (`nvcc`).

```sh
make            # builds everything (CPU tools + gpu_scan)
make cpu        # CPU tools only — no CUDA toolkit required
make ARCH=sm_89 # set your GPU arch (RTX 40xx=sm_89, 30xx=sm_86, 20xx=sm_75,
                #   A100=sm_80, H100=sm_90, or ARCH=native)
```

## Verify (no node needed)

```sh
make test        # 10 seeded CPU self-tests — all must say PASS
make gputest     # GPU found-set == CPU found-set on every fixture
make gputest_sub # subaddress gate, incl. tag-0x04 multi-subaddress txs:
                 #   GPU == CPU == planted
```

The self-test builds a synthetic wallet, plants real outputs to it among
thousands of decoys (mixed view-tag and pre-view-tag style), scans, and
requires the found set to equal the planted set **exactly**.

## Quick demo (synthetic chain, ~1 min, GPU optional)

```sh
./gen_bench 42 1000000 bench.bin               # 1M-tx chain, plants 215 outputs
./keys_for_seed 42                             # prints view_priv + spend_pub
./scan_cpu scan bench.bin <view_priv> <spend_pub>   # CPU baseline
./gpu_scan scan bench.bin <view_priv> <spend_pub>   # same 215, far faster
```

## Scan a real chain

1. **Export** the blockchain from a synced `monerod` into the flat `XMRSCAN1`
   format (stagenet RPC port shown; mainnet is `18081`):

   ```sh
   python3 export_chain.py --rpc http://127.0.0.1:38081 --from 0 --to -1 --out chain.bin
   # export_chain_fast.py is a parallel, byte-identical variant:
   #   local node --workers 12-24; public nodes rate-limit, use --workers 2
   ```

2. **Scan** with your private view key + public spend key:

   ```sh
   ./scan_cpu scan  chain.bin <view_priv_hex64> <spend_pub_hex64>   # reference
   ./gpu_scan scan  chain.bin <view_priv_hex64> <spend_pub_hex64>   # GPU, identical result
   ```

   It prints every owned output (`height`, `index`) plus outputs/sec. Compare
   the owned list against the wallet's own transaction history — they must match.

### Other modes

```sh
# Many wallets in one pass (chain uploaded to VRAM once; up to 256 wallets).
# wallets.txt: one "view_priv spend_pub [label]" per line.
./gpu_scan scanmulti chain.bin wallets.txt

# Subaddresses. Precompute a (major x minor) table, then scan against it.
./subaddr_table <view_priv> <spend_pub> <maj_n> <min_n> table.bin
./gpu_scan  scansub chain.bin <view_priv> table.bin
./scan_sub  scan    chain.bin <view_priv> table.bin    # CPU reference
```

## Benchmarks

Measured on an RTX 3060 Ti (sm_86, CUDA 12.4, WSL2) over the full stagenet
chain: 491 MB, 4,107,343 txs, 9,986,034 outputs.

| Configuration | Time | Throughput |
|---|---|---|
| `scan_cpu` (1 thread, reference) | ~730 s | 13.7k outputs/s |
| `gpu_scan`, warm cache | 3.3–3.6 s | up to 2.9M outputs/s |
| **ratio** | | **~220× end-to-end, ~298× kernel-only** |
| `gpu_scan scanmulti`, 64 wallets × ~3M outputs | 33.3 s | **5.77M wallet-checks/s** |

Also measured on an **RTX 4080 SUPER** (sm_89, CUDA 13.3, gcc 15, WSL2): the
same full chain scanned in **1.33 s (7.5M outputs/s)**, returning the identical
owned set.

~80% of GPU time is `k_derive` (the unavoidable per-tx scalar mult); batching
wallets amortizes everything else. Mainnet (~120M outputs) projects to minutes
on the GPU versus hours per CPU core.

## Verification status

All gates green (as of 2026-06-10):

| Gate | Result |
|---|---|
| CPU self-test, 10 seeds | 10/10 PASS |
| GPU == CPU on self-test fixtures (`make gputest`) | 10/10 byte-identical |
| GPU == CPU, full real stagenet chain (10M outputs) | identical, incl. all counters |
| Multi-wallet: per-wallet GPU sets == per-wallet CPU runs (3-wallet fixture) | identical |
| 64-wallet batch, 192M wallet-checks | 0 false positives; planted wallet found exactly |
| Subaddress synthetic (338 plants, 3×4 grid) | planted == CPU == GPU |
| Subaddress incl. tag-0x04 multi-subaddress txs (`make gputest_sub`) | planted == CPU == GPU |
| End-to-end vs real stagenet faucet wallet | scanners found exactly the wallet's outputs |
| Determinism / malformed input | repeated runs byte-identical; bad magic & truncation rejected cleanly |

Re-verified 2026-06-18 on a clean build (Ubuntu 26.04, gcc 15, CUDA 13.3, RTX
4080 SUPER): 10/10 CPU self-test, 10/10 `make gputest`, `make gputest_sub` green
(481/481 incl. tag-0x04 outputs), and the full real chain returned the expected
outputs.

**The one rule:** `scan_cpu.c`'s results are correct by definition. Every change
to GPU code must keep `make gputest` green. A mismatch is a GPU bug — no
exceptions.

## File format `XMRSCAN2`

```
magic "XMRSCAN2"
per tx:  u32 height | u8 n_out | u8 flags | R[32]
         if flags&1:  n_out × R_add[32]    (additional tx pubkeys, extra tag 0x04)
         n_out × ( key[32] | vt_flag u8 | vt u8 )
```

Little-endian. Includes coinbase txs; txs with no parsable tx pubkey are
skipped; at most 255 outputs per tx (well above any real tx). The additional
pubkey array is present only for transactions that pay multiple distinct
subaddresses. All readers also accept the older `XMRSCAN1` (no flags byte, no
additional keys), so existing exports keep working.

## Repository layout

| File | Role |
|------|------|
| `scan_cpu.c` | CPU reference scanner (ground truth) + self-test |
| `gpu_scan.cu` | CUDA scanner: `scan`, `scanmulti`, `scansub` |
| `gen_device_crypto.py` | generates `device_crypto.inc` (ref10 → CUDA, `__device__` only) |
| `scan_sub.c` | CPU reference for subaddress scanning |
| `subaddr_table.c` | precompute a subaddress spend-key table |
| `export_chain.py` / `export_chain_fast.py` | dump a chain from `monerod` RPC to `XMRSCAN2` (sequential / parallel) |
| `gen_bench.c` / `gen_bench_sub.c` | synthetic test chains with planted outputs |
| `keys_for_seed.c` / `keys_tool.c` | self-test wallet keys / pubkeys + address from private keys |
| `crypto-ops*.c/.h`, `keccak.*`, `*-util.h`, `warnings.h` | **vendored, unmodified** Monero ref10 + keccak (see `THIRD_PARTY.md`) |

## Known limitations / next steps

- **Additional tx pubkeys (`extra` tag `0x04`)** — *supported* as of the
  `XMRSCAN2` format: txs paying 2+ distinct subaddresses store one `R` per
  output, and subaddress scanning tries both the main and the per-output
  additional derivation (verified by `make gputest_sub`). This was the main gap
  for production lws use.
- `scanmulti` and `scansub` are separate modes; combined multi-wallet ×
  subaddress is a straightforward merge.
- No async H2D/kernel overlap yet (pinned memory + streams would hide the
  ~0.1 s transfer). `k_derive` itself is the next real optimization target
  (batched / Montgomery tricks).
- The CPU reference is deliberately unoptimized — it is ground truth, not a
  competitor.

## License & attribution

BSD 3-Clause — see [`LICENSE`](LICENSE). This project vendors unmodified
cryptographic source from the Monero project; that code keeps its own copyright
and is documented in [`THIRD_PARTY.md`](THIRD_PARTY.md). Not affiliated with or
endorsed by the Monero project.
