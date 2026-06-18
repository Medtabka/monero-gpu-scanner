# Third-party code

This repository vendors unmodified cryptographic source from the Monero
project so that the scanner's curve math is, by construction, identical to a
real wallet's. These files are **not** original to this project and carry
their own copyright (see `LICENSE`, BSD 3-Clause):

| File | Origin |
|------|--------|
| `crypto-ops.c`, `crypto-ops-data.c`, `crypto-ops.h` | The Monero Project — ref10 ed25519 group/scalar ops |
| `keccak.c`, `keccak.h` | Keccak (SHA-3) — baseline implementation by Markku-Juhani O. Saarinen, as vendored by Monero |
| `hash-ops.h`, `int-util.h`, `warnings.h` | The Monero Project — supporting headers |

These files are kept byte-for-byte as upstream. The GPU port
(`device_crypto.inc`) is generated from them by `gen_device_crypto.py`, which
only prefixes `__device__` to function/data definitions and changes no math —
this is what guarantees the GPU results match the CPU reference exactly.

Everything else in this repository (`scan_cpu.c`, `scan_sub.c`, `gpu_scan.cu`,
`subaddr_table.c`, the test generators, the exporters, and the build/test
tooling) is original work.

Upstream Monero source: https://github.com/monero-project/monero
