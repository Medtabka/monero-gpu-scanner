# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- Continuous integration: GitHub Actions builds the CPU tools and runs the 10x
  self-test on every push.
- `CONTRIBUTING.md`, `SECURITY.md`, and this changelog.

### Changed
- Build requirements note CUDA 13.x support (in addition to 12.x).
- README: added an RTX 4080 SUPER benchmark and a 2026-06-18 re-verification.

## [0.1.0] - 2026-06-10

First public release.

### Added
- `scan_cpu` — reference Monero output scanner on vendored, unmodified ref10
  (ground truth) + 10-seed self-test.
- `gpu_scan` — CUDA scanner with `scan`, `scanmulti` (up to 256 wallets in one
  VRAM pass), and `scansub` (subaddress) modes; device crypto generated from
  ref10 by `gen_device_crypto.py` (`__device__` only, math unchanged).
- `scan_sub` (CPU subaddress reference) and `subaddr_table` (table precompute).
- Chain exporters `export_chain.py` and `export_chain_fast.py` (XMRSCAN1).
- Test generators `gen_bench` / `gen_bench_sub`, key tools `keys_for_seed` /
  `keys_tool`, and the `make gputest` GPU==CPU verification gate.

### Verified
- 10/10 CPU self-test; 10/10 GPU==CPU byte-identical on fixtures; GPU == CPU on
  a full real stagenet chain (~10M outputs).
- Measured ~220x end-to-end over the single-threaded reference on an RTX 3060 Ti.
