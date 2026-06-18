# Contributing

Thanks for taking a look. This project has one non-negotiable rule, and a few
conventions that follow from it.

## The one rule

`scan_cpu.c` is **ground truth by definition** — it implements Monero output
ownership on the project's vendored, unmodified ref10. Every change to the GPU
code must keep the GPU's found-set **byte-identical** to the CPU reference:

```sh
make test       # 10 seeded CPU self-tests — must all PASS
make gputest    # GPU found-set == CPU found-set on every fixture — must be 10/10
```

A mismatch is a GPU bug, never a CPU bug. No exceptions. PRs that touch scanning
must show both gates green (CI runs `make test`; `make gputest` needs a local
GPU — please run it and say so in the PR).

## Don't modify the vendored crypto

`crypto-ops.c`, `crypto-ops-data.c`, `crypto-ops.h`, `keccak.c`, `keccak.h`,
`hash-ops.h`, `int-util.h`, and `warnings.h` are kept **byte-for-byte** from
upstream Monero (see `THIRD_PARTY.md`). The GPU device code (`device_crypto.inc`)
is *generated* from them by `gen_device_crypto.py`, which only adds `__device__`
qualifiers and changes no math — that mechanical, math-free transform is what
guarantees GPU/CPU equality. Keep it that way: if upstream changes, re-vendor
the files rather than hand-editing.

## Build

```sh
make            # everything (CPU tools + gpu_scan)
make cpu        # CPU tools only — no CUDA toolkit needed
make ARCH=sm_89 # set your GPU arch (RTX 40xx=sm_89, 30xx=sm_86, ... or native)
```

Requires Linux (native or WSL2), `gcc`, `python3`, and — for the GPU scanner —
an NVIDIA GPU with CUDA toolkit 12.x or 13.x (`nvcc`).

## Style

Match the surrounding code: C99/CUDA C, two-space indent, terse comments that
explain *why*. Keep the CPU reference simple and readable — it is documentation
of the algorithm, not a place for optimization.
