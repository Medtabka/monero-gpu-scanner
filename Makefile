# gpu-scan-kit — build
#
#   make            build everything (CPU tools + GPU scanner)
#   make cpu        build only the CPU tools (no CUDA toolkit needed)
#   make gpu        build only gpu_scan (needs nvcc)
#   make test       10x CPU self-test (must all PASS)
#   make gputest    GPU found-set == CPU found-set on the self-test fixtures
#   make clean
#
# GPU arch: override ARCH for your card, e.g. `make ARCH=sm_89` (RTX 40xx),
# sm_75 (RTX 20xx), sm_80 (A100), sm_90 (H100), or `make ARCH=native`.

CC      = gcc
CFLAGS  = -O2
NVCC    = nvcc
ARCH    = sm_86
# 128 regs measured ~+20% kernel throughput on Ampere; tune for your card.
NVCCFLAGS = -O3 -arch=$(ARCH) -maxrregcount=128

# crypto-ops.c is #included directly by the C scanners; these are the extra
# translation units every CPU tool links against.
CRYPTO  = keccak.c crypto-ops-data.c

CPU_BINS = scan_cpu scan_sub subaddr_table keys_for_seed keys_tool \
           gen_bench gen_bench_sub
GPU_BINS = gpu_scan

all: cpu gpu
cpu: $(CPU_BINS)
gpu: $(GPU_BINS)

scan_cpu: scan_cpu.c $(CRYPTO) crypto-ops.c crypto-ops.h keccak.h
	$(CC) $(CFLAGS) -o $@ scan_cpu.c $(CRYPTO)
scan_sub: scan_sub.c $(CRYPTO) crypto-ops.c crypto-ops.h keccak.h
	$(CC) $(CFLAGS) -o $@ scan_sub.c $(CRYPTO)
subaddr_table: subaddr_table.c $(CRYPTO) crypto-ops.c crypto-ops.h keccak.h
	$(CC) $(CFLAGS) -o $@ subaddr_table.c $(CRYPTO)
gen_bench: gen_bench.c $(CRYPTO) crypto-ops.c crypto-ops.h keccak.h
	$(CC) $(CFLAGS) -o $@ gen_bench.c $(CRYPTO)
gen_bench_sub: gen_bench_sub.c $(CRYPTO) crypto-ops.c crypto-ops.h keccak.h
	$(CC) $(CFLAGS) -o $@ gen_bench_sub.c $(CRYPTO)
keys_for_seed: keys_for_seed.c crypto-ops-data.c
	$(CC) $(CFLAGS) -o $@ keys_for_seed.c crypto-ops-data.c
keys_tool: keys_tool.c $(CRYPTO)
	$(CC) $(CFLAGS) -o $@ keys_tool.c $(CRYPTO)

# Generated GPU device code: vendored ref10 + keccakf with __device__ prefixes.
device_crypto.inc: gen_device_crypto.py crypto-ops.c crypto-ops-data.c crypto-ops.h keccak.c
	python3 gen_device_crypto.py
gpu_scan: gpu_scan.cu device_crypto.inc
	$(NVCC) $(NVCCFLAGS) -o $@ gpu_scan.cu

test: scan_cpu
	@for s in 1 2 3 4 5 6 7 8 9 10; do ./scan_cpu selftest $$s; done

# gate: GPU found-set must equal CPU found-set on the self-test fixtures
gputest: scan_cpu gpu_scan keys_for_seed
	./gputest.sh

clean:
	rm -f $(CPU_BINS) $(GPU_BINS) device_crypto.inc

.PHONY: all cpu gpu test gputest clean
