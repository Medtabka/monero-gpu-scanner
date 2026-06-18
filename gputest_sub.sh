#!/bin/bash
# gputest_sub.sh — subaddress verification gate.
#
# Generates a synthetic fixture with planted subaddress outputs, INCLUDING
# transactions that pay two distinct subaddresses (extra tag 0x04, one
# additional tx pubkey per output), then scans it with scan_sub (CPU ground
# truth) and gpu_scan scansub. Requires:
#   GPU OWNED set == CPU OWNED set   (byte-identical)
#   CPU OWNED set == planted set     (found exactly what was planted)
#
# Usage: ./gputest_sub.sh [seed] [n_tx]
set -u
SEED=${1:-42}
NTX=${2:-200000}

keys=$(./keys_for_seed "$SEED")
a=$(echo "$keys" | awk '/view_priv/{print $2}')
B=$(echo "$keys" | awk '/spend_pub/{print $2}')

./subaddr_table "$a" "$B" 3 4 /tmp/sub_table.bin >/dev/null
./gen_bench_sub "$SEED" "$NTX" /tmp/sub_bench.bin > /tmp/sub_planted_raw.txt 2>/dev/null
sed 's/^PLANTED: /OWNED: /' /tmp/sub_planted_raw.txt | sort > /tmp/sub_planted.txt

./scan_sub scan /tmp/sub_bench.bin "$a" /tmp/sub_table.bin | grep '^OWNED' | sort > /tmp/sub_cpu.txt
./gpu_scan scansub /tmp/sub_bench.bin "$a" /tmp/sub_table.bin | grep '^OWNED' | sort > /tmp/sub_gpu.txt

np=$(wc -l < /tmp/sub_planted.txt)
nc=$(wc -l < /tmp/sub_cpu.txt)
ng=$(wc -l < /tmp/sub_gpu.txt)
fail=0

if diff -q /tmp/sub_cpu.txt /tmp/sub_gpu.txt >/dev/null; then
  echo "GPU == CPU: identical ($ng owned)  PASS"
else
  echo "GPU != CPU  ** FAIL **"; diff /tmp/sub_cpu.txt /tmp/sub_gpu.txt | head -20; fail=1
fi
if diff -q /tmp/sub_planted.txt /tmp/sub_cpu.txt >/dev/null; then
  echo "CPU == PLANTED: identical ($np planted)  PASS"
else
  echo "CPU != PLANTED  ** FAIL **"; diff /tmp/sub_planted.txt /tmp/sub_cpu.txt | head -20; fail=1
fi
echo "planted=$np cpu=$nc gpu=$ng"
exit $fail
