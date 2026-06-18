#!/bin/bash
# gputest.sh — verification gate: for each selftest seed, scan the same
# fixture file with scan_cpu (ground truth) and gpu_scan; the OWNED sets
# must be byte-identical. Any diff = FAIL.
set -u
fail=0
for s in 1 2 3 4 5 6 7 8 9 10; do
  ./scan_cpu selftest $s >/dev/null || { echo "seed $s: selftest gen failed"; fail=1; continue; }
  keys=$(./keys_for_seed $s)
  a=$(echo "$keys" | awk '/view_priv/{print $2}')
  B=$(echo "$keys" | awk '/spend_pub/{print $2}')
  ./scan_cpu scan /tmp/selftest.bin "$a" "$B" | grep '^OWNED' > /tmp/cpu_owned.txt
  ./gpu_scan scan /tmp/selftest.bin "$a" "$B" | grep '^OWNED' > /tmp/gpu_owned.txt
  n=$(wc -l < /tmp/cpu_owned.txt)
  if diff -q /tmp/cpu_owned.txt /tmp/gpu_owned.txt >/dev/null; then
    echo "seed $s: cpu=$n gpu=$n identical  PASS"
  else
    echo "seed $s: MISMATCH  ** FAIL **"
    diff /tmp/cpu_owned.txt /tmp/gpu_owned.txt | head -20
    fail=1
  fi
done
exit $fail
