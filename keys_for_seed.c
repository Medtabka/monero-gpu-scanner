/*
 * keys_for_seed.c — print the synthetic wallet keys used by scan_cpu's
 * selftest for a given seed: view_priv (a) and spend_pub (B), hex.
 * Replicates scan_cpu.c's splitmix/rand_scalar sequence exactly.
 *
 * Usage: ./keys_for_seed <seed>
 * Then:  ./scan_cpu selftest <seed>          (writes /tmp/selftest.bin)
 *        ./scan_cpu scan /tmp/selftest.bin <a> <B>
 *        ./gpu_scan  scan /tmp/selftest.bin <a> <B>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define select crypto_ops_ge_select
#include "crypto-ops.c"
#undef select

static uint64_t rng_state;
static uint64_t splitmix(void) {
  uint64_t z = (rng_state += 0x9E3779B97F4A7C15ull);
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
  return z ^ (z >> 31);
}
static void rand_scalar(unsigned char s[32]) {
  for (int i = 0; i < 4; i++) { uint64_t v = splitmix(); memcpy(s + 8*i, &v, 8); }
  sc_reduce32(s);
}
static void print_hex(const char *label, const unsigned char *b) {
  printf("%s", label);
  for (int i = 0; i < 32; i++) printf("%02x", b[i]);
  printf("\n");
}

int main(int argc, char **argv) {
  rng_state = argc >= 2 ? strtoull(argv[1], 0, 10) : 1;
  unsigned char a[32], b[32], A[32], B[32];
  rand_scalar(a); rand_scalar(b);
  ge_p3 t;
  ge_scalarmult_base(&t, a); ge_p3_tobytes(A, &t);
  ge_scalarmult_base(&t, b); ge_p3_tobytes(B, &t);
  print_hex("view_priv: ", a);
  print_hex("spend_pub: ", B);
  return 0;
}
