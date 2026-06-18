/*
 * gen_bench_sub.c — synthetic XMRSCAN1 fixture with SUBADDRESS plants.
 *
 * Wallet keys derive from the seed exactly like keys_for_seed. Plants are
 * spread over subaddresses (major,minor) in [0,MAJ_N) x [0,MIN_N):
 *   (0,0): standard send     R = r*G,     D = 8*r*A
 *   else : subaddress send   R = r*B_sub, D = 8*r*A_sub, A_sub = a*B_sub
 * Either way the receiver computes D = 8*a*R and recovers
 * out_key - H_s(D||i)*G = B_sub. Decoys are random bytes. All view-tagged.
 *
 * Prints one "PLANTED: height H, output I, subaddr M/N" line per plant
 * (ground truth for the gate) plus a summary.
 *
 * Usage: ./gen_bench_sub <seed> <n_tx> <out.bin>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define select crypto_ops_ge_select
#include "crypto-ops.c"
#undef select
#include "keccak.h"

#define MAJ_N 3
#define MIN_N 4

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
static size_t write_varint(unsigned char *buf, uint64_t v) {
  size_t n = 0;
  while (v >= 0x80) { buf[n++] = (unsigned char)(v) | 0x80; v >>= 7; }
  buf[n++] = (unsigned char)v;
  return n;
}
static int gen_derivation(unsigned char D[32], const unsigned char R[32],
                          const unsigned char a[32]) {
  ge_p3 point; ge_p2 point2; ge_p1p1 point3;
  if (ge_frombytes_vartime(&point, R) != 0) return 0;
  ge_scalarmult(&point2, a, &point);
  ge_mul8(&point3, &point2);
  ge_p1p1_to_p2(&point2, &point3);
  ge_tobytes(D, &point2);
  return 1;
}
static void derivation_to_scalar(unsigned char s[32], const unsigned char D[32],
                                 uint64_t idx) {
  unsigned char buf[42];
  memcpy(buf, D, 32);
  size_t n = 32 + write_varint(buf + 32, idx);
  keccak(buf, n, s, 32);
  sc_reduce32(s);
}
static unsigned char derive_view_tag(const unsigned char D[32], uint64_t idx) {
  unsigned char buf[50], h[32];
  memcpy(buf, "view_tag", 8);
  memcpy(buf + 8, D, 32);
  size_t n = 8 + 32 + write_varint(buf + 40, idx);
  keccak(buf, n, h, 32);
  return h[0];
}
/* P = H_s(D||i)*G + base (base given as bytes) */
static int derive_public_key(unsigned char P[32], const unsigned char D[32],
                             uint64_t idx, const unsigned char base[32]) {
  unsigned char s[32];
  ge_p3 B, sG, sum; ge_cached Bc; ge_p1p1 t;
  if (ge_frombytes_vartime(&B, base) != 0) return 0;
  derivation_to_scalar(s, D, idx);
  ge_scalarmult_base(&sG, s);
  ge_p3_to_cached(&Bc, &B);
  ge_add(&t, &sG, &Bc);
  ge_p1p1_to_p3(&sum, &t);
  ge_p3_tobytes(P, &sum);
  return 1;
}

int main(int argc, char **argv) {
  if (argc != 4) { fprintf(stderr, "usage: %s <seed> <n_tx> <out.bin>\n", argv[0]); return 1; }
  rng_state = strtoull(argv[1], 0, 10);
  long n_tx = atol(argv[2]);

  unsigned char a[32], b[32], A[32], B[32];
  rand_scalar(a); rand_scalar(b);          /* same order as keys_for_seed */
  ge_p3 t;
  ge_scalarmult_base(&t, a); ge_p3_tobytes(A, &t);
  ge_scalarmult_base(&t, b); ge_p3_tobytes(B, &t);

  /* precompute subaddress spend keys B_sub and view keys A_sub = a*B_sub */
  unsigned char Bsub[MAJ_N][MIN_N][32], Asub[MAJ_N][MIN_N][32];
  ge_p3 Bp3;
  ge_frombytes_vartime(&Bp3, B);
  ge_cached Bc;
  ge_p3_to_cached(&Bc, &Bp3);
  for (uint32_t maj = 0; maj < MAJ_N; maj++) {
    for (uint32_t min = 0; min < MIN_N; min++) {
      if (maj == 0 && min == 0) {
        memcpy(Bsub[0][0], B, 32);
        memcpy(Asub[0][0], A, 32);
        continue;
      }
      unsigned char buf[48], m[32];
      memcpy(buf, "SubAddr\0", 8);
      memcpy(buf + 8, a, 32);
      memcpy(buf + 40, &maj, 4);
      memcpy(buf + 44, &min, 4);
      keccak(buf, 48, m, 32);
      sc_reduce32(m);
      ge_p3 mG, sum; ge_p1p1 tt;
      ge_scalarmult_base(&mG, m);
      ge_add(&tt, &mG, &Bc);
      ge_p1p1_to_p3(&sum, &tt);
      ge_p3_tobytes(Bsub[maj][min], &sum);
      ge_p3 Bs, As;
      ge_frombytes_vartime(&Bs, Bsub[maj][min]);
      ge_scalarmult_p3(&As, a, &Bs);       /* A_sub = a * B_sub */
      ge_p3_tobytes(Asub[maj][min], &As);
    }
  }

  FILE *f = fopen(argv[3], "wb");
  if (!f) { perror("open"); return 1; }
  setvbuf(f, NULL, _IOFBF, 1 << 20);
  fwrite("XMRSCAN1", 1, 8, f);

  long planted = 0;
  for (long x = 0; x < n_tx; x++) {
    unsigned n_out = 2 + (unsigned)(splitmix() % 3);
    int plant = (splitmix() % 1000 == 0);
    unsigned plant_idx = plant ? (unsigned)(splitmix() % n_out) : 0;
    uint32_t maj = (uint32_t)(splitmix() % MAJ_N);
    uint32_t min = (uint32_t)(splitmix() % MIN_N);

    unsigned char r[32], R[32], Dsender[32] = {0};
    rand_scalar(r);
    if (plant && !(maj == 0 && min == 0)) {
      ge_p3 Bs, Rp;                         /* subaddress send: R = r*B_sub */
      ge_frombytes_vartime(&Bs, Bsub[maj][min]);
      ge_scalarmult_p3(&Rp, r, &Bs);
      ge_p3_tobytes(R, &Rp);
      if (!gen_derivation(Dsender, Asub[maj][min], r)) plant = 0; /* 8*r*A_sub */
    } else {
      ge_scalarmult_base(&t, r);            /* standard send: R = r*G */
      ge_p3_tobytes(R, &t);
      if (plant && !gen_derivation(Dsender, A, r)) plant = 0;     /* 8*r*A */
    }

    uint32_t height = (uint32_t)x;
    unsigned char hdr[5]; memcpy(hdr, &height, 4); hdr[4] = (unsigned char)n_out;
    fwrite(hdr, 1, 5, f); fwrite(R, 1, 32, f);

    for (unsigned i = 0; i < n_out; i++) {
      unsigned char rec[34];
      if (plant && i == plant_idx) {
        if (!derive_public_key(rec, Dsender, i, Bsub[maj][min])) {
          fprintf(stderr, "plant fail\n"); return 1;
        }
        rec[33] = derive_view_tag(Dsender, i);
        printf("PLANTED: height %u, output %u, subaddr %u/%u\n",
               height, i, maj, min);
        planted++;
      } else {
        for (int k = 0; k < 32; k += 8) { uint64_t v = splitmix(); memcpy(rec + k, &v, 8); }
        rec[33] = (unsigned char)(splitmix() & 0xFF);
      }
      rec[32] = 1;
      fwrite(rec, 1, 34, f);
    }
  }
  fclose(f);
  fprintf(stderr, "wrote %ld txs, planted %ld subaddress outputs\n", n_tx, planted);
  return 0;
}
