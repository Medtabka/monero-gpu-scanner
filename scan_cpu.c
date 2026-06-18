/*
 * scan_cpu.c — reference Monero output scanner (primary address).
 *
 * Purpose: ground truth for the GPU kernel. Implements the real ownership
 * math using Monero's own ref10 + keccak sources (unmodified):
 *
 *   D  = 8 * (view_priv * R)                    generate_key_derivation
 *   vt = keccak("view_tag" || D || varint(i))[0]    derive_view_tag
 *   s  = sc_reduce32(keccak(D || varint(i)))        derivation_to_scalar
 *   P' = s*G + spend_pub                            derive_public_key
 *   own output  <=>  P' == out_key  (and vt matches when present)
 *
 * Modes:
 *   ./scan_cpu selftest [seed]           plant outputs among decoys, verify
 *                                        found-set == planted-set exactly
 *   ./scan_cpu scan <file> <view_priv_hex> <spend_pub_hex>
 *                                        scan an XMRSCAN1 flat file
 *
 * Flat file format "XMRSCAN1":
 *   magic[8] then records:
 *   u32 height | u8 n_out | R[32] | n_out * ( key[32] | vt_flag u8 | vt u8 )
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define select crypto_ops_ge_select
#include "crypto-ops.c"
#undef select
#include "keccak.h"

/* ---------- monero primitives rebuilt on ref10 ---------- */

static int hex2bin(unsigned char *out, const char *hex, size_t n) {
  for (size_t i = 0; i < n; i++) {
    unsigned v;
    if (sscanf(hex + 2 * i, "%2x", &v) != 1) return 0;
    out[i] = (unsigned char)v;
  }
  return 1;
}

static size_t write_varint(unsigned char *buf, uint64_t v) {
  size_t n = 0;
  while (v >= 0x80) { buf[n++] = (unsigned char)(v) | 0x80; v >>= 7; }
  buf[n++] = (unsigned char)v;
  return n;
}

/* D = 8 * (a * R); returns 0 on bad point */
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

/* s = H_s(D || varint(i)) */
static void derivation_to_scalar(unsigned char s[32], const unsigned char D[32],
                                 uint64_t idx) {
  unsigned char buf[32 + 10];
  memcpy(buf, D, 32);
  size_t n = 32 + write_varint(buf + 32, idx);
  keccak(buf, n, s, 32);
  sc_reduce32(s);
}

/* vt = keccak("view_tag" || D || varint(i))[0] */
static unsigned char derive_view_tag(const unsigned char D[32], uint64_t idx) {
  unsigned char buf[8 + 32 + 10], h[32];
  memcpy(buf, "view_tag", 8);
  memcpy(buf + 8, D, 32);
  size_t n = 8 + 32 + write_varint(buf + 40, idx);
  keccak(buf, n, h, 32);
  return h[0];
}

/* P' = H_s(D||i)*G + spend_pub */
static int derive_public_key(unsigned char P[32], const unsigned char D[32],
                             uint64_t idx, const unsigned char spend_pub[32]) {
  unsigned char s[32];
  ge_p3 B, sG, sum;
  ge_cached Bc;
  ge_p1p1 t;
  if (ge_frombytes_vartime(&B, spend_pub) != 0) return 0;
  derivation_to_scalar(s, D, idx);
  ge_scalarmult_base(&sG, s);
  ge_p3_to_cached(&Bc, &B);
  ge_add(&t, &sG, &Bc);
  ge_p1p1_to_p3(&sum, &t);
  ge_p3_tobytes(P, &sum);
  return 1;
}

/* ---------- flat file scan ---------- */

typedef struct { uint64_t checked, vt_skipped, found; } stats;

static int scan_file(FILE *f, const unsigned char view_priv[32],
                     const unsigned char spend_pub[32], int verbose, stats *st,
                     /* optional capture of found (height,out_idx) pairs */
                     uint64_t *found_list, size_t found_cap, size_t *found_n) {
  unsigned char magic[8];
  if (fread(magic, 1, 8, f) != 8 || memcmp(magic, "XMRSCAN1", 8)) {
    fprintf(stderr, "bad magic\n"); return 0;
  }
  for (;;) {
    unsigned char hdr[5];
    if (fread(hdr, 1, 5, f) != 5) break;        /* EOF */
    uint32_t height; memcpy(&height, hdr, 4);
    unsigned n_out = hdr[4];
    unsigned char R[32];
    if (fread(R, 1, 32, f) != 32) { fprintf(stderr, "truncated\n"); return 0; }

    unsigned char D[32];
    int okD = gen_derivation(D, R, view_priv);

    for (unsigned i = 0; i < n_out; i++) {
      unsigned char rec[34];
      if (fread(rec, 1, 34, f) != 34) { fprintf(stderr, "truncated\n"); return 0; }
      if (!okD) continue;
      st->checked++;
      const unsigned char *key = rec;
      int vt_flag = rec[32];
      unsigned char vt = rec[33];
      if (vt_flag) {
        if (derive_view_tag(D, i) != vt) { st->vt_skipped++; continue; }
      }
      unsigned char P[32];
      if (!derive_public_key(P, D, i, spend_pub)) continue;
      if (memcmp(P, key, 32) == 0) {
        st->found++;
        if (found_list && *found_n < found_cap)
          found_list[(*found_n)++] = ((uint64_t)height << 16) | i;
        if (verbose)
          printf("OWNED: height %u, output %u\n", height, i);
      }
    }
  }
  return 1;
}

/* ---------- self test ---------- */

static uint64_t rng_state = 12345;
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

static int selftest(uint64_t seed) {
  rng_state = seed;
  /* wallet */
  unsigned char a[32], b[32], A[32], B[32];
  rand_scalar(a); rand_scalar(b);
  ge_p3 t;
  ge_scalarmult_base(&t, a); ge_p3_tobytes(A, &t);
  ge_scalarmult_base(&t, b); ge_p3_tobytes(B, &t);

  const int TXS = 2000;
  uint64_t planted[64]; size_t n_planted = 0;

  FILE *f = fopen("/tmp/selftest.bin", "wb");
  fwrite("XMRSCAN1", 1, 8, f);
  for (int x = 0; x < TXS; x++) {
    unsigned n_out = 2 + (unsigned)(splitmix() % 3);
    int plant = (splitmix() % 50 == 0) && n_planted < 64;  /* ~2% of txs */
    unsigned plant_idx = plant ? (unsigned)(splitmix() % n_out) : 0;

    unsigned char r[32], R[32];
    rand_scalar(r);
    ge_scalarmult_base(&t, r); ge_p3_tobytes(R, &t);

    unsigned char Dsender[32] = {0};
    if (plant && !gen_derivation(Dsender, A, r)) plant = 0; /* sender: 8*r*A */

    uint32_t height = (uint32_t)x;
    unsigned char hdr[5]; memcpy(hdr, &height, 4); hdr[4] = (unsigned char)n_out;
    fwrite(hdr, 1, 5, f); fwrite(R, 1, 32, f);

    for (unsigned i = 0; i < n_out; i++) {
      unsigned char key[32], rec[34];
      int vt_flag = (int)(splitmix() % 2);    /* mix pre/post view-tag eras */
      unsigned char vt = (unsigned char)(splitmix() & 0xFF);
      if (plant && i == plant_idx) {
        if (!derive_public_key(key, Dsender, i, B)) { fprintf(stderr, "plant fail\n"); return 1; }
        if (vt_flag) vt = derive_view_tag(Dsender, i);
        planted[n_planted++] = ((uint64_t)height << 16) | i;
      } else {
        unsigned char junk[32]; rand_scalar(junk);       /* random point */
        ge_scalarmult_base(&t, junk); ge_p3_tobytes(key, &t);
      }
      memcpy(rec, key, 32); rec[32] = (unsigned char)vt_flag; rec[33] = vt;
      fwrite(rec, 1, 34, f);
    }
  }
  fclose(f);

  f = fopen("/tmp/selftest.bin", "rb");
  stats st = {0};
  uint64_t found[64]; size_t n_found = 0;
  if (!scan_file(f, a, B, 0, &st, found, 64, &n_found)) return 1;
  fclose(f);

  int ok = (n_found == n_planted) && !memcmp(found, planted, n_found * 8);
  printf("seed %llu: planted=%zu found=%zu checked=%llu vt_skipped=%llu  %s\n",
         (unsigned long long)seed, n_planted, n_found,
         (unsigned long long)st.checked, (unsigned long long)st.vt_skipped,
         ok ? "PASS" : "** FAIL **");
  return ok ? 0 : 1;
}

int main(int argc, char **argv) {
  if (argc >= 2 && !strcmp(argv[1], "selftest")) {
    uint64_t seed = argc >= 3 ? strtoull(argv[2], 0, 10) : 1;
    return selftest(seed);
  }
  if (argc == 5 && !strcmp(argv[1], "scan")) {
    unsigned char a[32], B[32];
    if (strlen(argv[3]) != 64 || !hex2bin(a, argv[3], 32) ||
        strlen(argv[4]) != 64 || !hex2bin(B, argv[4], 32)) {
      fprintf(stderr, "keys must be 64 hex chars\n"); return 1;
    }
    FILE *f = fopen(argv[2], "rb");
    if (!f) { perror("open"); return 1; }
    stats st = {0};
    double t0 = (double)clock() / CLOCKS_PER_SEC;
    int ok = scan_file(f, a, B, 1, &st, 0, 0, 0);
    double dt = (double)clock() / CLOCKS_PER_SEC - t0;
    fclose(f);
    printf("outputs checked: %llu, view-tag skipped: %llu, owned: %llu, "
           "%.2fs (%.0f outputs/s)\n",
           (unsigned long long)st.checked, (unsigned long long)st.vt_skipped,
           (unsigned long long)st.found, dt, st.checked / (dt > 0 ? dt : 1));
    return ok ? 0 : 1;
  }
  fprintf(stderr,
    "usage:\n  %s selftest [seed]\n  %s scan <file.bin> <view_priv_hex> <spend_pub_hex>\n",
    argv[0], argv[0]);
  return 1;
}
