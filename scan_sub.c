/*
 * scan_sub.c — reference Monero output scanner WITH SUBADDRESS support.
 *
 * CPU ground truth for gpu_scan's scansub mode. scan_cpu.c is untouched;
 * this reuses the same vendored ref10 + keccak and the same derivation,
 * but instead of comparing P' = H_s(D||i)*G + B against the output key,
 * it recovers the candidate spend key
 *     C = out_key - H_s(D||i)*G
 * and looks C up in a precomputed subaddress table (subaddr_table.c).
 * For table = {B} this is mathematically the same test as scan_cpu.
 *
 * Usage: ./scan_sub scan <file.bin> <view_priv_hex> <table.bin>
 * Prints: OWNED: height H, output I, subaddr MAJ/MIN
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#define select crypto_ops_ge_select
#include "crypto-ops.c"
#undef select
#include "keccak.h"

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
  unsigned char buf[32 + 10];
  memcpy(buf, D, 32);
  size_t n = 32 + write_varint(buf + 32, idx);
  keccak(buf, n, s, 32);
  sc_reduce32(s);
}

static unsigned char derive_view_tag(const unsigned char D[32], uint64_t idx) {
  unsigned char buf[8 + 32 + 10], h[32];
  memcpy(buf, "view_tag", 8);
  memcpy(buf + 8, D, 32);
  size_t n = 8 + 32 + write_varint(buf + 40, idx);
  keccak(buf, n, h, 32);
  return h[0];
}

/* C = out_key - H_s(D||i)*G; 0 if out_key is not a valid point */
static int derive_subaddress_candidate(unsigned char C[32],
                                       const unsigned char D[32], uint64_t idx,
                                       const unsigned char out_key[32]) {
  unsigned char s[32];
  ge_p3 K, sG, diff;
  ge_cached sGc;
  ge_p1p1 t;
  if (ge_frombytes_vartime(&K, out_key) != 0) return 0;
  derivation_to_scalar(s, D, idx);
  ge_scalarmult_base(&sG, s);
  ge_p3_to_cached(&sGc, &sG);
  ge_sub(&t, &K, &sGc);
  ge_p1p1_to_p3(&diff, &t);
  ge_p3_tobytes(C, &diff);
  return 1;
}

/* ---------- subaddress table ---------- */

typedef struct { unsigned char *keys; uint32_t *maj, *min; uint32_t n; } subtab;

static int load_table(const char *path, subtab *t) {
  FILE *f = fopen(path, "rb");
  if (!f) { perror("table"); return 0; }
  unsigned char magic[8];
  uint32_t n;
  if (fread(magic, 1, 8, f) != 8 || memcmp(magic, "XMRSUBT1", 8) ||
      fread(&n, 4, 1, f) != 1) { fprintf(stderr, "bad table\n"); return 0; }
  t->n = n;
  t->keys = malloc(32ull * n);
  t->maj = malloc(4ull * n);
  t->min = malloc(4ull * n);
  for (uint32_t i = 0; i < n; i++) {
    if (fread(t->keys + 32ull * i, 32, 1, f) != 1 ||
        fread(&t->maj[i], 4, 1, f) != 1 ||
        fread(&t->min[i], 4, 1, f) != 1) { fprintf(stderr, "bad table\n"); return 0; }
  }
  fclose(f);
  return 1;
}

static int table_lookup(const subtab *t, const unsigned char C[32]) {
  uint32_t lo = 0, hi = t->n;
  while (lo < hi) {
    uint32_t mid = lo + (hi - lo) / 2;
    int c = memcmp(C, t->keys + 32ull * mid, 32);
    if (c == 0) return (int)mid;
    if (c < 0) hi = mid; else lo = mid + 1;
  }
  return -1;
}

/* ---------- scan ---------- */

int main(int argc, char **argv) {
  if (argc != 5 || strcmp(argv[1], "scan")) {
    fprintf(stderr, "usage: %s scan <file.bin> <view_priv_hex> <table.bin>\n",
            argv[0]);
    return 1;
  }
  unsigned char a[32];
  if (strlen(argv[3]) != 64 || !hex2bin(a, argv[3], 32)) {
    fprintf(stderr, "view key must be 64 hex chars\n"); return 1;
  }
  subtab tab;
  if (!load_table(argv[4], &tab)) return 1;

  FILE *f = fopen(argv[2], "rb");
  if (!f) { perror("open"); return 1; }
  unsigned char magic[8];
  int ver = 0;
  if (fread(magic, 1, 8, f) != 8) { fprintf(stderr, "bad magic\n"); return 1; }
  if (!memcmp(magic, "XMRSCAN1", 8)) ver = 1;
  else if (!memcmp(magic, "XMRSCAN2", 8)) ver = 2;
  else { fprintf(stderr, "bad magic\n"); return 1; }

  uint64_t checked = 0, vt_skipped = 0, found = 0;
  double t0 = (double)clock() / CLOCKS_PER_SEC;
  for (;;) {
    unsigned char hdr[5];
    if (fread(hdr, 1, 5, f) != 5) break;
    uint32_t height; memcpy(&height, hdr, 4);
    unsigned n_out = hdr[4];
    unsigned char flags = 0;
    if (ver == 2 && fread(&flags, 1, 1, f) != 1) { fprintf(stderr, "truncated\n"); return 1; }
    unsigned char R[32];
    if (fread(R, 1, 32, f) != 32) { fprintf(stderr, "truncated\n"); return 1; }
    int has_add = (flags & 1);
    unsigned char radd[255][32];   /* additional tx pubkeys (tag 0x04), one per output */
    if (has_add && fread(radd, 32, n_out, f) != n_out) {
      fprintf(stderr, "truncated\n"); return 1;
    }

    unsigned char D[32];
    int okD = gen_derivation(D, R, a);   /* derivation from the main tx pubkey */

    for (unsigned i = 0; i < n_out; i++) {
      unsigned char rec[34];
      if (fread(rec, 1, 34, f) != 34) { fprintf(stderr, "truncated\n"); return 1; }
      int vtf = rec[32];
      unsigned char vt = rec[33];
      unsigned char C[32];
      int hit = -1;

      /* (1) try the main tx pubkey — change/standard outputs use this */
      if (okD && (!vtf || derive_view_tag(D, i) == vt) &&
          derive_subaddress_candidate(C, D, i, rec))
        hit = table_lookup(&tab, C);

      /* (2) else try this output's own additional tx pubkey (tag 0x04) —
       * how a tx paying multiple distinct subaddresses is scanned */
      if (hit < 0 && has_add) {
        unsigned char Da[32];
        if (gen_derivation(Da, radd[i], a) &&
            (!vtf || derive_view_tag(Da, i) == vt) &&
            derive_subaddress_candidate(C, Da, i, rec))
          hit = table_lookup(&tab, C);
      }

      if (okD || has_add) checked++;
      if (hit >= 0) {
        found++;
        printf("OWNED: height %u, output %u, subaddr %u/%u\n",
               height, i, tab.maj[hit], tab.min[hit]);
      } else if (vtf) {
        vt_skipped++;
      }
    }
  }
  double dt = (double)clock() / CLOCKS_PER_SEC - t0;
  fclose(f);
  printf("outputs checked: %llu, view-tag skipped: %llu, owned: %llu, "
         "%.2fs (%.0f outputs/s)\n",
         (unsigned long long)checked, (unsigned long long)vt_skipped,
         (unsigned long long)found, dt, checked / (dt > 0 ? dt : 1));
  return 0;
}
