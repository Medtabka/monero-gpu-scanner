/*
 * subaddr_table.c — precompute Monero subaddress spend keys for scanning.
 *
 * For each (major, minor) in [0,maj_n) x [0,min_n):
 *   (0,0): entry = B (the base spend key)
 *   else : m = H_s("SubAddr\0" || a || major_le32 || minor_le32)
 *          entry = B + m*G
 * Output file "XMRSUBT1": magic[8] | u32 count | count * (key32 maj32 min32),
 * sorted bytewise by key (for binary search in the scanners).
 *
 * Usage: ./subaddr_table <view_priv_hex> <spend_pub_hex> <maj_n> <min_n> <out.bin>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

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

typedef struct { unsigned char key[32]; uint32_t maj, min; } entry;

static int cmp_entry(const void *x, const void *y) {
  return memcmp(((const entry *)x)->key, ((const entry *)y)->key, 32);
}

int main(int argc, char **argv) {
  if (argc != 6) {
    fprintf(stderr, "usage: %s <view_priv> <spend_pub> <maj_n> <min_n> <out.bin>\n",
            argv[0]);
    return 1;
  }
  unsigned char a[32], B[32];
  if (strlen(argv[1]) != 64 || !hex2bin(a, argv[1], 32) ||
      strlen(argv[2]) != 64 || !hex2bin(B, argv[2], 32)) {
    fprintf(stderr, "keys must be 64 hex chars\n"); return 1;
  }
  uint32_t maj_n = (uint32_t)atoi(argv[3]), min_n = (uint32_t)atoi(argv[4]);
  uint64_t count = (uint64_t)maj_n * min_n;
  if (!count || count > (1u << 24)) { fprintf(stderr, "bad table size\n"); return 1; }

  ge_p3 Bp3;
  if (ge_frombytes_vartime(&Bp3, B) != 0) {
    fprintf(stderr, "spend_pub not a valid point\n"); return 1;
  }
  ge_cached Bc;
  ge_p3_to_cached(&Bc, &Bp3);

  entry *tab = (entry *)malloc(count * sizeof(entry));
  uint64_t n = 0;
  for (uint32_t maj = 0; maj < maj_n; maj++) {
    for (uint32_t min = 0; min < min_n; min++) {
      if (maj == 0 && min == 0) {
        memcpy(tab[n].key, B, 32);
      } else {
        /* m = H_s("SubAddr\0" || a || maj || min); 8-byte prefix incl. NUL */
        unsigned char buf[8 + 32 + 4 + 4], m[32];
        memcpy(buf, "SubAddr\0", 8);
        memcpy(buf + 8, a, 32);
        memcpy(buf + 40, &maj, 4);
        memcpy(buf + 44, &min, 4);
        keccak(buf, 48, m, 32);
        sc_reduce32(m);
        ge_p3 mG, sum;
        ge_p1p1 t;
        ge_scalarmult_base(&mG, m);
        ge_add(&t, &mG, &Bc);
        ge_p1p1_to_p3(&sum, &t);
        ge_p3_tobytes(tab[n].key, &sum);
      }
      tab[n].maj = maj; tab[n].min = min;
      n++;
    }
  }
  qsort(tab, n, sizeof(entry), cmp_entry);

  FILE *f = fopen(argv[5], "wb");
  if (!f) { perror("open"); return 1; }
  fwrite("XMRSUBT1", 1, 8, f);
  uint32_t cnt32 = (uint32_t)n;
  fwrite(&cnt32, 4, 1, f);
  for (uint64_t i = 0; i < n; i++) {
    fwrite(tab[i].key, 32, 1, f);
    fwrite(&tab[i].maj, 4, 1, f);
    fwrite(&tab[i].min, 4, 1, f);
  }
  fclose(f);
  printf("wrote %u subaddress entries (%ux%u)\n", cnt32, maj_n, min_n);
  return 0;
}
