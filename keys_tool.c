/*
 * keys_tool.c — derive public keys and addresses from Monero private keys.
 *
 * Usage: ./keys_tool <spend_priv_hex64> <view_priv_hex64>
 * Prints: spend_pub, view_pub, mainnet address, stagenet address.
 *
 * Uses the same vendored ref10 + keccak as scan_cpu (math untouched).
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

static void print_hex(const char *label, const unsigned char *b, size_t n) {
  printf("%s", label);
  for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
  printf("\n");
}

/* Monero base58: 8-byte blocks -> 11 chars; last partial block per table */
static const char B58[] =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const int enc_sizes[9] = {0, 2, 3, 5, 6, 7, 9, 10, 11};

static void b58_block(const unsigned char *in, size_t len, char *out) {
  uint64_t num = 0;
  for (size_t i = 0; i < len; i++) num = (num << 8) | in[i];
  int outlen = enc_sizes[len];
  for (int i = outlen - 1; i >= 0; i--) { out[i] = B58[num % 58]; num /= 58; }
}

static void monero_b58(const unsigned char *data, size_t len, char *out) {
  size_t i = 0, o = 0;
  for (; i + 8 <= len; i += 8, o += 11) b58_block(data + i, 8, out + o);
  if (i < len) { b58_block(data + i, len - i, out + o); o += enc_sizes[len - i]; }
  out[o] = 0;
}

static void make_address(unsigned char prefix, const unsigned char B[32],
                         const unsigned char A[32], char *out) {
  unsigned char buf[1 + 32 + 32 + 4], h[32];
  buf[0] = prefix;                 /* 18 mainnet, 24 stagenet: 1-byte varint */
  memcpy(buf + 1, B, 32);
  memcpy(buf + 33, A, 32);
  keccak(buf, 65, h, 32);
  memcpy(buf + 65, h, 4);
  monero_b58(buf, 69, out);
}

int main(int argc, char **argv) {
  if (argc != 3) { fprintf(stderr, "usage: %s <spend_priv> <view_priv>\n", argv[0]); return 1; }
  unsigned char b[32], a[32], B[32], A[32];
  if (strlen(argv[1]) != 64 || !hex2bin(b, argv[1], 32) ||
      strlen(argv[2]) != 64 || !hex2bin(a, argv[2], 32)) {
    fprintf(stderr, "keys must be 64 hex chars\n"); return 1;
  }
  if (sc_check(b) != 0 || sc_check(a) != 0) {
    fprintf(stderr, "warning: key not a reduced scalar\n");
  }
  ge_p3 t;
  ge_scalarmult_base(&t, b); ge_p3_tobytes(B, &t);
  ge_scalarmult_base(&t, a); ge_p3_tobytes(A, &t);
  print_hex("spend_pub: ", B, 32);
  print_hex("view_pub:  ", A, 32);
  char addr[128];
  make_address(18, B, A, addr); printf("mainnet:  %s\n", addr);
  make_address(24, B, A, addr); printf("stagenet: %s\n", addr);
  return 0;
}
