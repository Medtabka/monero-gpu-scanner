/*
 * gpu_scan.cu — CUDA Monero output scanner (primary address, multi-wallet).
 *
 * Same scan as scan_cpu.c, same XMRSCAN1 file format, same output format.
 * The curve math IS Monero's vendored ref10: device_crypto.inc is generated
 * by gen_device_crypto.py from the unmodified crypto-ops.c/-data.c with
 * `__device__` prefixes only — so GPU results must be bit-identical to the
 * CPU reference by construction.
 *
 * Keccak runs on the GPU: the view-tag check needs one keccak per output
 * *before* we know whether it's interesting, so hashing host-side would
 * force a full D round-trip per output and serialize the hot path. The
 * device keccak handles only single-block inputs (<=135 bytes; ours are
 * <=50) and is gated by the CPU-equality test like everything else.
 *
 * Pipeline per chunk of the file, for W wallets at once (chain data is
 * uploaded once and shared; each extra wallet costs 64 key bytes):
 *   k_derive: 1 thread/(tx,wallet)     D_w = 8*(a_w*R)
 *   k_check:  1 thread/(output,wallet) view-tag filter, then
 *                                      P' = H_s(D_w||i)*G + B_w == out key?
 *
 * Usage:
 *   ./gpu_scan scan <file.bin> <view_priv_hex64> <spend_pub_hex64>
 *   ./gpu_scan scanmulti <file.bin> <wallets.txt>
 *       wallets.txt lines: <view_priv_hex64> <spend_pub_hex64> [label]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <cuda_runtime.h>

#define NDEBUG
#include "device_crypto.inc"

#define CUDA_CHECK(x) do { cudaError_t e_ = (x); if (e_ != cudaSuccess) { \
  fprintf(stderr, "CUDA error %s:%d: %s\n", __FILE__, __LINE__, \
          cudaGetErrorString(e_)); exit(1); } } while (0)

#define MAXW 256                 /* wallets per scan (constant-mem budget) */

/* ---------- device-side monero primitives (mirror scan_cpu.c) ---------- */

__constant__ unsigned char c_view_priv[MAXW * 32];
__constant__ unsigned char c_spend_pub[MAXW * 32];
__device__ ge_cached d_Bc[MAXW];     /* spend pubs as cached points */
__device__ int d_okB[MAXW];

/* single-block keccak-256 (inlen <= 135); matches keccak.c for short input */
__device__ static void d_keccak32(const unsigned char *in, int inlen,
                                  unsigned char md[32]) {
  uint64_t st[25];
  unsigned char temp[136];
  for (int i = 0; i < 25; i++) st[i] = 0;
  for (int i = 0; i < inlen; i++) temp[i] = in[i];
  temp[inlen] = 1;
  for (int i = inlen + 1; i < 136; i++) temp[i] = 0;
  temp[135] |= 0x80;
  for (int i = 0; i < 17; i++) {
    uint64_t w = 0;
    for (int j = 0; j < 8; j++) w |= (uint64_t)temp[i * 8 + j] << (8 * j);
    st[i] ^= w;
  }
  keccakf(st, KECCAK_ROUNDS);
  for (int i = 0; i < 4; i++)
    for (int j = 0; j < 8; j++)
      md[i * 8 + j] = (unsigned char)(st[i] >> (8 * j));
}

__device__ static size_t d_write_varint(unsigned char *buf, uint64_t v) {
  size_t n = 0;
  while (v >= 0x80) { buf[n++] = (unsigned char)(v) | 0x80; v >>= 7; }
  buf[n++] = (unsigned char)v;
  return n;
}

__device__ static int d_gen_derivation(unsigned char D[32],
                                       const unsigned char R[32],
                                       const unsigned char a[32]) {
  ge_p3 point; ge_p2 point2; ge_p1p1 point3;
  if (ge_frombytes_vartime(&point, R) != 0) return 0;
  ge_scalarmult(&point2, a, &point);
  ge_mul8(&point3, &point2);
  ge_p1p1_to_p2(&point2, &point3);
  ge_tobytes(D, &point2);
  return 1;
}

__device__ static void d_derivation_to_scalar(unsigned char s[32],
                                              const unsigned char D[32],
                                              uint64_t idx) {
  unsigned char buf[32 + 10];
  for (int i = 0; i < 32; i++) buf[i] = D[i];
  size_t n = 32 + d_write_varint(buf + 32, idx);
  d_keccak32(buf, (int)n, s);
  sc_reduce32(s);
}

__device__ static unsigned char d_derive_view_tag(const unsigned char D[32],
                                                  uint64_t idx) {
  unsigned char buf[8 + 32 + 10], h[32];
  const char *tag = "view_tag";
  for (int i = 0; i < 8; i++) buf[i] = (unsigned char)tag[i];
  for (int i = 0; i < 32; i++) buf[8 + i] = D[i];
  size_t n = 8 + 32 + d_write_varint(buf + 40, idx);
  d_keccak32(buf, (int)n, h);
  return h[0];
}

/* P' = H_s(D||i)*G + B_w, with B_w pre-cached in d_Bc[w] */
__device__ static void d_derive_public_key(unsigned char P[32],
                                           const unsigned char D[32],
                                           uint64_t idx, int w) {
  unsigned char s[32];
  ge_p3 sG, sum;
  ge_p1p1 t;
  d_derivation_to_scalar(s, D, idx);
  ge_scalarmult_base(&sG, s);
  ge_add(&t, &sG, &d_Bc[w]);
  ge_p1p1_to_p3(&sum, &t);
  ge_p3_tobytes(P, &sum);
}

/* C = out_key - H_s(D||i)*G; 0 if out_key is not a valid point.
 * Mirrors scan_sub.c derive_subaddress_candidate. */
__device__ static int d_derive_sub_candidate(unsigned char C[32],
                                             const unsigned char D[32],
                                             uint64_t idx,
                                             const unsigned char out_key[32]) {
  unsigned char s[32];
  ge_p3 K, sG, diff;
  ge_cached sGc;
  ge_p1p1 t;
  if (ge_frombytes_vartime(&K, out_key) != 0) return 0;
  d_derivation_to_scalar(s, D, idx);
  ge_scalarmult_base(&sG, s);
  ge_p3_to_cached(&sGc, &sG);
  ge_sub(&t, &K, &sGc);
  ge_p1p1_to_p3(&diff, &t);
  ge_p3_tobytes(C, &diff);
  return 1;
}

/* bytewise binary search, same ordering as scan_sub.c's memcmp */
__device__ static int d_table_lookup(const unsigned char *keys, unsigned n,
                                     const unsigned char C[32]) {
  unsigned lo = 0, hi = n;
  while (lo < hi) {
    unsigned mid = lo + (hi - lo) / 2;
    const unsigned char *k = keys + 32ull * mid;
    int c = 0;
    for (int i = 0; i < 32 && c == 0; i++)
      c = (int)C[i] - (int)k[i];
    if (c == 0) return (int)mid;
    if (c < 0) hi = mid; else lo = mid + 1;
  }
  return -1;
}

/* ---------- kernels ---------- */

__global__ void k_prep(int n_wallets) {
  int w = blockIdx.x * blockDim.x + threadIdx.x;
  if (w >= n_wallets) return;
  ge_p3 B;
  d_okB[w] = (ge_frombytes_vartime(&B, c_spend_pub + 32 * w) == 0);
  if (d_okB[w]) ge_p3_to_cached(&d_Bc[w], &B);
}

/* D layout: [w][tx] — thread tid = w*n_tx + t for coalesced R reads */
__global__ void k_derive(int n_tx, int n_wallets, const unsigned char *R,
                         unsigned char *D, unsigned char *okD) {
  long long tid = (long long)blockIdx.x * blockDim.x + threadIdx.x;
  if (tid >= (long long)n_tx * n_wallets) return;
  int w = (int)(tid / n_tx), t = (int)(tid % n_tx);
  int ok = d_gen_derivation(D + 32ll * tid, R + 32ll * t,
                            c_view_priv + 32 * w);
  if (w == 0) okD[t] = (unsigned char)ok;   /* R validity is wallet-independent */
}

__global__ void k_check(int n_out, int n_tx, int n_wallets,
                        const uint32_t *out_tx,    /* tx index per output  */
                        const unsigned char *out_idx, /* index within tx   */
                        const unsigned char *keys, /* 32B per output       */
                        const unsigned char *vtf, const unsigned char *vt,
                        const unsigned char *D, const unsigned char *okD,
                        uint64_t *hits, unsigned *n_hits, unsigned hit_cap,
                        unsigned long long *checked,
                        unsigned long long *vt_skipped,
                        unsigned long long *found) {
  __shared__ unsigned s_checked, s_skip, s_found;
  if (threadIdx.x == 0) { s_checked = 0; s_skip = 0; s_found = 0; }
  __syncthreads();

  long long tid = (long long)blockIdx.x * blockDim.x + threadIdx.x;
  if (tid < (long long)n_out * n_wallets) {
    int w = (int)(tid / n_out), g = (int)(tid % n_out);
    uint32_t tx = out_tx[g];
    if (okD[tx]) {
      atomicAdd(&s_checked, 1u);
      const unsigned char *Dt = D + 32ll * ((long long)w * n_tx + tx);
      unsigned i = out_idx[g];
      int pass = 1;
      if (vtf[g]) {
        if (d_derive_view_tag(Dt, i) != vt[g]) { atomicAdd(&s_skip, 1u); pass = 0; }
      }
      if (pass && d_okB[w]) {
        unsigned char P[32];
        d_derive_public_key(P, Dt, i, w);
        const unsigned char *key = keys + 32ll * g;
        int eq = 1;
        for (int k = 0; k < 32; k++) eq &= (P[k] == key[k]);
        if (eq) {
          atomicAdd(&s_found, 1u);
          unsigned slot = atomicAdd(n_hits, 1u);
          if (slot < hit_cap)
            hits[slot] = ((uint64_t)w << 32) | (uint32_t)g;
        }
      }
    }
  }
  __syncthreads();
  if (threadIdx.x == 0) {
    if (s_checked) atomicAdd(checked, (unsigned long long)s_checked);
    if (s_skip)    atomicAdd(vt_skipped, (unsigned long long)s_skip);
    if (s_found)   atomicAdd(found, (unsigned long long)s_found);
  }
}

/* subaddress scan: single wallet, candidate = out_key - H_s(D||i)*G,
 * binary-search the precomputed subaddress table. Hit payload = table idx. */
__global__ void k_check_sub(int n_out,
                            const uint32_t *out_tx,
                            const unsigned char *out_idx,
                            const unsigned char *keys,
                            const unsigned char *vtf, const unsigned char *vt,
                            const unsigned char *D, const unsigned char *okD,
                            const unsigned char *radd, const unsigned char *hasadd,
                            const unsigned char *sub_keys, unsigned sub_n,
                            uint64_t *hits, unsigned *n_hits, unsigned hit_cap,
                            unsigned long long *checked,
                            unsigned long long *vt_skipped,
                            unsigned long long *found) {
  __shared__ unsigned s_checked, s_skip, s_found;
  if (threadIdx.x == 0) { s_checked = 0; s_skip = 0; s_found = 0; }
  __syncthreads();

  int g = blockIdx.x * blockDim.x + threadIdx.x;
  if (g < n_out) {
    uint32_t tx = out_tx[g];
    unsigned i = out_idx[g];
    const unsigned char *key = keys + 32ll * g;
    int vtf_g = vtf[g];
    unsigned char vt_g = vt[g];
    int hit = -1;

    /* (1) main tx pubkey derivation (precomputed per tx in k_derive) */
    if (okD[tx]) {
      atomicAdd(&s_checked, 1u);
      const unsigned char *Dt = D + 32ll * tx;
      if (!vtf_g || d_derive_view_tag(Dt, i) == vt_g) {
        unsigned char C[32];
        if (d_derive_sub_candidate(C, Dt, i, key))
          hit = d_table_lookup(sub_keys, sub_n, C);
      }
    }

    /* (2) else this output's own additional tx pubkey (extra tag 0x04) */
    if (hit < 0 && hasadd[g]) {
      unsigned char Da[32];
      if (d_gen_derivation(Da, radd + 32ll * g, c_view_priv) &&
          (!vtf_g || d_derive_view_tag(Da, i) == vt_g)) {
        unsigned char C[32];
        if (d_derive_sub_candidate(C, Da, i, key))
          hit = d_table_lookup(sub_keys, sub_n, C);
      }
    }

    if (hit >= 0) {
      atomicAdd(&s_found, 1u);
      unsigned slot = atomicAdd(n_hits, 1u);
      if (slot < hit_cap)
        hits[slot] = ((uint64_t)hit << 32) | (uint32_t)g;
    } else if (vtf_g) {
      atomicAdd(&s_skip, 1u);
    }
  }
  __syncthreads();
  if (threadIdx.x == 0) {
    if (s_checked) atomicAdd(checked, (unsigned long long)s_checked);
    if (s_skip)    atomicAdd(vt_skipped, (unsigned long long)s_skip);
    if (s_found)   atomicAdd(found, (unsigned long long)s_found);
  }
}

/* ---------- host ---------- */

static int hex2bin(unsigned char *out, const char *hex, size_t n) {
  for (size_t i = 0; i < n; i++) {
    unsigned v;
    if (sscanf(hex + 2 * i, "%2x", &v) != 1) return 0;
    out[i] = (unsigned char)v;
  }
  return 1;
}

static double now_s(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec + ts.tv_nsec * 1e-9;
}

#define HIT_CAP (1u << 20)
#define D_BYTES_BUDGET (3ull << 30)   /* VRAM budget for the D buffer */

typedef struct {
  unsigned char *R;
  uint32_t *out_tx;
  unsigned char *out_idx, *keys, *vtf, *vt;
  unsigned n_tx, n_out;
  unsigned tx_cap, out_cap;
  int n_wallets;
  unsigned char *dR, *dD, *dokD, *d_out_idx, *d_keys, *d_vtf, *d_vt;
  uint32_t *d_out_tx;
  uint64_t *d_hits;
  unsigned *d_nhits;
  unsigned long long *d_counters;  /* checked, vt_skipped, found */
  /* subaddress mode */
  int sub_mode;
  unsigned char *d_sub_keys;
  uint32_t sub_n, *sub_maj, *sub_min;     /* maj/min stay host-side */
  unsigned char *radd, *hasadd;           /* host: per-output additional pubkey + flag */
  unsigned char *d_radd, *d_hasadd;       /* device copies (sub mode) */
} ctx_t;

static uint32_t *g_heights;       /* per output (whole file), for printing */
static uint8_t *g_idx;
static uint64_t g_out_base;
static uint64_t *g_hits;          /* (wallet<<40) | global output position */
static size_t g_nhits, g_hits_cap;
static double t_h2d, t_kernel, t_d2h;
static float t_derive_ms, t_check_ms;     /* per-kernel (cudaEvent) */

#ifndef BLOCK
#define BLOCK 128
#endif

static void flush_chunk(ctx_t *c) {
  if (c->n_tx == 0) return;
  double t0 = now_s();
  CUDA_CHECK(cudaMemcpy(c->dR, c->R, 32ull * c->n_tx, cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemcpy(c->d_out_tx, c->out_tx, 4ull * c->n_out, cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemcpy(c->d_out_idx, c->out_idx, c->n_out, cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemcpy(c->d_keys, c->keys, 32ull * c->n_out, cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemcpy(c->d_vtf, c->vtf, c->n_out, cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemcpy(c->d_vt, c->vt, c->n_out, cudaMemcpyHostToDevice));
  if (c->sub_mode) {
    CUDA_CHECK(cudaMemcpy(c->d_radd, c->radd, 32ull * c->n_out, cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(c->d_hasadd, c->hasadd, c->n_out, cudaMemcpyHostToDevice));
  }
  CUDA_CHECK(cudaMemset(c->d_nhits, 0, 4));
  double t1 = now_s(); t_h2d += t1 - t0;

  int B = BLOCK;
  long long ndrv = (long long)c->n_tx * c->n_wallets;
  long long nchk = (long long)c->n_out * c->n_wallets;
  cudaEvent_t ev0, ev1, ev2;
  cudaEventCreate(&ev0); cudaEventCreate(&ev1); cudaEventCreate(&ev2);
  cudaEventRecord(ev0);
  k_derive<<<(unsigned)((ndrv + B - 1) / B), B>>>(c->n_tx, c->n_wallets,
                                                  c->dR, c->dD, c->dokD);
  cudaEventRecord(ev1);
  if (c->sub_mode)
    k_check_sub<<<(unsigned)((nchk + B - 1) / B), B>>>(c->n_out,
        c->d_out_tx, c->d_out_idx,
        c->d_keys, c->d_vtf, c->d_vt, c->dD, c->dokD,
        c->d_radd, c->d_hasadd, c->d_sub_keys, c->sub_n,
        c->d_hits, c->d_nhits, HIT_CAP,
        c->d_counters, c->d_counters + 1, c->d_counters + 2);
  else
    k_check<<<(unsigned)((nchk + B - 1) / B), B>>>(c->n_out, c->n_tx,
        c->n_wallets, c->d_out_tx, c->d_out_idx,
        c->d_keys, c->d_vtf, c->d_vt, c->dD, c->dokD,
        c->d_hits, c->d_nhits, HIT_CAP,
        c->d_counters, c->d_counters + 1, c->d_counters + 2);
  cudaEventRecord(ev2);
  CUDA_CHECK(cudaGetLastError());
  CUDA_CHECK(cudaDeviceSynchronize());
  double t2 = now_s(); t_kernel += t2 - t1;
  float ms;
  cudaEventElapsedTime(&ms, ev0, ev1); t_derive_ms += ms;
  cudaEventElapsedTime(&ms, ev1, ev2); t_check_ms += ms;
  cudaEventDestroy(ev0); cudaEventDestroy(ev1); cudaEventDestroy(ev2);

  unsigned nh = 0;
  CUDA_CHECK(cudaMemcpy(&nh, c->d_nhits, 4, cudaMemcpyDeviceToHost));
  if (nh > HIT_CAP) nh = HIT_CAP;
  if (nh) {
    uint64_t *tmp = (uint64_t *)malloc(8ull * nh);
    CUDA_CHECK(cudaMemcpy(tmp, c->d_hits, 8ull * nh, cudaMemcpyDeviceToHost));
    for (unsigned i = 0; i < nh; i++) {
      if (g_nhits == g_hits_cap) {
        g_hits_cap = g_hits_cap ? g_hits_cap * 2 : 1024;
        g_hits = (uint64_t *)realloc(g_hits, 8 * g_hits_cap);
      }
      uint64_t hi = tmp[i] >> 32, o = (uint32_t)tmp[i];
      /* sub mode: file-order sort key (out<<24)|table_idx;
       * wallet mode: wallet-major key (w<<40)|out */
      g_hits[g_nhits++] = c->sub_mode ? (((g_out_base + o) << 24) | hi)
                                      : ((hi << 40) | (g_out_base + o));
    }
    free(tmp);
  }
  t_d2h += now_s() - t2;

  g_out_base += c->n_out;
  c->n_tx = c->n_out = 0;
}

static int cmp_u64(const void *a, const void *b) {
  uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
  return x < y ? -1 : x > y ? 1 : 0;
}

int main(int argc, char **argv) {
  unsigned char wal_a[MAXW][32], wal_B[MAXW][32];
  char labels[MAXW][64];
  int W = 0, sub_mode = 0;
  unsigned char *sub_keys = NULL;
  uint32_t sub_n = 0, *sub_maj = NULL, *sub_min = NULL;

  if (argc == 5 && !strcmp(argv[1], "scansub")) {
    if (strlen(argv[3]) != 64 || !hex2bin(wal_a[0], argv[3], 32)) {
      fprintf(stderr, "view key must be 64 hex chars\n"); return 1;
    }
    FILE *tf = fopen(argv[4], "rb");
    if (!tf) { perror("table"); return 1; }
    unsigned char tmagic[8];
    if (fread(tmagic, 1, 8, tf) != 8 || memcmp(tmagic, "XMRSUBT1", 8) ||
        fread(&sub_n, 4, 1, tf) != 1) { fprintf(stderr, "bad table\n"); return 1; }
    sub_keys = (unsigned char *)malloc(32ull * sub_n);
    sub_maj = (uint32_t *)malloc(4ull * sub_n);
    sub_min = (uint32_t *)malloc(4ull * sub_n);
    for (uint32_t i = 0; i < sub_n; i++) {
      if (fread(sub_keys + 32ull * i, 32, 1, tf) != 1 ||
          fread(&sub_maj[i], 4, 1, tf) != 1 ||
          fread(&sub_min[i], 4, 1, tf) != 1) { fprintf(stderr, "bad table\n"); return 1; }
    }
    fclose(tf);
    memset(wal_B[0], 0, 32);   /* unused in sub mode (table replaces B) */
    strcpy(labels[0], "wallet0");
    W = 1;
    sub_mode = 1;
  } else if (argc == 5 && !strcmp(argv[1], "scan")) {
    if (strlen(argv[3]) != 64 || !hex2bin(wal_a[0], argv[3], 32) ||
        strlen(argv[4]) != 64 || !hex2bin(wal_B[0], argv[4], 32)) {
      fprintf(stderr, "keys must be 64 hex chars\n"); return 1;
    }
    strcpy(labels[0], "wallet0");
    W = 1;
  } else if (argc == 4 && !strcmp(argv[1], "scanmulti")) {
    FILE *wf = fopen(argv[3], "r");
    if (!wf) { perror("wallets file"); return 1; }
    char la[80], lb[80], ll[64];
    while (W < MAXW) {
      int n = fscanf(wf, "%79s %79s", la, lb);
      if (n != 2) break;
      if (strlen(la) != 64 || !hex2bin(wal_a[W], la, 32) ||
          strlen(lb) != 64 || !hex2bin(wal_B[W], lb, 32)) {
        fprintf(stderr, "wallet %d: keys must be 64 hex chars\n", W); return 1;
      }
      ll[0] = 0;
      int ch;
      while ((ch = fgetc(wf)) == ' ' || ch == '\t') {}
      if (ch != '\n' && ch != EOF) {
        ungetc(ch, wf);
        if (!fgets(ll, sizeof ll, wf)) ll[0] = 0;
        ll[strcspn(ll, "\n")] = 0;
      }
      if (ll[0]) snprintf(labels[W], 64, "%s", ll);
      else snprintf(labels[W], 64, "wallet%d", W);
      W++;
    }
    fclose(wf);
    if (!W) { fprintf(stderr, "no wallets parsed\n"); return 1; }
  } else {
    fprintf(stderr,
      "usage:\n  %s scan <file.bin> <view_priv_hex> <spend_pub_hex>\n"
      "  %s scanmulti <file.bin> <wallets.txt>\n"
      "  %s scansub <file.bin> <view_priv_hex> <table.bin>\n",
      argv[0], argv[0], argv[0]);
    return 1;
  }

  double t_start = now_s();

  FILE *f = fopen(argv[2], "rb");
  if (!f) { perror("open"); return 1; }
  fseek(f, 0, SEEK_END);
  long fsize = ftell(f);
  fseek(f, 0, SEEK_SET);
  unsigned char *buf = (unsigned char *)malloc(fsize);
  if (fread(buf, 1, fsize, f) != (size_t)fsize) { fprintf(stderr, "read fail\n"); return 1; }
  fclose(f);
  int ver = 0;
  if (fsize >= 8 && !memcmp(buf, "XMRSCAN1", 8)) ver = 1;
  else if (fsize >= 8 && !memcmp(buf, "XMRSCAN2", 8)) ver = 2;
  else { fprintf(stderr, "bad magic\n"); return 1; }
  double t_read = now_s() - t_start;

  /* chunk capacities scale down with wallet count to fit the D buffer */
  ctx_t c = {0};
  c.n_wallets = W;
  c.sub_mode = sub_mode;
  c.sub_n = sub_n;
  c.sub_maj = sub_maj;
  c.sub_min = sub_min;
  unsigned tx_cap = (unsigned)(D_BYTES_BUDGET / (32ull * W));
  if (tx_cap > (1u << 21)) tx_cap = 1u << 21;
  c.tx_cap = tx_cap;
  c.out_cap = c.tx_cap * 4 > (1u << 23) ? (1u << 23) : c.tx_cap * 4;

  c.R = (unsigned char *)malloc(32ull * c.tx_cap);
  c.out_tx = (uint32_t *)malloc(4ull * c.out_cap);
  c.out_idx = (unsigned char *)malloc(c.out_cap);
  c.keys = (unsigned char *)malloc(32ull * c.out_cap);
  c.vtf = (unsigned char *)malloc(c.out_cap);
  c.vt = (unsigned char *)malloc(c.out_cap);
  CUDA_CHECK(cudaMalloc(&c.dR, 32ull * c.tx_cap));
  CUDA_CHECK(cudaMalloc(&c.dD, 32ull * c.tx_cap * W));
  CUDA_CHECK(cudaMalloc(&c.dokD, c.tx_cap));
  CUDA_CHECK(cudaMalloc(&c.d_out_tx, 4ull * c.out_cap));
  CUDA_CHECK(cudaMalloc(&c.d_out_idx, c.out_cap));
  CUDA_CHECK(cudaMalloc(&c.d_keys, 32ull * c.out_cap));
  CUDA_CHECK(cudaMalloc(&c.d_vtf, c.out_cap));
  CUDA_CHECK(cudaMalloc(&c.d_vt, c.out_cap));
  CUDA_CHECK(cudaMalloc(&c.d_hits, 8ull * HIT_CAP));
  CUDA_CHECK(cudaMalloc(&c.d_nhits, 4));
  if (sub_mode) {
    CUDA_CHECK(cudaMalloc(&c.d_sub_keys, 32ull * sub_n));
    CUDA_CHECK(cudaMemcpy(c.d_sub_keys, sub_keys, 32ull * sub_n,
                          cudaMemcpyHostToDevice));
    c.radd = (unsigned char *)malloc(32ull * c.out_cap);
    c.hasadd = (unsigned char *)malloc(c.out_cap);
    CUDA_CHECK(cudaMalloc(&c.d_radd, 32ull * c.out_cap));
    CUDA_CHECK(cudaMalloc(&c.d_hasadd, c.out_cap));
  }
  CUDA_CHECK(cudaMalloc(&c.d_counters, 3 * 8));
  CUDA_CHECK(cudaMemset(c.d_counters, 0, 3 * 8));
  CUDA_CHECK(cudaMemcpyToSymbol(c_view_priv, wal_a, 32ull * W));
  CUDA_CHECK(cudaMemcpyToSymbol(c_spend_pub, wal_B, 32ull * W));
  k_prep<<<(W + 31) / 32, 32>>>(W);
  CUDA_CHECK(cudaDeviceSynchronize());
  int okB[MAXW];
  CUDA_CHECK(cudaMemcpyFromSymbol(okB, d_okB, sizeof(int) * W));
  if (!sub_mode)
    for (int w = 0; w < W; w++)
      if (!okB[w]) fprintf(stderr, "warning: wallet %d spend_pub invalid\n", w);

  uint64_t total_out = 0;
  size_t heights_cap = 1 << 20;
  g_heights = (uint32_t *)malloc(4 * heights_cap);
  g_idx = (uint8_t *)malloc(heights_cap);

  size_t p = 8;
  while (p + 5 <= (size_t)fsize) {
    uint32_t height; memcpy(&height, buf + p, 4);
    unsigned n_out = buf[p + 4];
    size_t q = p + 5;
    unsigned char flags = 0;
    if (ver == 2) {
      if (q + 1 > (size_t)fsize) { fprintf(stderr, "truncated\n"); return 1; }
      flags = buf[q]; q += 1;
    }
    if (q + 32 > (size_t)fsize) { fprintf(stderr, "truncated\n"); return 1; }
    const unsigned char *R = buf + q; q += 32;
    int has_add = (flags & 1);
    const unsigned char *radd = NULL;
    if (has_add) {
      if (q + 32ull * n_out > (size_t)fsize) { fprintf(stderr, "truncated\n"); return 1; }
      radd = buf + q; q += 32ull * n_out;
    }
    size_t rec_end = q + 34ull * n_out;
    if (rec_end > (size_t)fsize) { fprintf(stderr, "truncated\n"); return 1; }

    if (c.n_tx + 1 > c.tx_cap || c.n_out + n_out > c.out_cap) flush_chunk(&c);

    uint32_t tx_local = c.n_tx;
    memcpy(c.R + 32ull * c.n_tx, R, 32);
    c.n_tx++;
    const unsigned char *rec = buf + q;
    for (unsigned i = 0; i < n_out; i++, rec += 34) {
      unsigned o = c.n_out;
      c.out_tx[o] = tx_local;
      c.out_idx[o] = (unsigned char)i;
      memcpy(c.keys + 32ull * o, rec, 32);
      c.vtf[o] = rec[32];
      c.vt[o] = rec[33];
      if (c.sub_mode) {
        if (has_add) { memcpy(c.radd + 32ull * o, radd + 32ull * i, 32); c.hasadd[o] = 1; }
        else c.hasadd[o] = 0;
      }
      c.n_out++;
      if (total_out == heights_cap) {
        heights_cap *= 2;
        g_heights = (uint32_t *)realloc(g_heights, 4 * heights_cap);
        g_idx = (uint8_t *)realloc(g_idx, heights_cap);
      }
      g_heights[total_out] = height;
      g_idx[total_out] = (uint8_t)i;
      total_out++;
    }
    p = rec_end;
  }
  flush_chunk(&c);
  free(buf);

  unsigned long long counters[3];
  CUDA_CHECK(cudaMemcpy(counters, c.d_counters, 3 * 8, cudaMemcpyDeviceToHost));

  /* print hits: wallet-major, then file order (single wallet => same lines
   * as scan_cpu) */
  qsort(g_hits, g_nhits, 8, cmp_u64);
  unsigned long long owned_per_w[MAXW] = {0};
  for (size_t i = 0; i < g_nhits; i++) {
    if (sub_mode) {
      uint64_t g = g_hits[i] >> 24, ti = g_hits[i] & 0xFFFFFF;
      printf("OWNED: height %u, output %u, subaddr %u/%u\n",
             g_heights[g], (unsigned)g_idx[g], sub_maj[ti], sub_min[ti]);
      continue;
    }
    uint64_t w = g_hits[i] >> 40, g = g_hits[i] & ((1ull << 40) - 1);
    owned_per_w[w]++;
    if (W == 1)
      printf("OWNED: height %u, output %u\n", g_heights[g], (unsigned)g_idx[g]);
    else
      printf("OWNED[%llu %s]: height %u, output %u\n",
             (unsigned long long)w, labels[w], g_heights[g], (unsigned)g_idx[g]);
  }

  double dt = now_s() - t_start;
  printf("outputs checked: %llu, view-tag skipped: %llu, owned: %llu, "
         "%.2fs (%.0f outputs/s)\n",
         counters[0], counters[1], counters[2], dt,
         counters[0] / (dt > 0 ? dt : 1));
  if (W > 1)
    for (int w = 0; w < W; w++)
      printf("wallet %d (%s): owned %llu\n", w, labels[w], owned_per_w[w]);
  printf("timing: read %.3fs, h2d %.3fs, kernels %.3fs (derive %.3fs, "
         "check %.3fs), d2h %.3fs, total %.3fs, outputs %llu, wallets %d, "
         "block %d\n",
         t_read, t_h2d, t_kernel, t_derive_ms / 1e3, t_check_ms / 1e3,
         t_d2h, dt, (unsigned long long)total_out, W, BLOCK);
  return 0;
}
