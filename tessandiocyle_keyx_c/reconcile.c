/**
 * TessanDioKey V18 — Tri-layer Reconciliation
 * Translated from Rust V18 reconcile.rs
 */
#include "tessandiocyle_keyx.h"
#include <string.h>

static uint8_t coarse_bucket(int16_t v)
{
    int32_t u = v;
    u += (u >> 31) & TD18_Q;
    int32_t scaled = (u * 8 * 2 + TD18_Q) / (2 * TD18_Q);
    int32_t bucket = (scaled * 8) / 9;
    if (bucket > 7) bucket = 7;
    return (uint8_t)bucket;
}

static uint8_t fine_sub(int16_t v, uint8_t coarse)
{
    int32_t u = v;
    u += (u >> 31) & TD18_Q;
    int32_t low  = (int32_t)coarse * TD18_Q / 8;
    int32_t high = ((int32_t)coarse + 1) * TD18_Q / 8;
    int32_t mid = (low + high) / 2;
    return (u >= mid) ? 1 : 0;
}

static uint8_t spectral_pair(const int16_t block[4])
{
    int32_t s0 = (int32_t)block[0] + block[1] - block[2] - block[3];
    int32_t s1 = (int32_t)block[0] + block[2] - block[1] - block[3];
    uint8_t b0 = (s0 >= 0) ? 1 : 0;
    uint8_t b1 = (s1 >= 0) ? 1 : 0;
    return (uint8_t)((b1 << 1) | b0);
}

void td18_reconcile_alice(uint8_t hints[TD18_RECON_BYTES], const int16_t v[TD18_N])
{
    memset(hints, 0, TD18_RECON_BYTES);
    const int cfb = 128;
    for (int i = 0; i < TD18_N; i++) {
        uint8_t c = coarse_bucket(v[i]);
        uint8_t f = fine_sub(v[i], c);
        uint8_t bits = (uint8_t)(((c & 7) << 1) | (f & 1));
        int bit_pos = i * 4;
        int byte_idx = bit_pos / 8;
        int bit_off  = bit_pos % 8;
        hints[byte_idx] |= bits << bit_off;
        if (bit_off + 4 > 8) hints[byte_idx + 1] |= bits >> (8 - bit_off);
    }
    for (int block_idx = 0; block_idx < 64; block_idx++) {
        int16_t block[4];
        for (int j = 0; j < 4; j++) block[j] = v[block_idx * 4 + j];
        uint8_t sp = spectral_pair(block);
        int bit_pos = block_idx * 2;
        int byte_idx = cfb + (bit_pos / 8);
        int bit_off  = bit_pos % 8;
        hints[byte_idx] |= sp << bit_off;
        if (bit_off + 2 > 8) hints[byte_idx + 1] |= sp >> (8 - bit_off);
    }
}

int td18_reconcile_verify(const int16_t va[TD18_N], const int16_t vb[TD18_N])
{
    const int32_t SPECTRAL_TOLERANCE = 64;
    for (int i = 0; i < TD18_N; i++) {
        uint8_t ca = coarse_bucket(va[i]);
        uint8_t cb = coarse_bucket(vb[i]);
        int diff = (int)ca - (int)cb;
        if (diff < 0) diff = -diff;
        if (diff > 1) return TD18_ERR_VERIFY;
    }
    for (int block_idx = 0; block_idx < 64; block_idx++) {
        int16_t a[4], b[4];
        for (int j = 0; j < 4; j++) { a[j] = va[block_idx * 4 + j]; b[j] = vb[block_idx * 4 + j]; }
        int32_t s0_a = (int32_t)a[0] + a[1] - a[2] - a[3];
        int32_t s0_b = (int32_t)b[0] + b[1] - b[2] - b[3];
        int32_t s1_a = (int32_t)a[0] + a[2] - a[1] - a[3];
        int32_t s1_b = (int32_t)b[0] + b[2] - b[1] - b[3];
        int32_t as0 = s0_a >= 0 ? s0_a : -s0_a;
        int32_t as0b = s0_b >= 0 ? s0_b : -s0_b;
        int32_t as1 = s1_a >= 0 ? s1_a : -s1_a;
        int32_t as1b = s1_b >= 0 ? s1_b : -s1_b;
        int s0_ok = ((s0_a >= 0 && s0_b >= 0) || (s0_a < 0 && s0_b < 0) || (as0 < SPECTRAL_TOLERANCE && as0b < SPECTRAL_TOLERANCE));
        int s1_ok = ((s1_a >= 0 && s1_b >= 0) || (s1_a < 0 && s1_b < 0) || (as1 < SPECTRAL_TOLERANCE && as1b < SPECTRAL_TOLERANCE));
        if (!s0_ok || !s1_ok) return TD18_ERR_VERIFY;
    }
    return TD18_OK;
}
