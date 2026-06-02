/**
 * TessanDioKey V18 — NTT with Feistel-shuffled butterflies
 * Translated from Rust V18 ntt.rs
 */
#include "tessandiocyle_keyx.h"
#include <string.h>

static uint64_t g_ntt_seed = 0x9E3779B97F4A7C15ULL;

static const int16_t ZETAS[128] = {
    -1044, -758, -359, -1517, 1493, 1422, 287, 202,
    -171, 622, 1577, 182, 962, -1202, -1474, 1468,
    573, -1325, 264, 383, -829, 1458, -1602, -130,
    -681, 1017, 732, 608, -1542, 411, -205, -1571,
    1223, 652, -552, 1015, -1293, 1491, -282, -1544,
    516, -8, -320, -666, -1618, -1162, 126, 1469,
    -853, -90, -271, 830, 107, -1421, -247, -951,
    -398, 961, -1508, -725, 448, -1065, 677, -1275,
    -1103, 430, 555, 843, -1251, 871, 1550, 105,
    422, 587, 177, -235, -291, -460, 1574, 1653,
    -246, 778, 1159, -147, -777, 1483, -602, 1119,
    -1590, 644, -872, 349, 418, 329, -156, -75,
    817, 1097, 603, 610, 1322, -1285, -1465, 384,
    -1215, -136, 1218, -1335, -874, 220, -1187, -1659,
    -1185, -1530, -1278, 794, -1510, -854, -870, 478,
    -108, -308, 996, 991, 958, -1460, 1522, 1628,
};

static int16_t fqmul(int16_t a, int16_t b)
{
    return td18_montgomery_reduce((int32_t)a * (int32_t)b);
}

static uint32_t feistel_round(uint32_t right, uint32_t key, uint32_t half_bits, uint32_t mask)
{
    return ((right * key) >> half_bits) & mask;
}

static uint32_t feistel_permute(uint32_t x, uint32_t bits, uint64_t seed)
{
    if (bits <= 1) return x;
    uint32_t half = bits / 2;
    uint32_t mask = ((uint32_t)1 << half) - 1;
    uint32_t left  = x >> half;
    uint32_t right = x & mask;
    uint64_t state = seed;
    for (int rnd = 0; rnd < 4; rnd++) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        uint32_t key = (((uint32_t)(state >> 32)) | 1u);
        uint32_t new_right = left ^ feistel_round(right, key, half, mask);
        left = right;
        right = new_right;
    }
    return (left << half) | (right & mask);
}

void td18_ntt_seed(uint64_t seed)
{
    g_ntt_seed = seed;
}

void td18_ntt(int16_t r[TD18_N])
{
    size_t k = 1;
    size_t len = 128;
    uint64_t seed = g_ntt_seed;
    while (len >= 2) {
        uint32_t bits = 0;
        size_t tmp = len;
        while (tmp > 1) { tmp >>= 1; bits++; }
        size_t start = 0;
        while (start < TD18_N) {
            int16_t zeta = ZETAS[k];
            k++;
            for (size_t idx = 0; idx < len; idx++) {
                size_t j = start + feistel_permute((uint32_t)idx, bits, seed);
                int16_t t = fqmul(zeta, r[j + len]);
                r[j + len] = r[j] - t;
                r[j]      += t;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

void td18_invntt(int16_t r[TD18_N])
{
    size_t k = 127;
    size_t len = 2;
    const int16_t F = 1441; /* mont^2 / 128 */
    uint64_t seed = g_ntt_seed;
    while (len <= 128) {
        uint32_t bits = 0;
        size_t tmp = len;
        while (tmp > 1) { tmp >>= 1; bits++; }
        size_t start = 0;
        while (start < TD18_N) {
            int16_t zeta = ZETAS[k];
            k--;
            for (size_t idx = 0; idx < len; idx++) {
                size_t j = start + feistel_permute((uint32_t)idx, bits, seed);
                int16_t t = r[j];
                r[j]       = td18_barrett_reduce(t + r[j + len]);
                r[j + len] = r[j + len] - t;
                r[j + len] = fqmul(zeta, r[j + len]);
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    for (int i = 0; i < TD18_N; i++) {
        r[i] = fqmul(r[i], F);
    }
}

void td18_basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta)
{
    r[0] = fqmul(a[1], b[1]);
    r[0] = fqmul(r[0], zeta);
    r[0] += fqmul(a[0], b[0]);
    r[1]  = fqmul(a[0], b[1]);
    r[1] += fqmul(a[1], b[0]);
}
