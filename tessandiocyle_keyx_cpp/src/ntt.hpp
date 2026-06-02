#pragma once
#include "params.hpp"
#include "reduce.hpp"
#include <cstdint>

namespace td18 {

/* Zetas for NTT — same as C ref_c */
inline const std::array<int16_t, 128>& zetas() {
    static const std::array<int16_t, 128> Z = {{
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
    }};
    return Z;
}

/* Global NTT seed */
inline uint64_t& ntt_seed_global() {
    static uint64_t s = 0;
    return s;
}
inline void ntt_seed(uint64_t s) { ntt_seed_global() = s; }

inline uint32_t feistel_round(uint32_t right, uint32_t key, uint32_t half_bits, uint32_t mask) {
    return ((right * key) >> half_bits) & mask;
}

inline uint32_t feistel_permute(uint32_t x, uint32_t bits, uint64_t seed) {
    if (bits <= 1) return x;
    uint32_t half = bits / 2;
    uint32_t mask = (1u << half) - 1;
    uint32_t left  = x >> half;
    uint32_t right = x & mask;
    uint64_t state = seed;
    for (int rnd = 0; rnd < 4; ++rnd) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        uint32_t key = (static_cast<uint32_t>(state >> 32)) | 1u;
        uint32_t new_right = left ^ feistel_round(right, key, half, mask);
        left = right;
        right = new_right;
    }
    return (left << half) | (right & mask);
}

void ntt(Poly& r);
void invntt(Poly& r);
void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta);

} // namespace td18
