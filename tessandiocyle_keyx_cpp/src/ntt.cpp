#include "ntt.hpp"
#include <cstring>

namespace td18 {

void ntt(Poly& r) {
    uint64_t seed = ntt_seed_global();
    const auto& Z = zetas();
    size_t k = 1;
    size_t len = 128;
    while (len >= 2) {
        uint32_t bits = 0;
        size_t tmp = len;
        while (tmp > 1) { tmp >>= 1; bits++; }
        size_t start = 0;
        while (start < N) {
            int16_t zeta = Z[k];
            k++;
            for (size_t idx = 0; idx < len; ++idx) {
                size_t j = start + feistel_permute(static_cast<uint32_t>(idx), bits, seed);
                int16_t t = montgomery_reduce(static_cast<int32_t>(zeta) * r[j + len]);
                r[j + len] = r[j] - t;
                r[j] = r[j] + t;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

void invntt(Poly& r) {
    uint64_t seed = ntt_seed_global();
    const auto& Z = zetas();
    size_t k = 127;
    size_t len = 2;
    const int16_t F = 1441; /* mont^2 / 128 */
    while (len <= 128) {
        uint32_t bits = 0;
        size_t tmp = len;
        while (tmp > 1) { tmp >>= 1; bits++; }
        size_t start = 0;
        while (start < N) {
            int16_t zeta = Z[k];
            k--;
            for (size_t idx = 0; idx < len; ++idx) {
                size_t j = start + feistel_permute(static_cast<uint32_t>(idx), bits, seed);
                int16_t t = r[j];
                r[j] = barrett_reduce(t + r[j + len]);
                r[j + len] = r[j + len] - t;
                r[j + len] = montgomery_reduce(static_cast<int32_t>(zeta) * r[j + len]);
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    for (int i = 0; i < N; ++i) {
        r[i] = montgomery_reduce(static_cast<int32_t>(r[i]) * F);
    }
}

void basemul(int16_t rr[2], const int16_t a[2], const int16_t b[2], int16_t zeta) {
    rr[0] = montgomery_reduce(static_cast<int32_t>(a[1]) * b[1]);
    rr[0] = montgomery_reduce(static_cast<int32_t>(rr[0]) * zeta);
    rr[0] = montgomery_reduce(static_cast<int32_t>(a[0]) * b[0]) + rr[0];
    rr[1] = montgomery_reduce(static_cast<int32_t>(a[0]) * b[1]);
    rr[1] = montgomery_reduce(static_cast<int32_t>(a[1]) * b[0]) + rr[1];
}

} // namespace td18
