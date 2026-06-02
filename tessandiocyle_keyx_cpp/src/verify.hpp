#pragma once
#include <cstdint>
#include <cstddef>

namespace td18 {

inline uint8_t verify(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t r = 0;
    for (size_t i = 0; i < len; ++i) r |= a[i] ^ b[i];
    return static_cast<uint8_t>((-(uint64_t)r) >> 63);
}

inline void cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b) {
    b = static_cast<uint8_t>(-static_cast<int8_t>(b));
    for (size_t i = 0; i < len; ++i) r[i] ^= b & (r[i] ^ x[i]);
}

} // namespace td18
