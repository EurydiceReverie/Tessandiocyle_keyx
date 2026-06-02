#pragma once
#include "params.hpp"
#include <array>

namespace td18 {

/* CBD centered binomial distribution */
inline void cbd2(Poly& r, const std::array<uint8_t,128>& buf) {
    auto load32 = [](const uint8_t x[4]) -> uint32_t {
        return static_cast<uint32_t>(x[0])
             | (static_cast<uint32_t>(x[1]) << 8)
             | (static_cast<uint32_t>(x[2]) << 16)
             | (static_cast<uint32_t>(x[3]) << 24);
    };
    for (int i = 0; i < N / 8; ++i) {
        uint32_t t = load32(&buf[4 * i]);
        uint32_t d = t & 0x55555555;
        d += (t >> 1) & 0x55555555;
        for (int j = 0; j < 8; ++j) {
            int16_t a = static_cast<int16_t>((d >> (4*j)) & 3);
            int16_t b = static_cast<int16_t>((d >> (4*j + 2)) & 3);
            r[8*i + j] = a - b;
        }
    }
}

void poly_getnoise_eta1(Poly& r, const std::array<uint8_t,SYMBYTES>& seed, uint8_t nonce);
void poly_getnoise_eta2(Poly& r, const std::array<uint8_t,SYMBYTES>& seed, uint8_t nonce);

} // namespace td18
