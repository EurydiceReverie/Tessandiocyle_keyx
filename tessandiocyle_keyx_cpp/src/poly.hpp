#pragma once
#include "params.hpp"
#include "reduce.hpp"
#include "ntt.hpp"
#include <array>
#include <cstdint>

namespace td18 {

inline void poly_compress(std::array<uint8_t,POLYCOMPRESSEDBYTES>& r, const Poly& a) {
    for (int i = 0; i < N / 8; ++i) {
        uint8_t t[8];
        for (int j = 0; j < 8; ++j) {
            int16_t u = a[8*i+j];
            u += (u >> 15) & Q;
            uint32_t d0 = static_cast<uint32_t>(u);
            d0 <<= 4;
            d0 += 1665;
            d0 *= 80635;
            d0 >>= 28;
            t[j] = static_cast<uint8_t>(d0 & 0xf);
        }
        r[4*i+0] = t[0] | (t[1] << 4);
        r[4*i+1] = t[2] | (t[3] << 4);
        r[4*i+2] = t[4] | (t[5] << 4);
        r[4*i+3] = t[6] | (t[7] << 4);
    }
}

inline void poly_decompress(Poly& r, const std::array<uint8_t,POLYCOMPRESSEDBYTES>& a) {
    for (int i = 0; i < N / 2; ++i) {
        r[2*i+0] = static_cast<int16_t>((((static_cast<uint16_t>(a[i] & 15) * Q) + 8) >> 4));
        r[2*i+1] = static_cast<int16_t>((((static_cast<uint16_t>(a[i] >> 4) * Q) + 8) >> 4));
    }
}

inline void poly_tobytes(std::array<uint8_t,POLYBYTES>& r, const Poly& a) {
    for (int i = 0; i < N / 2; ++i) {
        uint16_t t0 = static_cast<uint16_t>(a[2*i]);
        uint16_t t1 = static_cast<uint16_t>(a[2*i+1]);
        t0 += (static_cast<int16_t>(t0) >> 15) & Q;
        t1 += (static_cast<int16_t>(t1) >> 15) & Q;
        r[3*i+0] = static_cast<uint8_t>(t0 >> 0);
        r[3*i+1] = static_cast<uint8_t>((t0 >> 8) | (t1 << 4));
        r[3*i+2] = static_cast<uint8_t>(t1 >> 4);
    }
}

inline void poly_frombytes(Poly& r, const std::array<uint8_t,POLYBYTES>& a) {
    for (int i = 0; i < N / 2; ++i) {
        r[2*i]   = static_cast<int16_t>(((static_cast<uint16_t>(a[3*i+0])       ) | (static_cast<uint16_t>(a[3*i+1]) << 8)) & 0xFFF);
        r[2*i+1] = static_cast<int16_t>(((static_cast<uint16_t>(a[3*i+1]) >> 4) | (static_cast<uint16_t>(a[3*i+2]) << 4)) & 0xFFF);
    }
}

inline void cmov_int16(int16_t& p, int16_t v, uint16_t b) {
    b = static_cast<uint16_t>(-static_cast<int16_t>(b));
    p ^= static_cast<int16_t>(b & static_cast<uint16_t>(p ^ v));
}

inline void poly_frommsg(Poly& r, const std::array<uint8_t,SYMBYTES>& msg) {
    for (int i = 0; i < N / 8; ++i) {
        for (int j = 0; j < 8; ++j) {
            r[8*i+j] = 0;
            cmov_int16(r[8*i+j], (Q + 1) / 2, (msg[i] >> j) & 1);
        }
    }
}

inline void poly_tomsg(std::array<uint8_t,SYMBYTES>& msg, const Poly& a) {
    for (int i = 0; i < N / 8; ++i) {
        msg[i] = 0;
        for (int j = 0; j < 8; ++j) {
            int32_t t = a[8*i+j];
            t += (t >> 15) & Q;
            t = (((t << 1) + Q / 2) / Q) & 1;
            msg[i] |= static_cast<uint8_t>(t << j);
        }
    }
}

inline void poly_ntt(Poly& r) {
    ntt(r);
    for (auto& c : r) c = barrett_reduce(c);
}

inline void poly_invntt_tomont(Poly& r) {
    invntt(r);
}

inline void poly_basemul_montgomery(Poly& r, const Poly& a, const Poly& b) {
    const auto& Z = zetas();
    for (int i = 0; i < N / 4; ++i) {
        basemul(&r[4*i],   &a[4*i],   &b[4*i],   Z[64+i]);
        basemul(&r[4*i+2], &a[4*i+2], &b[4*i+2], -Z[64+i]);
    }
}

inline void poly_tomont(Poly& r) {
    const int32_t f = static_cast<int32_t>((1ULL << 32) % Q);
    for (int i = 0; i < N; ++i)
        r[i] = montgomery_reduce(static_cast<int32_t>(r[i]) * f);
}

inline void poly_reduce(Poly& r) {
    for (int i = 0; i < N; ++i) r[i] = barrett_reduce(r[i]);
}

inline void poly_add(Poly& r, const Poly& a) {
    for (int i = 0; i < N; ++i) r[i] += a[i];
}

inline void poly_sub(Poly& r, const Poly& a) {
    for (int i = 0; i < N; ++i) r[i] = a[i] - r[i];
}

} // namespace td18
