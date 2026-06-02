#pragma once
#include "params.hpp"
#include "poly.hpp"
#include <array>

namespace td18 {

inline void polyvec_compress(std::array<uint8_t,POLYVECCOMPRESSEDBYTES>& r, const PolyVec& a) {
    size_t off = 0;
    for (int i = 0; i < K; ++i) {
        for (int j = 0; j < N / 4; ++j) {
            uint16_t t[4];
            for (int k = 0; k < 4; ++k) {
                t[k] = static_cast<uint16_t>(a[i][4*j+k]);
                t[k] += (static_cast<int16_t>(t[k]) >> 15) & Q;
                uint64_t d0 = t[k];
                d0 <<= 10;
                d0 += 1665;
                d0 *= 1290167;
                d0 >>= 32;
                t[k] = static_cast<uint16_t>(d0 & 0x3FF);
            }
            r[off+0] = static_cast<uint8_t>(t[0] >> 0);
            r[off+1] = static_cast<uint8_t>((t[0] >> 8) | (t[1] << 2));
            r[off+2] = static_cast<uint8_t>((t[1] >> 6) | (t[2] << 4));
            r[off+3] = static_cast<uint8_t>((t[2] >> 4) | (t[3] << 6));
            r[off+4] = static_cast<uint8_t>(t[3] >> 2);
            off += 5;
        }
    }
}

inline void polyvec_decompress(PolyVec& r, const std::array<uint8_t,POLYVECCOMPRESSEDBYTES>& a) {
    size_t off = 0;
    for (int i = 0; i < K; ++i) {
        for (int j = 0; j < N / 4; ++j) {
            uint16_t t[4];
            t[0] = static_cast<uint16_t>(a[off+0]       ) | (static_cast<uint16_t>(a[off+1]) << 8);
            t[1] = static_cast<uint16_t>(a[off+1] >> 2) | (static_cast<uint16_t>(a[off+2]) << 6);
            t[2] = static_cast<uint16_t>(a[off+2] >> 4) | (static_cast<uint16_t>(a[off+3]) << 4);
            t[3] = static_cast<uint16_t>(a[off+3] >> 6) | (static_cast<uint16_t>(a[off+4]) << 2);
            off += 5;
            for (int k = 0; k < 4; ++k)
                r[i][4*j+k] = static_cast<int16_t>(((static_cast<uint32_t>(t[k] & 0x3FF) * Q + 512) >> 10));
        }
    }
}

inline void polyvec_tobytes(std::array<uint8_t,POLYVECBYTES>& r, const PolyVec& a) {
    for (int i = 0; i < K; ++i) {
        std::array<uint8_t,POLYBYTES> tmp;
        poly_tobytes(tmp, a[i]);
        std::copy(tmp.begin(), tmp.end(), r.begin() + i * POLYBYTES);
    }
}

inline void polyvec_frombytes(PolyVec& r, const std::array<uint8_t,POLYVECBYTES>& a) {
    for (int i = 0; i < K; ++i) {
        std::array<uint8_t,POLYBYTES> tmp;
        std::copy(a.begin() + i * POLYBYTES, a.begin() + (i+1) * POLYBYTES, tmp.begin());
        poly_frombytes(r[i], tmp);
    }
}

inline void polyvec_ntt(PolyVec& r) {
    for (int i = 0; i < K; ++i) poly_ntt(r[i]);
}

inline void polyvec_invntt_tomont(PolyVec& r) {
    for (int i = 0; i < K; ++i) poly_invntt_tomont(r[i]);
}

inline void polyvec_basemul_acc_montgomery(Poly& r, const PolyVec& a, const PolyVec& b) {
    Poly t;
    poly_basemul_montgomery(r, a[0], b[0]);
    for (int i = 1; i < K; ++i) {
        poly_basemul_montgomery(t, a[i], b[i]);
        poly_add(r, t);
    }
    poly_reduce(r);
}

inline void polyvec_reduce(PolyVec& r) {
    for (int i = 0; i < K; ++i) poly_reduce(r[i]);
}

inline void polyvec_add(PolyVec& r, const PolyVec& a) {
    for (int i = 0; i < K; ++i) {
        for (int j = 0; j < N; ++j) r[i][j] += a[i][j];
    }
}

} // namespace td18
