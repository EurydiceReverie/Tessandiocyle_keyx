#include "indcpa.hpp"
#include "polyvec.hpp"
#include "cbd.hpp"
#include "shake.hpp"
#include <cstring>

namespace td18 {

static size_t rej_uniform(int16_t *r, size_t len, const uint8_t *buf, size_t buflen) {
    size_t ctr = 0, pos = 0;
    while (ctr < len && pos + 3 <= buflen) {
        uint16_t val0 = (static_cast<uint16_t>(buf[pos]) | (static_cast<uint16_t>(buf[pos+1]) << 8)) & 0xFFF;
        uint16_t val1 = ((static_cast<uint16_t>(buf[pos+1]) >> 4) | (static_cast<uint16_t>(buf[pos+2]) << 4)) & 0xFFF;
        pos += 3;
        if (val0 < Q) r[ctr++] = static_cast<int16_t>(val0);
        if (ctr < len && val1 < Q) r[ctr++] = static_cast<int16_t>(val1);
    }
    return ctr;
}

void gen_matrix(std::array<PolyVec,K>& a, const std::array<uint8_t,SYMBYTES>& seed, bool transposed) {
    constexpr size_t GEN_MATRIX_NBLOCKS = 3;
    constexpr size_t BLOCK_SIZE = 168;
    for (int i = 0; i < K; ++i) {
        for (int j = 0; j < K; ++j) {
            uint8_t extseed[SYMBYTES + 2];
            std::copy(seed.begin(), seed.end(), extseed);
            extseed[SYMBYTES + 0] = transposed ? static_cast<uint8_t>(i) : static_cast<uint8_t>(j);
            extseed[SYMBYTES + 1] = transposed ? static_cast<uint8_t>(j) : static_cast<uint8_t>(i);

            Keccak1600 state(BLOCK_SIZE);
            state.shake128_absorb(extseed, sizeof(extseed));

            uint8_t buf[GEN_MATRIX_NBLOCKS * BLOCK_SIZE];
            state.shake128_squeeze(buf, sizeof(buf));
            size_t ctr = rej_uniform(a[i][j].data(), N, buf, sizeof(buf));

            while (ctr < N) {
                state.shake128_squeeze(buf, BLOCK_SIZE);
                ctr += rej_uniform(a[i][j].data() + ctr, N - ctr, buf, BLOCK_SIZE);
            }
        }
    }
}

void indcpa_keypair_derand(std::array<uint8_t,INDCPA_PUBLICKEYBYTES>& pk,
                           std::array<uint8_t,INDCPA_SECRETKEYBYTES>& sk,
                           const std::array<uint8_t,SYMBYTES>& coins) {
    std::array<PolyVec,K> a;
    PolyVec e, pkpv, skpv;
    uint8_t buf[2 * SYMBYTES];
    std::copy(coins.begin(), coins.end(), buf);
    buf[SYMBYTES] = static_cast<uint8_t>(K);
    uint8_t input[SYMBYTES + 1];
    std::copy(buf, buf + SYMBYTES + 1, input);
    Keccak1600::sha3_512(buf, input, sizeof(input));

    uint8_t *publicseed = buf;
    uint8_t *noiseseed  = buf + SYMBYTES;

    gen_matrix(a, *reinterpret_cast<std::array<uint8_t,SYMBYTES>*>(publicseed), false);

    uint8_t nonce = 0;
    for (int i = 0; i < K; ++i) poly_getnoise_eta1(skpv[i], *reinterpret_cast<std::array<uint8_t,SYMBYTES>*>(noiseseed), nonce++);
    for (int i = 0; i < K; ++i) poly_getnoise_eta1(e[i], *reinterpret_cast<std::array<uint8_t,SYMBYTES>*>(noiseseed), nonce++);

    polyvec_ntt(skpv);
    polyvec_ntt(e);

    for (int i = 0; i < K; ++i) {
        polyvec_basemul_acc_montgomery(pkpv[i], a[i], skpv);
        poly_tomont(pkpv[i]);
    }
    polyvec_add(pkpv, e);
    polyvec_reduce(pkpv);

    polyvec_tobytes(sk, skpv);
    polyvec_tobytes(*reinterpret_cast<std::array<uint8_t,POLYVECBYTES>*>(&pk[0]), pkpv);
    std::copy(publicseed, publicseed + SYMBYTES, pk.begin() + POLYVECBYTES);
}

void indcpa_enc(std::array<uint8_t,INDCPA_BYTES>& c,
                const std::array<uint8_t,SYMBYTES>& m,
                const std::array<uint8_t,INDCPA_PUBLICKEYBYTES>& pk,
                const std::array<uint8_t,SYMBYTES>& coins) {
    std::array<PolyVec,K> at;
    PolyVec sp, pkpv, ep, b;
    Poly v, k, epp;
    std::array<uint8_t,SYMBYTES> seed;
    uint8_t nonce = 0;

    polyvec_frombytes(pkpv, *reinterpret_cast<const std::array<uint8_t,POLYVECBYTES>*>(&pk[0]));
    std::copy(pk.begin() + POLYVECBYTES, pk.end(), seed.begin());
    poly_frommsg(k, m);
    gen_matrix(at, seed, true);

    for (int i = 0; i < K; ++i) poly_getnoise_eta1(sp[i], coins, nonce++);
    for (int i = 0; i < K; ++i) poly_getnoise_eta2(ep[i], coins, nonce++);
    poly_getnoise_eta2(epp, coins, nonce);

    polyvec_ntt(sp);
    for (int i = 0; i < K; ++i)
        polyvec_basemul_acc_montgomery(b[i], at[i], sp);

    polyvec_basemul_acc_montgomery(v, pkpv, sp);
    polyvec_invntt_tomont(b);
    poly_invntt_tomont(v);

    polyvec_add(b, ep);
    poly_add(v, epp);
    poly_add(v, k);
    polyvec_reduce(b);
    poly_reduce(v);

    polyvec_compress(*reinterpret_cast<std::array<uint8_t,POLYVECCOMPRESSEDBYTES>*>(&c[0]), b);
    poly_compress(*reinterpret_cast<std::array<uint8_t,POLYCOMPRESSEDBYTES>*>(&c[POLYVECCOMPRESSEDBYTES]), v);
}

void indcpa_dec(std::array<uint8_t,SYMBYTES>& m,
                const std::array<uint8_t,INDCPA_BYTES>& c,
                const std::array<uint8_t,INDCPA_SECRETKEYBYTES>& sk) {
    PolyVec b, skpv;
    Poly v, mp;
    polyvec_decompress(b, *reinterpret_cast<const std::array<uint8_t,POLYVECCOMPRESSEDBYTES>*>(&c[0]));
    poly_decompress(v, *reinterpret_cast<const std::array<uint8_t,POLYCOMPRESSEDBYTES>*>(&c[POLYVECCOMPRESSEDBYTES]));
    polyvec_frombytes(skpv, sk);

    polyvec_ntt(b);
    polyvec_basemul_acc_montgomery(mp, skpv, b);
    poly_invntt_tomont(mp);

    poly_sub(mp, v);    /* mp = v - mp */
    poly_reduce(mp);
    poly_tomsg(m, mp);
}

} // namespace td18
