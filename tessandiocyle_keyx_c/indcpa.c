/**
 * TessanDioKey V18 — IND-CPA encryption
 * Translated from Rust V18 indcpa.rs
 */
#include "tessandiocyle_keyx.h"
#include <string.h>
#include "fips202.h"

static void pack_pk(uint8_t *r, const td18_polyvec *pk, const uint8_t seed[TD18_SYMBYTES])
{
    td18_polyvec_tobytes(r, pk);
    memcpy(r + TD18_POLYVECBYTES, seed, TD18_SYMBYTES);
}

static void unpack_pk(td18_polyvec *pk, uint8_t seed[TD18_SYMBYTES], const uint8_t *packedpk)
{
    td18_polyvec_frombytes(pk, packedpk);
    memcpy(seed, packedpk + TD18_POLYVECBYTES, TD18_SYMBYTES);
}

static void pack_sk(uint8_t *r, const td18_polyvec *sk)
{
    td18_polyvec_tobytes(r, sk);
}

static void unpack_sk(td18_polyvec *sk, const uint8_t *packedsk)
{
    td18_polyvec_frombytes(sk, packedsk);
}

static void pack_ciphertext(uint8_t *r, const td18_polyvec *b, const td18_poly *v)
{
    td18_polyvec_compress(r, b);
    td18_poly_compress(r + TD18_POLYVECCOMPRESSEDBYTES, v);
}

static void unpack_ciphertext(td18_polyvec *b, td18_poly *v, const uint8_t *c)
{
    td18_polyvec_decompress(b, c);
    td18_poly_decompress(v, c + TD18_POLYVECCOMPRESSEDBYTES);
}

static size_t rej_uniform(int16_t *r, size_t len, const uint8_t *buf, size_t buflen)
{
    size_t ctr = 0, pos = 0;
    while (ctr < len && pos + 3 <= buflen) {
        uint16_t val0 = (uint16_t)(buf[pos] | ((uint16_t)buf[pos+1] << 8)) & 0xFFF;
        uint16_t val1 = (uint16_t)((buf[pos+1] >> 4) | ((uint16_t)buf[pos+2] << 4)) & 0xFFF;
        pos += 3;
        if (val0 < TD18_Q) { r[ctr] = (int16_t)val0; ctr++; }
        if (ctr < len && val1 < TD18_Q) { r[ctr] = (int16_t)val1; ctr++; }
    }
    return ctr;
}

#define GEN_MATRIX_NBLOCKS 3
#define XOF_BLOCKBYTES 168

static void gen_matrix(td18_polyvec a[TD18_K], const uint8_t seed[TD18_SYMBYTES], int transposed)
{
    for (int i = 0; i < TD18_K; i++) {
        for (int j = 0; j < TD18_K; j++) {
            keccak_state state;
            uint8_t extseed[TD18_SYMBYTES + 2];
            memcpy(extseed, seed, TD18_SYMBYTES);
            extseed[TD18_SYMBYTES + 0] = transposed ? (uint8_t)i : (uint8_t)j;
            extseed[TD18_SYMBYTES + 1] = transposed ? (uint8_t)j : (uint8_t)i;
            shake128_absorb_once(&state, extseed, sizeof(extseed));

            uint8_t buf[GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES];
            shake128_squeezeblocks(buf, GEN_MATRIX_NBLOCKS, &state);
            size_t ctr = rej_uniform(a[i].vec[j].coeffs, TD18_N, buf, GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES);

            while (ctr < TD18_N) {
                shake128_squeezeblocks(buf, 1, &state);
                ctr += rej_uniform(a[i].vec[j].coeffs + ctr, TD18_N - ctr, buf, XOF_BLOCKBYTES);
            }
        }
    }
}

void td18_indcpa_keypair_derand(uint8_t pk[TD18_INDCPA_PUBLICKEYBYTES],
                                uint8_t sk[TD18_INDCPA_SECRETKEYBYTES],
                                const uint8_t coins[TD18_SYMBYTES])
{
    td18_polyvec a[TD18_K];
    td18_polyvec e, pkpv, skpv;
    uint8_t buf[2 * TD18_SYMBYTES];
    uint8_t nonce = 0;

    memcpy(buf, coins, TD18_SYMBYTES);
    buf[TD18_SYMBYTES] = (uint8_t)TD18_K;
    uint8_t input[TD18_SYMBYTES + 1];
    memcpy(input, buf, TD18_SYMBYTES + 1);
    td18_hash_g(buf, input, TD18_SYMBYTES + 1);

    uint8_t *publicseed = buf;
    uint8_t *noiseseed  = buf + TD18_SYMBYTES;

    gen_matrix(a, publicseed, 0);

    for (int i = 0; i < TD18_K; i++) {
        td18_poly_getnoise_eta1(&skpv.vec[i], noiseseed, nonce++);
    }
    for (int i = 0; i < TD18_K; i++) {
        td18_poly_getnoise_eta1(&e.vec[i], noiseseed, nonce++);
    }

    td18_polyvec_ntt(&skpv);
    td18_polyvec_ntt(&e);

    for (int i = 0; i < TD18_K; i++) {
        td18_polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
        td18_poly_tomont(&pkpv.vec[i]);
    }
    td18_polyvec_add(&pkpv, &pkpv, &e);
    td18_polyvec_reduce(&pkpv);

    pack_sk(sk, &skpv);
    pack_pk(pk, &pkpv, publicseed);
}

void td18_indcpa_enc(uint8_t c[TD18_INDCPA_BYTES],
                     const uint8_t m[TD18_SYMBYTES],
                     const uint8_t pk[TD18_INDCPA_PUBLICKEYBYTES],
                     const uint8_t coins[TD18_SYMBYTES])
{
    td18_polyvec at[TD18_K];
    td18_polyvec sp, pkpv, ep, b;
    td18_poly v, k, epp;
    uint8_t seed[TD18_SYMBYTES];
    uint8_t nonce = 0;

    unpack_pk(&pkpv, seed, pk);
    td18_poly_frommsg(&k, m);

    gen_matrix(at, seed, 1);

    for (int i = 0; i < TD18_K; i++) td18_poly_getnoise_eta1(&sp.vec[i], coins, nonce++);
    for (int i = 0; i < TD18_K; i++) td18_poly_getnoise_eta2(&ep.vec[i], coins, nonce++);
    td18_poly_getnoise_eta2(&epp, coins, nonce);

    td18_polyvec_ntt(&sp);

    for (int i = 0; i < TD18_K; i++)
        td18_polyvec_basemul_acc_montgomery(&b.vec[i], &at[i], &sp);

    td18_polyvec_basemul_acc_montgomery(&v, &pkpv, &sp);
    td18_polyvec_invntt_tomont(&b);
    td18_poly_invntt_tomont(&v);

    td18_polyvec_add(&b, &b, &ep);
    td18_poly_add(&v, &v, &epp);
    td18_poly_add(&v, &v, &k);
    td18_polyvec_reduce(&b);
    td18_poly_reduce(&v);

    pack_ciphertext(c, &b, &v);
}

void td18_indcpa_dec(uint8_t m[TD18_SYMBYTES],
                     const uint8_t c[TD18_INDCPA_BYTES],
                     const uint8_t sk[TD18_INDCPA_SECRETKEYBYTES])
{
    td18_polyvec b, skpv;
    td18_poly v, mp;

    unpack_ciphertext(&b, &v, c);
    unpack_sk(&skpv, sk);

    td18_polyvec_ntt(&b);
    td18_polyvec_basemul_acc_montgomery(&mp, &skpv, &b);
    td18_poly_invntt_tomont(&mp);

    td18_poly_sub(&mp, &v, &mp);
    td18_poly_reduce(&mp);
    td18_poly_tomsg(m, &mp);
}
