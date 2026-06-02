/**
 * TessanDioKey V18 — CCA KEM with triple-redundant decaps, VDF rate-limiting
 * Translated from Rust V18 kem.rs
 */
#include "tessandiocyle_keyx.h"
#include <string.h>
#include "randombytes.h"

static uint64_t derive_ntt_seed(const uint8_t coins[TD18_SYMBYTES])
{
    uint8_t hash[32];
    td18_hash_h(hash, coins, TD18_SYMBYTES);
    uint64_t s = 0;
    for (int i = 0; i < 8; i++) s |= ((uint64_t)hash[i]) << (8 * i);
    return s;
}

static void decaps_state_mac(const uint8_t sk[TD18_SECRETKEYBYTES],
                             const uint8_t buf[2 * TD18_SYMBYTES],
                             const uint8_t ct[TD18_CIPHERTEXTBYTES],
                             uint8_t mac[16])
{
    uint8_t key[32];
    memcpy(key, sk + TD18_SECRETKEYBYTES - TD18_SYMBYTES, TD18_SYMBYTES);
    uint8_t in[TD18_SYMBYTES + 24 + 2*TD18_SYMBYTES + TD18_CIPHERTEXTBYTES];
    memcpy(in, key, TD18_SYMBYTES);
    memcpy(in + TD18_SYMBYTES, "tessandio-v18-decaps-mac", 24);
    memcpy(in + TD18_SYMBYTES + 24, buf, 2 * TD18_SYMBYTES);
    memcpy(in + TD18_SYMBYTES + 24 + 2 * TD18_SYMBYTES, ct, TD18_CIPHERTEXTBYTES);
    uint8_t hash[32];
    td18_hash_h(hash, in, sizeof(in));
    memcpy(mac, hash, 16);
}

static void vdf_prove(uint8_t out[32], const uint8_t *in, size_t inlen, uint32_t iterations)
{
    td18_hash_h(out, in, inlen);
    for (uint32_t i = 0; i < iterations; i++) {
        uint8_t tmp[32];
        td18_hash_h(tmp, out, 32);
        memcpy(out, tmp, 32);
    }
}

static void majority_vote(const uint8_t *a, const uint8_t *b, const uint8_t *c,
                          uint8_t *out, size_t len)
{
    for (size_t i = 0; i < len; i++)
        out[i] = (a[i] == b[i] || a[i] == c[i]) ? a[i] : b[i];
}

static void triple_decaps_buf(const uint8_t ct[TD18_CIPHERTEXTBYTES],
                              const uint8_t sk[TD18_SECRETKEYBYTES],
                              uint8_t out[2 * TD18_SYMBYTES])
{
    uint8_t buf0[2 * TD18_SYMBYTES] = {0};
    uint8_t buf1[2 * TD18_SYMBYTES] = {0};
    uint8_t buf2[2 * TD18_SYMBYTES] = {0};

    td18_indcpa_dec(buf0, ct, sk);
    td18_indcpa_dec(buf1, ct, sk);
    td18_indcpa_dec(buf2, ct, sk);

    memcpy(buf0 + TD18_SYMBYTES,
           sk + TD18_SECRETKEYBYTES - 2 * TD18_SYMBYTES,
           TD18_SYMBYTES);
    memcpy(buf1 + TD18_SYMBYTES,
           sk + TD18_SECRETKEYBYTES - 2 * TD18_SYMBYTES,
           TD18_SYMBYTES);
    memcpy(buf2 + TD18_SYMBYTES,
           sk + TD18_SECRETKEYBYTES - 2 * TD18_SYMBYTES,
           TD18_SYMBYTES);

    majority_vote(buf0, buf1, buf2, out, 2 * TD18_SYMBYTES);
}

void td18_kem_keypair_derand(uint8_t pk[TD18_PUBLICKEYBYTES],
                             uint8_t sk[TD18_SECRETKEYBYTES],
                             const uint8_t coins[2 * TD18_SYMBYTES])
{
    td18_ntt_seed(derive_ntt_seed(coins));
    uint8_t indcpa_sk[TD18_INDCPA_SECRETKEYBYTES];
    td18_indcpa_keypair_derand(pk, indcpa_sk, coins);

    memcpy(sk, indcpa_sk, TD18_INDCPA_SECRETKEYBYTES);
    memcpy(sk + TD18_INDCPA_SECRETKEYBYTES, pk, TD18_PUBLICKEYBYTES);

    uint8_t hpk[TD18_SYMBYTES];
    td18_hash_h(hpk, pk, TD18_PUBLICKEYBYTES);
    memcpy(sk + TD18_SECRETKEYBYTES - 2 * TD18_SYMBYTES, hpk, TD18_SYMBYTES);
    memcpy(sk + TD18_SECRETKEYBYTES - TD18_SYMBYTES, coins + TD18_SYMBYTES, TD18_SYMBYTES);

    td18_secure_zero(indcpa_sk, sizeof(indcpa_sk));
}

void td18_kem_enc_derand(uint8_t ct[TD18_CIPHERTEXTBYTES],
                         uint8_t ss[TD18_SSBYTES],
                         const uint8_t pk[TD18_PUBLICKEYBYTES],
                         const uint8_t coins[TD18_SYMBYTES])
{
    td18_ntt_seed(derive_ntt_seed(coins));
    uint8_t buf[2 * TD18_SYMBYTES];
    memcpy(buf, coins, TD18_SYMBYTES);

    uint8_t hpk[TD18_SYMBYTES];
    td18_hash_h(hpk, pk, TD18_PUBLICKEYBYTES);
    memcpy(buf + TD18_SYMBYTES, hpk, TD18_SYMBYTES);

    uint8_t kr[2 * TD18_SYMBYTES];
    td18_hash_g(kr, buf, sizeof(buf));

    td18_indcpa_enc(ct, buf, pk, kr + TD18_SYMBYTES);
    memcpy(ss, kr, TD18_SSBYTES);

    td18_secure_zero(kr, sizeof(kr));
}

void td18_kem_enc(uint8_t ct[TD18_CIPHERTEXTBYTES],
                  uint8_t ss[TD18_SSBYTES],
                  const uint8_t pk[TD18_PUBLICKEYBYTES])
{
    uint8_t coins[TD18_SYMBYTES];
    randombytes(coins, TD18_SYMBYTES);
    td18_kem_enc_derand(ct, ss, pk, coins);
}

void td18_kem_dec(uint8_t ss[TD18_SSBYTES],
                  const uint8_t ct[TD18_CIPHERTEXTBYTES],
                  const uint8_t sk[TD18_SECRETKEYBYTES])
{
    /* VDF rate-limiting */
    uint32_t vdf_iterations = 1u << 18;
    uint8_t vdf_input[TD18_SECRETKEYBYTES + TD18_CIPHERTEXTBYTES];
    memcpy(vdf_input, sk, TD18_SECRETKEYBYTES);
    memcpy(vdf_input + TD18_SECRETKEYBYTES, ct, TD18_CIPHERTEXTBYTES);
    uint8_t vdf_proof[32];
    vdf_prove(vdf_proof, vdf_input, sizeof(vdf_input), vdf_iterations);
    (void)vdf_proof; /* work itself is the rate limiter */

    td18_ntt_seed(derive_ntt_seed(sk + TD18_SECRETKEYBYTES - TD18_SYMBYTES));
    const uint8_t *pk = sk + TD18_INDCPA_SECRETKEYBYTES;

    /* Triple-redundant decryption */
    uint8_t buf[2 * TD18_SYMBYTES];
    triple_decaps_buf(ct, sk, buf);

    /* Memory-auth MAC */
    uint8_t mac[16];
    decaps_state_mac(sk, buf, ct, mac);
    (void)mac;

    /* FO re-encryption (triple redundant) */
    uint8_t kr0[2 * TD18_SYMBYTES], kr1[2 * TD18_SYMBYTES], kr2[2 * TD18_SYMBYTES], kr[2 * TD18_SYMBYTES];
    td18_hash_g(kr0, buf, sizeof(buf));
    td18_hash_g(kr1, buf, sizeof(buf));
    td18_hash_g(kr2, buf, sizeof(buf));
    majority_vote(kr0, kr1, kr2, kr, sizeof(kr));

    uint8_t cmp0[TD18_INDCPA_BYTES], cmp1[TD18_INDCPA_BYTES], cmp2[TD18_INDCPA_BYTES], cmp[TD18_INDCPA_BYTES];
    td18_indcpa_enc(cmp0, buf, pk, kr + TD18_SYMBYTES);
    td18_indcpa_enc(cmp1, buf, pk, kr + TD18_SYMBYTES);
    td18_indcpa_enc(cmp2, buf, pk, kr + TD18_SYMBYTES);
    majority_vote(cmp0, cmp1, cmp2, cmp, sizeof(cmp));

    uint8_t fail = td18_verify(ct, cmp, TD18_INDCPA_BYTES);

    /* Implicit rejection */
    uint8_t tmp_ss[TD18_SSBYTES];
    td18_rkprf(tmp_ss, sk + TD18_SECRETKEYBYTES - TD18_SYMBYTES, ct, TD18_CIPHERTEXTBYTES);

    td18_cmov(ss, kr, TD18_SSBYTES, (uint8_t)(1 - fail));
    td18_cmov(ss, tmp_ss, TD18_SSBYTES, fail);

    td18_secure_zero(kr0, sizeof(kr0));
    td18_secure_zero(kr1, sizeof(kr1));
    td18_secure_zero(kr2, sizeof(kr2));
    td18_secure_zero(buf, sizeof(buf));
}
