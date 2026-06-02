/**
 * TessanDioKey V18 — Symmetric primitives using SHAKE-256/SHA3-256
 * Structurally matches Rust V18 symmetric.rs (BLAKE3 replaced by FIPS-202)
 */
#include "tessandiocyle_keyx.h"
#include <string.h>
#include "fips202.h"

void td18_hash_h(uint8_t out[32], const uint8_t *in, size_t inlen)
{
    sha3_256(out, in, inlen);
}

void td18_hash_g(uint8_t out[64], const uint8_t *in, size_t inlen)
{
    sha3_512(out, in, inlen);
}

void td18_xof(const uint8_t seed[TD18_SYMBYTES], uint8_t x, uint8_t y, uint8_t *out, size_t outlen)
{
    uint8_t in[TD18_SYMBYTES + 2];
    memcpy(in, seed, TD18_SYMBYTES);
    in[TD18_SYMBYTES] = x;
    in[TD18_SYMBYTES + 1] = y;
    shake256(out, outlen, in, sizeof(in));
}

void td18_prf(uint8_t *out, size_t outlen, const uint8_t key[TD18_SYMBYTES], uint8_t nonce)
{
    uint8_t in[TD18_SYMBYTES + 1];
    memcpy(in, key, TD18_SYMBYTES);
    in[TD18_SYMBYTES] = nonce;
    shake256(out, outlen, in, sizeof(in));
}

void td18_rkprf(uint8_t out[32], const uint8_t key[32], const uint8_t *in, size_t inlen)
{
    uint8_t buf[32 + inlen];
    memcpy(buf, key, 32);
    memcpy(buf + 32, in, inlen);
    shake256(out, 32, buf, sizeof(buf));
}
