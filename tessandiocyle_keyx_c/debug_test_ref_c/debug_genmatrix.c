#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* Native */
#include "tessandiocyle_keyx.h"
#include "ref_c/fips202.h"

/* Ref C globals */
#include "ref_c/params.h"
#include "ref_c/polyvec.h"
#include "ref_c/poly.h"
#include "ref_c/indcpa.h"

#define GEN_MATRIX_NBLOCKS 3
#define XOF_BLOCKBYTES 168

static size_t rej_uniform_native(int16_t *r, size_t len, const uint8_t *buf, size_t buflen)
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

static void native_gen_matrix(td18_polyvec a[TD18_K], const uint8_t seed[TD18_SYMBYTES], int transposed)
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
            size_t ctr = rej_uniform_native(a[i].vec[j].coeffs, TD18_N, buf, GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES);

            while (ctr < TD18_N) {
                shake128_squeezeblocks(buf, 1, &state);
                ctr += rej_uniform_native(a[i].vec[j].coeffs + ctr, TD18_N - ctr, buf, XOF_BLOCKBYTES);
            }
        }
    }
}

int main() {
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(0x11 * i);

    td18_polyvec a1[TD18_K];
    polyvec a2[KYBER_K];

    native_gen_matrix(a1, seed, 1);
    gen_matrix(a2, seed, 1);

    int same = 1;
    int diff_count = 0;
    for (int i = 0; i < TD18_K; i++) {
        for (int j = 0; j < TD18_K; j++) {
            for (int k = 0; k < TD18_N; k++) {
                if (a1[i].vec[j].coeffs[k] != a2[i].vec[j].coeffs[k]) {
                    same = 0;
                    diff_count++;
                    if (diff_count <= 5) {
                        printf("diff at [%d][%d][%d]: native=%d ref=%d\n", i, j, k,
                               a1[i].vec[j].coeffs[k], a2[i].vec[j].coeffs[k]);
                    }
                }
            }
        }
    }
    printf("gen_matrix(transposed=1) same: %s (diffs=%d)\n", same ? "YES" : "NO", diff_count);
    return 0;
}
