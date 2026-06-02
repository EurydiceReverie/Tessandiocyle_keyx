#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "tessandiocyle_keyx.h"

#include "ref_c/params.h"
#include "ref_c/poly.h"
#include "ref_c/polyvec.h"

int main() {
    /* --- poly_compress --- */
    {
        td18_poly p1;
        poly p2;
        for (int i = 0; i < TD18_N; i++) {
            int16_t v = (int16_t)((i * 13 + 17) % TD18_Q);
            p1.coeffs[i] = v;
            p2.coeffs[i] = v;
        }
        uint8_t c1[TD18_POLYCOMPRESSEDBYTES];
        uint8_t c2[KYBER_POLYCOMPRESSEDBYTES];
        td18_poly_compress(c1, &p1);
        poly_compress(c2, &p2);
        int same = (memcmp(c1, c2, TD18_POLYCOMPRESSEDBYTES) == 0);
        printf("poly_compress same: %s\n", same ? "YES" : "NO");
        if (!same) {
            for (int i = 0; i < 16; i++) printf("%02x", c1[i]); printf(" | ");
            for (int i = 0; i < 16; i++) printf("%02x", c2[i]); printf("\n");
        }
    }

    /* --- polyvec_compress --- */
    {
        td18_polyvec pv1;
        polyvec pv2;
        for (int i = 0; i < TD18_K; i++) {
            for (int j = 0; j < TD18_N; j++) {
                int16_t v = (int16_t)((i * 7 + j * 13 + 19) % TD18_Q);
                pv1.vec[i].coeffs[j] = v;
                pv2.vec[i].coeffs[j] = v;
            }
        }
        uint8_t c1[TD18_POLYVECCOMPRESSEDBYTES];
        uint8_t c2[KYBER_POLYVECCOMPRESSEDBYTES];
        td18_polyvec_compress(c1, &pv1);
        polyvec_compress(c2, &pv2);
        int same = (memcmp(c1, c2, TD18_POLYVECCOMPRESSEDBYTES) == 0);
        printf("polyvec_compress same: %s\n", same ? "YES" : "NO");
        if (!same) {
            for (int i = 0; i < 16; i++) printf("%02x", c1[i]); printf(" | ");
            for (int i = 0; i < 16; i++) printf("%02x", c2[i]); printf("\n");
        }
    }

    /* --- poly_decompress roundtrip approx --- */
    {
        td18_poly p1;
        for (int i = 0; i < TD18_N; i++) {
            p1.coeffs[i] = (int16_t)((i * 13 + 17) % TD18_Q);
        }
        uint8_t c1[TD18_POLYCOMPRESSEDBYTES];
        td18_poly_compress(c1, &p1);
        td18_poly p1d;
        td18_poly_decompress(&p1d, c1);
        poly p2d;
        poly_decompress(&p2d, c1);
        int same = 1;
        for (int i = 0; i < TD18_N; i++) {
            if (p1d.coeffs[i] != p2d.coeffs[i]) { same = 0; break; }
        }
        printf("poly_decompress same bytes as ref: %s\n", same ? "YES" : "NO");
    }

    return 0;
}
