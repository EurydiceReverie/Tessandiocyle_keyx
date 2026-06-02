/**
 * TessanDioKey V18 — PolyVec operations
 */
#include "tessandiocyle_keyx.h"
#include <string.h>

void td18_polyvec_compress(uint8_t r[TD18_POLYVECCOMPRESSEDBYTES], const td18_polyvec *a)
{
    for (int i = 0; i < TD18_K; i++) {
        for (int j = 0; j < TD18_N / 4; j++) {
            uint16_t t[4];
            for (int k = 0; k < 4; k++) {
                t[k] = a->vec[i].coeffs[4*j+k];
                t[k] += ((int16_t)t[k] >> 15) & TD18_Q;
                uint64_t d0 = t[k];
                d0 <<= 10;
                d0 += 1665;
                d0 *= 1290167;
                d0 >>= 32;
                t[k] = (uint16_t)(d0 & 0x3FF);
            }
            r[0] = (uint8_t)(t[0] >> 0);
            r[1] = (uint8_t)((t[0] >> 8) | (t[1] << 2));
            r[2] = (uint8_t)((t[1] >> 6) | (t[2] << 4));
            r[3] = (uint8_t)((t[2] >> 4) | (t[3] << 6));
            r[4] = (uint8_t)(t[3] >> 2);
            r += 5;
        }
    }
}

void td18_polyvec_decompress(td18_polyvec *r, const uint8_t a[TD18_POLYVECCOMPRESSEDBYTES])
{
    for (int i = 0; i < TD18_K; i++) {
        for (int j = 0; j < TD18_N / 4; j++) {
            uint16_t t[4];
            t[0] = (uint16_t)(a[0]       ) | ((uint16_t)a[1] << 8);
            t[1] = (uint16_t)(a[1] >> 2) | ((uint16_t)a[2] << 6);
            t[2] = (uint16_t)(a[2] >> 4) | ((uint16_t)a[3] << 4);
            t[3] = (uint16_t)(a[3] >> 6) | ((uint16_t)a[4] << 2);
            a += 5;
            for (int k = 0; k < 4; k++)
                r->vec[i].coeffs[4*j+k] = (int16_t)(((uint32_t)(t[k] & 0x3FF) * TD18_Q + 512) >> 10);
        }
    }
}

void td18_polyvec_tobytes(uint8_t r[TD18_POLYVECBYTES], const td18_polyvec *a)
{
    for (int i = 0; i < TD18_K; i++)
        td18_poly_tobytes(r + i * TD18_POLYBYTES, &a->vec[i]);
}

void td18_polyvec_frombytes(td18_polyvec *r, const uint8_t a[TD18_POLYVECBYTES])
{
    for (int i = 0; i < TD18_K; i++)
        td18_poly_frombytes(&r->vec[i], a + i * TD18_POLYBYTES);
}

void td18_polyvec_ntt(td18_polyvec *r)
{
    for (int i = 0; i < TD18_K; i++) td18_poly_ntt(&r->vec[i]);
}

void td18_polyvec_invntt_tomont(td18_polyvec *r)
{
    for (int i = 0; i < TD18_K; i++) td18_poly_invntt_tomont(&r->vec[i]);
}

void td18_polyvec_basemul_acc_montgomery(td18_poly *r, const td18_polyvec *a, const td18_polyvec *b)
{
    td18_poly t;
    td18_poly_basemul_montgomery(r, &a->vec[0], &b->vec[0]);
    for (int i = 1; i < TD18_K; i++) {
        td18_poly_basemul_montgomery(&t, &a->vec[i], &b->vec[i]);
        td18_poly_add(r, r, &t);
    }
    td18_poly_reduce(r);
}

void td18_polyvec_reduce(td18_polyvec *r)
{
    for (int i = 0; i < TD18_K; i++) td18_poly_reduce(&r->vec[i]);
}

void td18_polyvec_add(td18_polyvec *r, const td18_polyvec *a, const td18_polyvec *b)
{
    for (int i = 0; i < TD18_K; i++) td18_poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
}
