/**
 * TessanDioKey V18 — Polynomial arithmetic
 */
#include "tessandiocyle_keyx.h"
#include <string.h>

/* poly_tobytes / frombytes / compress / decompress / frommsg / tomsg */

void td18_poly_tobytes(uint8_t r[TD18_POLYBYTES], const td18_poly *a)
{
    for (int i = 0; i < TD18_N / 2; i++) {
        uint16_t t0 = a->coeffs[2*i];
        uint16_t t1 = a->coeffs[2*i+1];
        t0 += ((int16_t)t0 >> 15) & TD18_Q;
        t1 += ((int16_t)t1 >> 15) & TD18_Q;
        r[3*i+0] = (uint8_t)(t0 >> 0);
        r[3*i+1] = (uint8_t)((t0 >> 8) | (t1 << 4));
        r[3*i+2] = (uint8_t)(t1 >> 4);
    }
}

void td18_poly_frombytes(td18_poly *r, const uint8_t a[TD18_POLYBYTES])
{
    for (int i = 0; i < TD18_N / 2; i++) {
        r->coeffs[2*i]   = (int16_t)(((uint16_t)a[3*i+0]       ) | ((uint16_t)a[3*i+1] << 8)) & 0xFFF;
        r->coeffs[2*i+1] = (int16_t)(((uint16_t)a[3*i+1] >> 4) | ((uint16_t)a[3*i+2] << 4)) & 0xFFF;
    }
}

void td18_poly_compress(uint8_t r[TD18_POLYCOMPRESSEDBYTES], const td18_poly *a)
{
    for (int i = 0; i < TD18_N / 8; i++) {
        uint8_t t[8];
        for (int j = 0; j < 8; j++) {
            int16_t u = a->coeffs[8*i+j];
            u += (u >> 15) & TD18_Q;
            uint32_t d0 = u;
            d0 <<= 4;
            d0 += 1665;
            d0 *= 80635;
            d0 >>= 28;
            t[j] = (uint8_t)(d0 & 0xf);
        }
        r[0] = t[0] | (t[1] << 4);
        r[1] = t[2] | (t[3] << 4);
        r[2] = t[4] | (t[5] << 4);
        r[3] = t[6] | (t[7] << 4);
        r += 4;
    }
}

void td18_poly_decompress(td18_poly *r, const uint8_t a[TD18_POLYCOMPRESSEDBYTES])
{
    for (int i = 0; i < TD18_N / 2; i++) {
        r->coeffs[2*i+0] = (int16_t)((((uint16_t)(a[0] & 15) * TD18_Q) + 8) >> 4);
        r->coeffs[2*i+1] = (int16_t)((((uint16_t)(a[0] >> 4) * TD18_Q) + 8) >> 4);
        a += 1;
    }
}

static void cmov_int16(int16_t *p, int16_t v, uint16_t b)
{
    b = (uint16_t)(-(int16_t)b);
    *p ^= (int16_t)(b & (uint16_t)(*p ^ v));
}

void td18_poly_frommsg(td18_poly *r, const uint8_t msg[TD18_SYMBYTES])
{
    for (int i = 0; i < TD18_N / 8; i++) {
        for (int j = 0; j < 8; j++) {
            r->coeffs[8*i+j] = 0;
            cmov_int16(&r->coeffs[8*i+j], (TD18_Q + 1) / 2, (msg[i] >> j) & 1);
        }
    }
}

void td18_poly_tomsg(uint8_t msg[TD18_SYMBYTES], const td18_poly *a)
{
    for (int i = 0; i < TD18_N / 8; i++) {
        msg[i] = 0;
        for (int j = 0; j < 8; j++) {
            int32_t t = a->coeffs[8*i+j];
            t += (t >> 15) & TD18_Q;
            t = (((t << 1) + TD18_Q / 2) / TD18_Q) & 1;
            msg[i] |= (uint8_t)(t << j);
        }
    }
}

void td18_poly_ntt(td18_poly *r)
{
    td18_ntt(r->coeffs);
    td18_poly_reduce(r);
}

void td18_poly_invntt_tomont(td18_poly *r)
{
    td18_invntt(r->coeffs);
}

void td18_poly_basemul_montgomery(td18_poly *r, const td18_poly *a, const td18_poly *b)
{
    for (int i = 0; i < TD18_N / 4; i++) {
        static const int16_t zetas_hi[128] = {
            -1044, -758, -359, -1517, 1493, 1422, 287, 202,
            -171, 622, 1577, 182, 962, -1202, -1474, 1468,
            573, -1325, 264, 383, -829, 1458, -1602, -130,
            -681, 1017, 732, 608, -1542, 411, -205, -1571,
            1223, 652, -552, 1015, -1293, 1491, -282, -1544,
            516, -8, -320, -666, -1618, -1162, 126, 1469,
            -853, -90, -271, 830, 107, -1421, -247, -951,
            -398, 961, -1508, -725, 448, -1065, 677, -1275,
            -1103, 430, 555, 843, -1251, 871, 1550, 105,
            422, 587, 177, -235, -291, -460, 1574, 1653,
            -246, 778, 1159, -147, -777, 1483, -602, 1119,
            -1590, 644, -872, 349, 418, 329, -156, -75,
            817, 1097, 603, 610, 1322, -1285, -1465, 384,
            -1215, -136, 1218, -1335, -874, 220, -1187, -1659,
            -1185, -1530, -1278, 794, -1510, -854, -870, 478,
            -108, -308, 996, 991, 958, -1460, 1522, 1628,
        };
        td18_basemul(&r->coeffs[4*i],   &a->coeffs[4*i],   &b->coeffs[4*i],   zetas_hi[64+i]);
        td18_basemul(&r->coeffs[4*i+2], &a->coeffs[4*i+2], &b->coeffs[4*i+2], -zetas_hi[64+i]);
    }
}

void td18_poly_tomont(td18_poly *r)
{
    const int32_t f = (int32_t)((1ULL << 32) % TD18_Q);
    for (int i = 0; i < TD18_N; i++)
        r->coeffs[i] = td18_montgomery_reduce((int32_t)r->coeffs[i] * f);
}

void td18_poly_reduce(td18_poly *r)
{
    for (int i = 0; i < TD18_N; i++)
        r->coeffs[i] = td18_barrett_reduce(r->coeffs[i]);
}

void td18_poly_add(td18_poly *r, const td18_poly *a, const td18_poly *b)
{
    for (int i = 0; i < TD18_N; i++) r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

void td18_poly_sub(td18_poly *r, const td18_poly *a, const td18_poly *b)
{
    for (int i = 0; i < TD18_N; i++) r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}
