/**
 * TessanDioKey V18 — CBD (Centered Binomial Distribution)
 */
#include "tessandiocyle_keyx.h"

static uint32_t load32_littleendian(const uint8_t x[4])
{
    return (uint32_t)x[0]
         | ((uint32_t)x[1] << 8)
         | ((uint32_t)x[2] << 16)
         | ((uint32_t)x[3] << 24);
}

void td18_cbd2(td18_poly *r, const uint8_t buf[128])
{
    for (int i = 0; i < TD18_N / 8; i++) {
        uint32_t t = load32_littleendian(&buf[4 * i]);
        uint32_t d = t & 0x55555555;
        d += (t >> 1) & 0x55555555;
        for (int j = 0; j < 8; j++) {
            int16_t a = (int16_t)((d >> (4 * j)) & 3);
            int16_t b = (int16_t)((d >> (4 * j + 2)) & 3);
            r->coeffs[8 * i + j] = a - b;
        }
    }
}

void td18_poly_getnoise_eta1(td18_poly *r, const uint8_t seed[TD18_SYMBYTES], uint8_t nonce)
{
    uint8_t buf[128];
    td18_prf(buf, sizeof(buf), seed, nonce);
    td18_cbd2(r, buf);
}

void td18_poly_getnoise_eta2(td18_poly *r, const uint8_t seed[TD18_SYMBYTES], uint8_t nonce)
{
    uint8_t buf[128];
    td18_prf(buf, sizeof(buf), seed, nonce);
    td18_cbd2(r, buf);
}
