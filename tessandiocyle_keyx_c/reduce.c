/**
 * TessanDioKey V18 — Reduce
 * Barrett and Montgomery reduction ( native C, from Rust V18 )
 */
#include "tessandiocyle_keyx.h"

#define V  ((((int32_t)1 << 26) + (TD18_Q / 2)) / TD18_Q)

int16_t td18_montgomery_reduce(int32_t a)
{
    int16_t t = (int16_t)(a);
    int32_t u = a - (int32_t)((int16_t)(t * TD18_QINV)) * TD18_Q;
    return (int16_t)(u >> 16);
}

int16_t td18_barrett_reduce(int16_t a)
{
    int32_t t = ((int32_t)V * (int32_t)a + (1 << 25)) >> 26;
    return a - (int16_t)(t * TD18_Q);
}
