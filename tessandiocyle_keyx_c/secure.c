/**
 * TessanDioKey V18 — Secure memory primitives
 * Translated from Rust V18 secure.rs
 */
#include "tessandiocyle_keyx.h"
#include <stdint.h>

void td18_secure_zero(void *p, size_t len)
{
    volatile uint8_t *vp = (volatile uint8_t *)p;
    while (len--) *vp++ = 0;
}

void td18_secure_copy(uint8_t *dst, const uint8_t *src, size_t len)
{
    volatile uint8_t *d = (volatile uint8_t *)dst;
    volatile const uint8_t *s = (volatile const uint8_t *)src;
    while (len--) *d++ = *s++;
}

void td18_ct_cswap(uint8_t *a, uint8_t *b, uint8_t swap)
{
    uint8_t mask = (uint8_t)(-(int8_t)swap);
    uint8_t diff = *a ^ *b;
    uint8_t t = mask & diff;
    *a ^= t;
    *b ^= t;
}
