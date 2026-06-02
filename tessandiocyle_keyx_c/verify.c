#include <stdint.h>
#include <stddef.h>
#include "tessandiocyle_keyx.h"

uint8_t td18_verify(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint64_t r = 0;
    for (size_t i = 0; i < len; i++) r |= (uint64_t)(a[i] ^ b[i]);
    r = (~r + 1) >> 63; /* unsigned negation: 0->0, >0->1 */
    return (uint8_t)r;
}

void td18_cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b)
{
    b = (uint8_t)(-(int8_t)b);
    for (size_t i = 0; i < len; i++) r[i] ^= b & (x[i] ^ r[i]);
}
