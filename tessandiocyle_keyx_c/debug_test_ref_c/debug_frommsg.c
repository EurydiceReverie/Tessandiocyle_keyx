#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "tessandiocyle_keyx.h"
#include "ref_c/poly.h"

int main() {
    uint8_t m[32];
    for (int i = 0; i < 32; i++) m[i] = (uint8_t)(0xAA + i);

    td18_poly p1;
    poly p2;

    td18_poly_frommsg(&p1, m);
    poly_frommsg(&p2, m);

    int same = 1;
    for (int i = 0; i < TD18_N; i++) {
        if (p1.coeffs[i] != p2.coeffs[i]) { same = 0; break; }
    }
    printf("poly_frommsg same: %s\n", same ? "YES" : "NO");
    return 0;
}
