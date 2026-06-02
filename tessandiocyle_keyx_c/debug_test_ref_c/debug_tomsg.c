#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "tessandiocyle_keyx.h"
#include "ref_c/poly.h"

int main() {
    int same = 1;
    int diffs = 0;
    for (int v = -1000; v < 5000; v++) {
        td18_poly p1;
        poly p2;
        for (int i = 0; i < TD18_N; i++) {
            p1.coeffs[i] = (int16_t)v;
            p2.coeffs[i] = (int16_t)v;
        }
        uint8_t m1[32], m2[32];
        td18_poly_tomsg(m1, &p1);
        poly_tomsg(m2, &p2);
        if (memcmp(m1, m2, 32) != 0) {
            same = 0;
            diffs++;
            if (diffs <= 5) {
                printf("tomsg diff at v=%d: ", v);
                for (int i = 0; i < 8; i++) printf("%02x", m1[i]); printf(" | ");
                for (int i = 0; i < 8; i++) printf("%02x", m2[i]); printf("\n");
            }
        }
    }
    printf("poly_tomsg same over range: %s (diffs=%d)\n", same ? "YES" : "NO", diffs);
    return 0;
}
