#include <stdio.h>
#include <string.h>
#include "tessandiocyle_keyx.h"
#include "ref_c/ntt.h"
#include "ref_c/reduce.h"

int main() {
    int16_t a[256], b[256];
    for (int i = 0; i < 256; i++) a[i] = (int16_t)((i * 13) % 3329);
    memcpy(b, a, sizeof(a));

    /* Reference NTT */
    ntt(a);

    /* My NTT */
    td18_ntt_seed(0);
    td18_ntt(b);

    int same = 1;
    for (int i = 0; i < 256; i++) {
        if (a[i] != b[i]) {
            same = 0;
            if (i < 8) printf("diff[%d]: ref=%d mine=%d\n", i, a[i], b[i]);
        }
    }
    printf("NTT same with seed=0: %s\n", same ? "YES" : "NO");

    /* Compare invNTT */
    ntt(a);
    invntt(a);
    td18_ntt(b);
    td18_invntt(b);

    same = 1;
    for (int i = 0; i < 256; i++) {
        if (a[i] != b[i]) {
            same = 0;
            if (i < 8) printf("inv_diff[%d]: ref=%d mine=%d\n", i, a[i], b[i]);
        }
    }
    printf("NTT+invNTT same with seed=0: %s\n", same ? "YES" : "NO");

    /* Test if standard NTT roundtrips (without Feistel) */
    for (int i = 0; i < 256; i++) a[i] = (int16_t)((i * 13) % 3329);
    int16_t orig[256];
    memcpy(orig, a, sizeof(a));
    ntt(a);
    invntt(a);
    int ok = 1;
    for (int i = 0; i < 256; i++) {
        if (a[i] != orig[i]) { ok = 0; }
    }
    printf("Ref NTT roundtrip exact: %s\n", ok ? "YES" : "NO");
    if (!ok) {
        for (int i = 0; i < 8; i++) printf("ref[%d]: orig=%d back=%d\n", i, orig[i], a[i]);
    }

    return 0;
}
