#include <stdio.h>
#include <string.h>
#include "tessandiocyle_keyx.h"
#include "ref_c/indcpa.h"
#include "ref_c/params.h"

int main() {
    uint8_t coins[32];
    for (int i = 0; i < 32; i++) coins[i] = (uint8_t)(0x11 * i);

    td18_ntt_seed(0);

    uint8_t pk1[TD18_INDCPA_PUBLICKEYBYTES], sk1[TD18_INDCPA_SECRETKEYBYTES];
    uint8_t pk2[KYBER_INDCPA_PUBLICKEYBYTES], sk2[KYBER_INDCPA_SECRETKEYBYTES];

    td18_indcpa_keypair_derand(pk1, sk1, coins);
    pqcrystals_kyber768_ref_indcpa_keypair_derand(pk2, sk2, coins);

    int same_pk = memcmp(pk1, pk2, sizeof(pk1)) == 0;
    int same_sk = memcmp(sk1, sk2, sizeof(sk1)) == 0;
    printf("keypair pk same: %s\n", same_pk ? "YES" : "NO");
    printf("keypair sk same: %s\n", same_sk ? "YES" : "NO");

    if (!same_pk) {
        for (int i = 0; i < 16; i++) printf("%02x", pk1[i]); printf(" | ");
        for (int i = 0; i < 16; i++) printf("%02x", pk2[i]); printf("\n");
    }
    if (!same_sk) {
        for (int i = 0; i < 16; i++) printf("%02x", sk1[i]); printf(" | ");
        for (int i = 0; i < 16; i++) printf("%02x", sk2[i]); printf("\n");
    }

    if (same_pk && same_sk) {
        uint8_t m[32], enc_coins[32];
        for (int i = 0; i < 32; i++) m[i] = (uint8_t)(0xAA + i);
        for (int i = 0; i < 32; i++) enc_coins[i] = (uint8_t)(0x55 + i);

        uint8_t ct1[TD18_INDCPA_BYTES], ct2[KYBER_INDCPA_BYTES];
        td18_indcpa_enc(ct1, m, pk1, enc_coins);
        pqcrystals_kyber768_ref_indcpa_enc(ct2, m, pk2, enc_coins);

        int same_ct = memcmp(ct1, ct2, sizeof(ct1)) == 0;
        printf("enc ct same: %s\n", same_ct ? "YES" : "NO");
        if (!same_ct) {
            for (int i = 0; i < 16; i++) printf("%02x", ct1[i]); printf(" | ");
            for (int i = 0; i < 16; i++) printf("%02x", ct2[i]); printf("\n");
        }

        uint8_t md1[32], md2[32];
        td18_indcpa_dec(md1, ct1, sk1);
        pqcrystals_kyber768_ref_indcpa_dec(md2, ct2, sk2);
        int same_dec = memcmp(md1, md2, 32) == 0;
        printf("dec same: %s\n", same_dec ? "YES" : "NO");
        if (!same_dec) {
            for (int i = 0; i < 32; i++) printf("%02x", md1[i]); printf(" | ");
            for (int i = 0; i < 32; i++) printf("%02x", md2[i]); printf("\n");
        }
    }
    return 0;
}
