#include <stdio.h>
#include <string.h>

/* Use ONLY reference C */
#include "ref_c/indcpa.h"
#include "ref_c/params.h"

int main() {
    uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES];
    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES];
    uint8_t coins[KYBER_SYMBYTES];
    for (int i = 0; i < KYBER_SYMBYTES; i++) coins[i] = (uint8_t)(0x11 * i);
    indcpa_keypair_derand(pk, sk, coins);

    uint8_t m[KYBER_SYMBYTES];
    for (int i = 0; i < KYBER_SYMBYTES; i++) m[i] = (uint8_t)(0xAA + i);
    uint8_t enc_coins[KYBER_SYMBYTES];
    for (int i = 0; i < KYBER_SYMBYTES; i++) enc_coins[i] = (uint8_t)(0x55 + i);
    uint8_t ct[KYBER_INDCPA_BYTES];
    indcpa_enc(ct, m, pk, enc_coins);

    uint8_t m_dec[KYBER_SYMBYTES];
    indcpa_dec(m_dec, ct, sk);

    if (memcmp(m, m_dec, KYBER_SYMBYTES) == 0) {
        printf("REF IND-CPA: OK\n");
    } else {
        printf("REF IND-CPA: FAIL\n");
        for (int i = 0; i < KYBER_SYMBYTES; i++) printf("%02x", m[i]); printf("\n");
        for (int i = 0; i < KYBER_SYMBYTES; i++) printf("%02x", m_dec[i]); printf("\n");
    }
    return 0;
}
