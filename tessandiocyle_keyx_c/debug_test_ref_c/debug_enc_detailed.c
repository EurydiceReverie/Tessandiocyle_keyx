#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* Native */
#include "tessandiocyle_keyx.h"

/* Ref C */
#include "ref_c/params.h"
#include "ref_c/poly.h"
#include "ref_c/polyvec.h"
#include "ref_c/indcpa.h"

static void print_poly(const char *label, const td18_poly *p) {
    printf("%s:", label);
    for (int i = 0; i < 8; i++) printf(" %d", p->coeffs[i]);
    printf("\n");
}
static void print_poly_ref(const char *label, const poly *p) {
    printf("%s:", label);
    for (int i = 0; i < 8; i++) printf(" %d", p->coeffs[i]);
    printf("\n");
}
static void print_polyvec(const char *label, const td18_polyvec *pv) {
    for (int j = 0; j < TD18_K; j++) {
        printf("%s[%d]:", label, j);
        for (int i = 0; i < 4; i++) printf(" %d", pv->vec[j].coeffs[i]);
        printf("\n");
    }
}
static void print_polyvec_ref(const char *label, const polyvec *pv) {
    for (int j = 0; j < KYBER_K; j++) {
        printf("%s[%d]:", label, j);
        for (int i = 0; i < 4; i++) printf(" %d", pv->vec[j].coeffs[i]);
        printf("\n");
    }
}

int main() {
    uint8_t coins[32], enc_coins[32], m[32];
    for (int i = 0; i < 32; i++) coins[i] = (uint8_t)(0x11 * i);
    for (int i = 0; i < 32; i++) enc_coins[i] = (uint8_t)(0x55 + i);
    for (int i = 0; i < 32; i++) m[i] = (uint8_t)(0xAA + i);

    td18_ntt_seed(0);

    /* keypair */
    uint8_t pk1[TD18_INDCPA_PUBLICKEYBYTES], sk1[TD18_INDCPA_SECRETKEYBYTES];
    uint8_t pk2[KYBER_INDCPA_PUBLICKEYBYTES], sk2[KYBER_INDCPA_SECRETKEYBYTES];
    td18_indcpa_keypair_derand(pk1, sk1, coins);
    indcpa_keypair_derand(pk2, sk2, coins);
    printf("pk same: %d  sk same: %d\n",
           memcmp(pk1, pk2, sizeof(pk1)) == 0,
           memcmp(sk1, sk2, sizeof(sk1)) == 0);

    /* unpack pk */
    td18_polyvec pkpv1; td18_polyvec_frombytes(&pkpv1, pk1);
    uint8_t seed1[32]; memcpy(seed1, pk1 + TD18_POLYVECBYTES, TD18_SYMBYTES);
    polyvec pkpv2; polyvec_frombytes(&pkpv2, pk2);
    uint8_t seed2[32]; memcpy(seed2, pk2 + KYBER_POLYVECBYTES, KYBER_SYMBYTES);
    printf("seed same: %d\n", memcmp(seed1, seed2, 32) == 0);

    /* k */
    td18_poly k1; td18_poly_frommsg(&k1, m);
    poly k2; poly_frommsg(&k2, m);

    /* gen_matrix transposed */
    td18_polyvec at1[TD18_K];
    gen_matrix((polyvec*)at1, seed1, 1);
    polyvec at2[KYBER_K];
    gen_matrix(at2, seed2, 1);
    print_polyvec("at1[0]", &at1[0]);
    print_polyvec_ref("at2[0]", &at2[0]);

    /* noise */
    td18_polyvec sp1, ep1; td18_poly epp1;
    uint8_t n1 = 0;
    for (int i = 0; i < TD18_K; i++) td18_poly_getnoise_eta1(&sp1.vec[i], enc_coins, n1++);
    for (int i = 0; i < TD18_K; i++) td18_poly_getnoise_eta2(&ep1.vec[i], enc_coins, n1++);
    td18_poly_getnoise_eta2(&epp1, enc_coins, n1);

    polyvec sp2, ep2; poly epp2;
    uint8_t n2 = 0;
    for (int i = 0; i < KYBER_K; i++) poly_getnoise_eta1(&sp2.vec[i], enc_coins, n2++);
    for (int i = 0; i < KYBER_K; i++) poly_getnoise_eta2(&ep2.vec[i], enc_coins, n2++);
    poly_getnoise_eta2(&epp2, enc_coins, n2++);

    print_polyvec("sp1", &sp1); print_polyvec_ref("sp2", &sp2);
    print_polyvec("ep1", &ep1); print_polyvec_ref("ep2", &ep2);
    print_poly("epp1", &epp1); print_poly_ref("epp2", &epp2);

    /* ntt sp */
    td18_polyvec_ntt(&sp1); polyvec_ntt(&sp2);
    print_polyvec("sp1_ntt", &sp1); print_polyvec_ref("sp2_ntt", &sp2);

    /* b */
    td18_polyvec b1;
    for (int i = 0; i < TD18_K; i++)
        td18_polyvec_basemul_acc_montgomery(&b1.vec[i], &at1[i], &sp1);
    polyvec b2;
    for (int i = 0; i < KYBER_K; i++)
        polyvec_basemul_acc_montgomery(&b2.vec[i], &at2[i], &sp2);
    print_polyvec("b1_preinv", &b1); print_polyvec_ref("b2_preinv", &b2);

    /* v */
    td18_poly v1; td18_polyvec_basemul_acc_montgomery(&v1, &pkpv1, &sp1);
    poly v2; polyvec_basemul_acc_montgomery(&v2, &pkpv2, &sp2);
    print_poly("v1_preinv", &v1); print_poly_ref("v2_preinv", &v2);

    /* invntt */
    td18_polyvec_invntt_tomont(&b1); polyvec_invntt_tomont(&b2);
    td18_poly_invntt_tomont(&v1); poly_invntt_tomont(&v2);
    print_polyvec("b1_inv", &b1); print_polyvec_ref("b2_inv", &b2);
    print_poly("v1_inv", &v1); print_poly_ref("v2_inv", &v2);

    /* add */
    td18_polyvec_add(&b1, &b1, &ep1); polyvec_add(&b2, &b2, &ep2);
    td18_poly_add(&v1, &v1, &epp1); poly_add(&v2, &v2, &epp2);
    td18_poly_add(&v1, &v1, &k1); poly_add(&v2, &v2, &k2);
    print_polyvec("b1_add", &b1); print_polyvec_ref("b2_add", &b2);
    print_poly("v1_add", &v1); print_poly_ref("v2_add", &v2);

    /* reduce */
    td18_polyvec_reduce(&b1); polyvec_reduce(&b2);
    td18_poly_reduce(&v1); poly_reduce(&v2);
    print_polyvec("b1_red", &b1); print_polyvec_ref("b2_red", &b2);
    print_poly("v1_red", &v1); print_poly_ref("v2_red", &v2);

    /* check full v coeffs before compress */
    int v_diff = -1;
    for (int i = 0; i < TD18_N; i++) {
        if (v1.coeffs[i] != v2.coeffs[i]) { v_diff = i; break; }
    }
    printf("first v coeff diff: %d\n", v_diff);

    /* pack (compress directly) */
    uint8_t ct1[TD18_INDCPA_BYTES];
    uint8_t ct2[KYBER_INDCPA_BYTES];
    td18_polyvec_compress(ct1, &b1);
    td18_poly_compress(ct1 + TD18_POLYVECCOMPRESSEDBYTES, &v1);
    polyvec_compress(ct2, &b2);
    poly_compress(ct2 + KYBER_POLYVECCOMPRESSEDBYTES, &v2);

    int ct_same = 1;
    int diff_off = -1;
    for (int i = 0; i < (int)sizeof(ct1); i++) {
        if (ct1[i] != ct2[i]) { ct_same = 0; if (diff_off < 0) diff_off = i; }
    }
    printf("ct same: %d  first_diff=%d\n", ct_same, diff_off);
    if (!ct_same) {
        for (int i = diff_off; i < diff_off + 16 && i < (int)sizeof(ct1); i++) printf("%02x", ct1[i]); printf(" | ");
        for (int i = diff_off; i < diff_off + 16 && i < (int)sizeof(ct1); i++) printf("%02x", ct2[i]); printf("\n");
    }
    return 0;
}
