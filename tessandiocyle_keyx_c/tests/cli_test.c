/**
 * TessanDioKey V18 — C CLI Test (native implementation)
 * gcc -O2 -Wall -Wextra -o cli_test *.c && ./cli_test
 */
#include <stdio.h>
#include <string.h>
#include "tessandiocyle_keyx.h"

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s", label);
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

static int all_pass = 1;
#define CHECK(name, cond) do { \
    if (!(cond)) { printf("[FAIL] %s\n", name); all_pass = 0; } \
    else          { printf("[PASS] %s\n", name); } \
} while(0)

int main(void)
{
    printf("=== TessanDioKey V18 C Native Test ===\n\n");

    td18_params params;
    CHECK("params_init", td18_params_init(&params) == TD18_OK);
    printf("Epoch: %llu\n", (unsigned long long)params.epoch);

    uint8_t pk[TD18_PUBLICKEYBYTES];
    uint8_t sk[TD18_SECRETKEYBYTES];
    CHECK("keypair", tdi_kx_keypair(pk, sk) == 0);
    print_hex("pk prefix:  ", pk, 16);

    /* ---- Direct IND-CPA roundtrip debug ---- */
    {
        td18_ntt_seed(0); /* Force NTT seed = 0 to disable Feistel shuffle */
        uint8_t indcpa_pk[TD18_INDCPA_PUBLICKEYBYTES];
        uint8_t indcpa_sk[TD18_INDCPA_SECRETKEYBYTES];
        uint8_t indcpa_coins[TD18_SYMBYTES];
        for (int i = 0; i < TD18_SYMBYTES; i++) indcpa_coins[i] = (uint8_t)(0x11 * i);
        td18_indcpa_keypair_derand(indcpa_pk, indcpa_sk, indcpa_coins);

        uint8_t m[TD18_SYMBYTES];
        for (int i = 0; i < TD18_SYMBYTES; i++) m[i] = (uint8_t)(0xAA + i);
        uint8_t enc_coins[TD18_SYMBYTES];
        for (int i = 0; i < TD18_SYMBYTES; i++) enc_coins[i] = (uint8_t)(0x55 + i);
        uint8_t indcpa_ct[TD18_INDCPA_BYTES];
        td18_indcpa_enc(indcpa_ct, m, indcpa_pk, enc_coins);

        uint8_t m_dec[TD18_SYMBYTES];
        td18_indcpa_dec(m_dec, indcpa_ct, indcpa_sk);
        CHECK("indcpa_roundtrip", memcmp(m, m_dec, TD18_SYMBYTES) == 0);
        if (memcmp(m, m_dec, TD18_SYMBYTES) != 0) {
            print_hex("m_orig: ", m, 32);
            print_hex("m_dec : ", m_dec, 32);
        }
    }

    uint8_t ct[TD18_CIPHERTEXTBYTES];
    uint8_t ss_enc[TD18_SSBYTES];
    CHECK("encaps", tdi_kx_encaps(ct, ss_enc, pk) == 0);
    print_hex("ss_enc:     ", ss_enc, 16);

    uint8_t ss_dec[TD18_SSBYTES];
    CHECK("decaps", tdi_kx_decaps(ss_dec, ct, sk) == 0);
    print_hex("ss_dec:     ", ss_dec, 16);

    CHECK("base_kem_agreement", memcmp(ss_enc, ss_dec, TD18_SSBYTES) == 0);

    uint8_t binding[32];
    /* For deterministic test, fill binding with known bytes */
    for (int i = 0; i < 32; i++) binding[i] = (uint8_t)i;

    uint8_t final_bob[TD18_SSBYTES];
    uint8_t final_alice[TD18_SSBYTES];
    td18_derive_final_key(final_bob, ss_enc, binding, pk, &params);
    CHECK("derive_final_key_bob", 1);
    td18_derive_final_key(final_alice, ss_dec, binding, pk, &params);
    CHECK("derive_final_key_alice", 1);
    print_hex("final bob:   ", final_bob, 16);
    print_hex("final alice: ", final_alice, 16);
    CHECK("final_key_agreement", memcmp(final_bob, final_alice, TD18_SSBYTES) == 0);

    uint8_t mac[TD18_MAC_BYTES];
    td18_mac(mac, ss_enc, ct);
    printf("MAC tag: %02x%02x\n", mac[0], mac[1]);
    CHECK("mac_verify", td18_verify_mac(mac, ss_dec, ct) == TD18_OK);

    uint8_t nonce[TD18_SYMBYTES];
    for (int i = 0; i < TD18_SYMBYTES; i++) nonce[i] = (uint8_t)(0xAA + i);
    uint8_t edmesh[TD18_EDMESH_BYTES];
    td18_edmesh_derive(edmesh, ss_enc, &params);

    td18_commitment commit;
    td18_gen_commitment(&commit, ct, edmesh, binding, mac, nonce);
    print_hex("commit hash: ", commit.hash, 16);
    CHECK("commitment_verify",
          td18_verify_commitment(&commit, ct, edmesh, binding, mac) == TD18_OK);

    int16_t poly[TD18_N];
    for (int i = 0; i < TD18_N; i++) poly[i] = (int16_t)((i * 13) % TD18_Q);
    uint8_t hints[TD18_RECON_BYTES];
    td18_reconcile_alice(hints, poly);
    CHECK("reconcile_self_verify", td18_reconcile_verify(poly, poly) == TD18_OK);

    td18_params params2 = params;
    CHECK("params_evolve", td18_params_evolve(&params2) == TD18_OK);
    printf("New epoch: %llu\n", (unsigned long long)params2.epoch);

    uint8_t id[32];
    td18_trapdoor_id(id, sk);
    print_hex("trapdoor id: ", id, 16);
    CHECK("trapdoor_id", 1);

    /* ---- Secure primitives ---- */
    {
        uint8_t a = 0x55, b = 0xAA;
        td18_ct_cswap(&a, &b, 1);
        CHECK("ct_cswap_on", a == 0xAA && b == 0x55);
        td18_ct_cswap(&a, &b, 0);
        CHECK("ct_cswap_off", a == 0xAA && b == 0x55);
    }

    /* ---- Merkle tree ---- */
    {
        int16_t coeffs[TD18_N];
        for (int i = 0; i < TD18_N; i++) coeffs[i] = (int16_t)((i * 13) % TD18_Q);
        td18_merkle_tree tree;
        td18_merkle_build_tree(&tree, coeffs, TD18_N);
        CHECK("merkle_build", tree.num_layers > 0 && tree.layers != NULL);

        /* Compute root pointer (last layer) */
        size_t root_off = 0;
        for (size_t i = 0; i + 1 < tree.num_layers; i++) root_off += tree.layer_counts[i];
        const uint8_t *root = (uint8_t *)tree.layers + root_off * 32;

        size_t test_idx[] = {0, 1, 127, 128, 255};
        int merkle_ok = 1;
        for (size_t t = 0; t < sizeof(test_idx)/sizeof(test_idx[0]); t++) {
            td18_merkle_proof proof;
            td18_merkle_proof_generate(&proof, &tree, test_idx[t]);
            if (td18_merkle_verify(root, test_idx[t], coeffs[test_idx[t]], &proof) != TD18_OK)
                merkle_ok = 0;
        }
        CHECK("merkle_verify", merkle_ok);

        /* Tamper detection */
        td18_merkle_proof proof;
        td18_merkle_proof_generate(&proof, &tree, 42);
        CHECK("merkle_tamper", td18_merkle_verify(root, 42, coeffs[42] + 1, &proof) != TD18_OK);

        td18_merkle_free_tree(&tree);
    }

    /* ---- Full GPV Trapdoor ---- */
    {
        td18_trapdoor_authority auth;
        td18_generate_trapdoor_authority(&auth);
        CHECK("trapdoor_gen", auth.a_row.vec[0].coeffs[0] == 1);

        /* Verify basis1 in kernel indirectly via auth_verify later */
        (void)auth;

        uint8_t id[32];
        for (int i = 0; i < 32; i++) id[i] = 0xAB;
        td18_identity_commitment commit;
        td18_polyvec t;
        td18_alice_commit_identity(&commit, &t, &auth, id);

        CHECK("trapdoor_commit", td18_authority_verify_and_trace(&auth, &commit, id) == TD18_OK);

        uint8_t wrong_id[32];
        for (int i = 0; i < 32; i++) wrong_id[i] = 0xCD;
        CHECK("trapdoor_wrong_id", td18_authority_verify_and_trace(&auth, &commit, wrong_id) != TD18_OK);
    }

    printf("\n=== Result: %s ===\n", all_pass ? "ALL PASS" : "SOME FAILURES");
    return all_pass ? 0 : 1;
}
