#include "params.hpp"
#include "kem.hpp"
#include "protocol.hpp"
#include "graph.hpp"
#include "reconcile.hpp"
#include "merkle.hpp"
#include "trapdoor.hpp"
#include "secure.hpp"
#include "ntt.hpp"
#include "indcpa.hpp"
#include "random.hpp"
#include <cstdio>
#include <cstring>

using namespace td18;

static int all_pass = 1;
#define CHECK(name, cond) do { \
    if (!(cond)) { printf("[FAIL] %s\n", name); all_pass = 0; } \
    else          { printf("[PASS] %s\n", name); } \
} while(0)

int main() {
    printf("=== TessanDioKey V18 C++ Native Test ===\n\n");

    Params params;
    CHECK("params_init", params_init(params) == 0);
    printf("Epoch: %llu\n", (unsigned long long)params.epoch);

    std::array<uint8_t,PUBLICKEYBYTES> pk;
    std::array<uint8_t,SECRETKEYBYTES> sk;
    std::array<uint8_t,2*SYMBYTES> coins;
    randombytes(coins.data(), coins.size());
    kem_keypair_derand(pk, sk, coins);
    printf("pk prefix:  ");
    for (int i = 0; i < 16; ++i) printf("%02x", pk[i]); printf("\n");
    CHECK("keypair", 1);

    /* IND-CPA roundtrip deterministic */
    {
        ntt_seed(0);
        std::array<uint8_t,INDCPA_PUBLICKEYBYTES> indcpa_pk;
        std::array<uint8_t,INDCPA_SECRETKEYBYTES> indcpa_sk;
        std::array<uint8_t,SYMBYTES> indcpa_coins;
        for (int i = 0; i < SYMBYTES; ++i) indcpa_coins[i] = static_cast<uint8_t>(0x11 * i);
        indcpa_keypair_derand(indcpa_pk, indcpa_sk, indcpa_coins);

        std::array<uint8_t,SYMBYTES> m, enc_coins;
        for (int i = 0; i < SYMBYTES; ++i) m[i] = static_cast<uint8_t>(0xAA + i);
        for (int i = 0; i < SYMBYTES; ++i) enc_coins[i] = static_cast<uint8_t>(0x55 + i);
        std::array<uint8_t,INDCPA_BYTES> indcpa_ct;
        ntt_seed(0);
        indcpa_enc(indcpa_ct, m, indcpa_pk, enc_coins);

        std::array<uint8_t,SYMBYTES> m_dec;
        ntt_seed(0);
        indcpa_dec(m_dec, indcpa_ct, indcpa_sk);
        CHECK("indcpa_roundtrip", m == m_dec);
    }

    std::array<uint8_t,CIPHERTEXTBYTES> ct;
    std::array<uint8_t,SSBYTES> ss_enc;
    kem_enc(ct, ss_enc, pk);
    printf("ss_enc:     ");
    for (int i = 0; i < 16; ++i) printf("%02x", ss_enc[i]); printf("\n");
    CHECK("encaps", 1);

    std::array<uint8_t,SSBYTES> ss_dec;
    kem_dec(ss_dec, ct, sk);
    printf("ss_dec:     ");
    for (int i = 0; i < 16; ++i) printf("%02x", ss_dec[i]); printf("\n");
    CHECK("decaps", 1);

    CHECK("base_kem_agreement", ss_enc == ss_dec);

    std::array<uint8_t,32> binding;
    for (int i = 0; i < 32; ++i) binding[i] = static_cast<uint8_t>(i);

    std::array<uint8_t,SSBYTES> final_bob, final_alice;
    derive_final_key(final_bob, ss_enc, binding, pk, params);
    derive_final_key(final_alice, ss_dec, binding, pk, params);
    printf("final bob:   ");
    for (int i = 0; i < 16; ++i) printf("%02x", final_bob[i]); printf("\n");
    printf("final alice: ");
    for (int i = 0; i < 16; ++i) printf("%02x", final_alice[i]); printf("\n");
    CHECK("final_key_agreement", final_bob == final_alice);

    std::array<uint8_t,MAC_BYTES> mac_tag;
    mac(mac_tag, ss_enc, ct);
    printf("MAC tag: %02x%02x\n", mac_tag[0], mac_tag[1]);
    CHECK("mac_verify", verify_mac(mac_tag, ss_dec, ct) == 0);

    std::array<uint8_t,SYMBYTES> nonce;
    for (int i = 0; i < SYMBYTES; ++i) nonce[i] = static_cast<uint8_t>(0xAA + i);
    std::array<uint8_t,EDMESH_BYTES> edmesh;
    edmesh_derive(edmesh, ss_enc, params);

    Commitment commit;
    gen_commitment(commit, ct, edmesh, binding, mac_tag, nonce);
    printf("commit hash: ");
    for (int i = 0; i < 16; ++i) printf("%02x", commit.hash[i]); printf("\n");
    CHECK("commitment_verify", verify_commitment(commit, ct, edmesh, binding, mac_tag) == 0);

    Poly poly;
    for (int i = 0; i < N; ++i) poly[i] = static_cast<int16_t>((i * 13) % Q);
    std::array<uint8_t,RECON_BYTES> hints;
    reconcile_alice(hints, poly);
    CHECK("reconcile_self_verify", reconcile_verify(poly, poly) == 0);

    Params params2 = params;
    CHECK("params_evolve", params_evolve(params2) == 0);
    printf("New epoch: %llu\n", (unsigned long long)params2.epoch);

    std::array<uint8_t,32> id;
    trapdoor_id(id, sk);
    printf("trapdoor id: ");
    for (int i = 0; i < 16; ++i) printf("%02x", id[i]); printf("\n");
    CHECK("trapdoor_id", 1);

    /* Secure primitives */
    {
        uint8_t a = 0x55, b = 0xAA;
        ct_cswap(&a, &b, 1);
        CHECK("ct_cswap_on", a == 0xAA && b == 0x55);
        ct_cswap(&a, &b, 0);
        CHECK("ct_cswap_off", a == 0xAA && b == 0x55);
    }

    /* Merkle */
    {
        Poly coeffs;
        for (int i = 0; i < N; ++i) coeffs[i] = static_cast<int16_t>((i * 13) % Q);
        auto tree = merkle_build_tree(coeffs);
        CHECK("merkle_build", !tree.layers.empty());

        auto root = tree.layers.back()[0];
        size_t test_idx[] = {0, 1, 127, 128, 255};
        int merkle_ok = 1;
        for (auto idx : test_idx) {
            auto proof = merkle_proof(tree, idx);
            if (merkle_verify(root, idx, coeffs[idx], proof) != 0) merkle_ok = 0;
        }
        CHECK("merkle_verify", merkle_ok);

        auto proof = merkle_proof(tree, 42);
        CHECK("merkle_tamper", merkle_verify(root, 42, coeffs[42] + 1, proof) != 0);
    }

    /* Trapdoor */
    {
        TrapdoorAuthority auth;
        generate_trapdoor_authority(auth);
        CHECK("trapdoor_gen", auth.a_row[0][0] == 1);

        std::array<uint8_t,32> id_hash;
        id_hash.fill(0xAB);
        IdentityCommitment commit2;
        PolyVec t;
        alice_commit_identity(commit2, t, auth, id_hash);
        CHECK("trapdoor_commit", authority_verify_and_trace(auth, commit2, id_hash) == 0);

        std::array<uint8_t,32> wrong_id;
        wrong_id.fill(0xCD);
        CHECK("trapdoor_wrong_id", authority_verify_and_trace(auth, commit2, wrong_id) != 0);
    }

    printf("\n=== Result: %s ===\n", all_pass ? "ALL PASS" : "SOME FAILURES");
    return all_pass ? 0 : 1;
}
