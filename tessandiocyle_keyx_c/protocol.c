/**
 * TessanDioKey V18 — Protocol layer (params, commitment, MAC, binding, final key)
 */
#include "tessandiocyle_keyx.h"
#include <string.h>
#include "randombytes.h"

/* ---------- Params ---------- */
int td18_params_init(td18_params *p)
{
    if (!p) return TD18_ERR_INVALID;
    randombytes(p->epoch_seed, TD18_SYMBYTES);
    randombytes((uint8_t *)p->graph_seeds, TD18_K * TD18_SYMBYTES);
    uint8_t buf[8];
    for (int i = 0; i < TD18_K; i++) {
        randombytes(buf, 8);
        uint64_t s = 0;
        for (int j = 0; j < 8; j++) s |= ((uint64_t)buf[j]) << (8 * j);
        p->starts[i] = (uint16_t)(s % TD18_GRAPH_NODES);
    }
    p->epoch = 0;
    return TD18_OK;
}

int td18_params_evolve(td18_params *p)
{
    if (!p) return TD18_ERR_INVALID;
    for (int i = 0; i < TD18_K; i++)
        td18_vdf_hash(p->graph_seeds[i], 1u << 18);
    uint8_t buf[8];
    for (int i = 0; i < TD18_K; i++) {
        randombytes(buf, 8);
        uint64_t s = 0;
        for (int j = 0; j < 8; j++) s |= ((uint64_t)buf[j]) << (8 * j);
        p->starts[i] = (uint16_t)(s % TD18_GRAPH_NODES);
    }
    p->epoch++;
    return TD18_OK;
}

/* ---------- Hybrid Binding ---------- */
void td18_hybrid_bind(uint8_t out[32], const uint8_t binding[32], const uint8_t pk[TD18_PUBLICKEYBYTES])
{
    uint8_t in[32 + TD18_PUBLICKEYBYTES];
    memcpy(in, binding, 32);
    memcpy(in + 32, pk, TD18_PUBLICKEYBYTES);
    td18_hash_h(out, in, sizeof(in));
}

/* ---------- MAC ---------- */
void td18_mac(uint8_t mac[TD18_MAC_BYTES], const uint8_t ss[TD18_SSBYTES], const uint8_t ct[TD18_CIPHERTEXTBYTES])
{
    uint8_t in[TD18_SSBYTES + TD18_CIPHERTEXTBYTES + 18];
    memcpy(in, ss, TD18_SSBYTES);
    memcpy(in + TD18_SSBYTES, ct, TD18_CIPHERTEXTBYTES);
    memcpy(in + TD18_SSBYTES + TD18_CIPHERTEXTBYTES, "tessandio-v18-mac", 17);
    uint8_t hash[32];
    td18_hash_h(hash, in, TD18_SSBYTES + TD18_CIPHERTEXTBYTES + 17);
    mac[0] = hash[0];
    mac[1] = hash[1];
}

int td18_verify_mac(const uint8_t mac[TD18_MAC_BYTES], const uint8_t ss[TD18_SSBYTES], const uint8_t ct[TD18_CIPHERTEXTBYTES])
{
    uint8_t expected[TD18_MAC_BYTES];
    td18_mac(expected, ss, ct);
    return (mac[0] == expected[0] && mac[1] == expected[1]) ? TD18_OK : TD18_ERR_VERIFY;
}

/* ---------- Commitment ---------- */
void td18_gen_commitment(td18_commitment *commit,
                         const uint8_t ct[TD18_CIPHERTEXTBYTES],
                         const uint8_t edmesh[TD18_EDMESH_BYTES],
                         const uint8_t binding[32],
                         const uint8_t mac_tag[TD18_MAC_BYTES],
                         const uint8_t nonce[TD18_SYMBYTES])
{
    uint8_t in[TD18_CIPHERTEXTBYTES + TD18_EDMESH_BYTES + 32 + TD18_MAC_BYTES + TD18_SYMBYTES];
    size_t off = 0;
    memcpy(in + off, ct, TD18_CIPHERTEXTBYTES); off += TD18_CIPHERTEXTBYTES;
    memcpy(in + off, edmesh, TD18_EDMESH_BYTES); off += TD18_EDMESH_BYTES;
    memcpy(in + off, binding, 32); off += 32;
    memcpy(in + off, mac_tag, TD18_MAC_BYTES); off += TD18_MAC_BYTES;
    memcpy(in + off, nonce, TD18_SYMBYTES); off += TD18_SYMBYTES;
    td18_hash_h(commit->hash, in, off);
    memcpy(commit->nonce, nonce, TD18_SYMBYTES);
}

int td18_verify_commitment(const td18_commitment *commit,
                           const uint8_t ct[TD18_CIPHERTEXTBYTES],
                           const uint8_t edmesh[TD18_EDMESH_BYTES],
                           const uint8_t binding[32],
                           const uint8_t mac_tag[TD18_MAC_BYTES])
{
    uint8_t in[TD18_CIPHERTEXTBYTES + TD18_EDMESH_BYTES + 32 + TD18_MAC_BYTES + TD18_SYMBYTES];
    size_t off = 0;
    memcpy(in + off, ct, TD18_CIPHERTEXTBYTES); off += TD18_CIPHERTEXTBYTES;
    memcpy(in + off, edmesh, TD18_EDMESH_BYTES); off += TD18_EDMESH_BYTES;
    memcpy(in + off, binding, 32); off += 32;
    memcpy(in + off, mac_tag, TD18_MAC_BYTES); off += TD18_MAC_BYTES;
    memcpy(in + off, commit->nonce, TD18_SYMBYTES); off += TD18_SYMBYTES;
    uint8_t hash[32];
    td18_hash_h(hash, in, off);
    return (memcmp(hash, commit->hash, 32) == 0) ? TD18_OK : TD18_ERR_VERIFY;
}

/* ---------- Final key derivation ---------- */
void td18_derive_final_key(uint8_t final_key[TD18_SSBYTES],
                           const uint8_t base_ss[TD18_SSBYTES],
                           const uint8_t binding[32],
                           const uint8_t pk[TD18_PUBLICKEYBYTES],
                           const td18_params *p)
{
    /* Base key */
    uint8_t in0[TD18_SSBYTES + 18];
    memcpy(in0, base_ss, TD18_SSBYTES);
    memcpy(in0 + TD18_SSBYTES, "tessandio-v18-base", 18);
    uint8_t base_key[32];
    td18_hash_h(base_key, in0, sizeof(in0));

    /* Hybrid binding c */
    uint8_t c[32];
    td18_hybrid_bind(c, binding, pk);

    /* EDMesh */
    uint8_t expanded[64];
    td18_edmesh_derive(expanded, base_ss, p);

    /* Pseudo-poly + reconcile */
    uint8_t in1[TD18_SSBYTES + 24];
    memcpy(in1, base_ss, TD18_SSBYTES);
    memcpy(in1 + TD18_SSBYTES, "tessandio-v18-pseudopoly", 24);
    uint8_t poly_bytes[512];
    /* Use two hash_g calls for 512 bytes */
    uint8_t tmp64[64];
    td18_hash_g(tmp64, in1, sizeof(in1));
    memcpy(poly_bytes, tmp64, 64);
    /* Second block: hash the first output as input */
    td18_hash_g(tmp64, poly_bytes, 64);
    memcpy(poly_bytes + 64, tmp64, 64);
    td18_hash_g(tmp64, poly_bytes + 64, 64);
    memcpy(poly_bytes + 128, tmp64, 64);
    td18_hash_g(tmp64, poly_bytes + 128, 64);
    memcpy(poly_bytes + 192, tmp64, 64);
    td18_hash_g(tmp64, poly_bytes + 192, 64);
    memcpy(poly_bytes + 256, tmp64, 64);
    td18_hash_g(tmp64, poly_bytes + 256, 64);
    memcpy(poly_bytes + 320, tmp64, 64);
    td18_hash_g(tmp64, poly_bytes + 320, 64);
    memcpy(poly_bytes + 384, tmp64, 64);
    td18_hash_g(tmp64, poly_bytes + 384, 64);
    memcpy(poly_bytes + 448, tmp64, 64);

    int16_t pseudo_poly[TD18_N];
    for (int i = 0; i < TD18_N; i++) {
        uint16_t val = (uint16_t)(poly_bytes[2*i] | ((uint16_t)poly_bytes[2*i+1] << 8));
        pseudo_poly[i] = (int16_t)(val % TD18_Q);
    }
    uint8_t reconcile_data[TD18_RECON_BYTES];
    td18_reconcile_alice(reconcile_data, pseudo_poly);

    /* Overlay KDF */
    uint8_t in2[64 + 32 + 32 + TD18_RECON_BYTES + 21];
    size_t off = 0;
    memcpy(in2 + off, expanded, 64); off += 64;
    memcpy(in2 + off, c, 32); off += 32;
    memcpy(in2 + off, binding, 32); off += 32;
    memcpy(in2 + off, reconcile_data, TD18_RECON_BYTES); off += TD18_RECON_BYTES;
    memcpy(in2 + off, "tessandio-v18-overlay", 21); off += 21;
    uint8_t overlay[32];
    td18_hash_h(overlay, in2, off);

    for (int i = 0; i < 32; i++) final_key[i] = base_key[i] ^ overlay[i];
}

/* ---------- Trapdoor ID stub ---------- */
void td18_trapdoor_id(uint8_t id[32], const uint8_t sk[TD18_SECRETKEYBYTES])
{
    td18_hash_h(id, sk, TD18_POLYVECBYTES);
}
