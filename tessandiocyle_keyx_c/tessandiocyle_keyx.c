/**
 * TessanDioKey V18 — Main API (native C)
 * Thin convenience wrappers over the internal modules.
 */
#include "tessandiocyle_keyx.h"
#include <string.h>
#include "randombytes.h"

/* ---------- Core KEM entry points ---------- */

int tdi_kx_keypair(uint8_t pk[TD18_PUBLICKEYBYTES], uint8_t sk[TD18_SECRETKEYBYTES])
{
    uint8_t coins[2 * TD18_SYMBYTES];
    randombytes(coins, sizeof(coins));
    td18_kem_keypair_derand(pk, sk, coins);
    return 0;
}

int tdi_kx_encaps(uint8_t ct[TD18_CIPHERTEXTBYTES], uint8_t ss[TD18_SSBYTES],
                  const uint8_t pk[TD18_PUBLICKEYBYTES])
{
    uint8_t coins[TD18_SYMBYTES];
    randombytes(coins, sizeof(coins));
    td18_kem_enc_derand(ct, ss, pk, coins);
    return 0;
}

int tdi_kx_decaps(uint8_t ss[TD18_SSBYTES], const uint8_t ct[TD18_CIPHERTEXTBYTES],
                  const uint8_t sk[TD18_SECRETKEYBYTES])
{
    td18_kem_dec(ss, ct, sk);
    return 0;
}

/* ---------- Params wrappers (legacy naming) ---------- */

int tdi_kx_params_init(tdi_kx_params *p)
{
    return td18_params_init((td18_params *)p);
}

int tdi_kx_params_evolve(tdi_kx_params *p)
{
    return td18_params_evolve((td18_params *)p);
}

/* ---------- EDMesh wrapper ---------- */

int tdi_kx_edmesh_derive(uint8_t out[TD18_EDMESH_BYTES], const uint8_t seed[TD18_SYMBYTES],
                         const tdi_kx_params *p)
{
    td18_edmesh_derive(out, seed, (const td18_params *)p);
    return 0;
}

/* ---------- VDF wrapper ---------- */

int tdi_kx_evolve_epoch_seed(uint8_t seed[TD18_SYMBYTES], uint32_t work_factor)
{
    td18_vdf_hash(seed, work_factor);
    return 0;
}

/* ---------- Reconcile wrappers ---------- */

int tdi_kx_reconcile_alice(uint8_t hints[TD18_RECON_BYTES], const int16_t v[TD18_N])
{
    td18_reconcile_alice(hints, v);
    return 0;
}

int tdi_kx_reconcile_verify(const int16_t va[TD18_N], const int16_t vb[TD18_N])
{
    return td18_reconcile_verify(va, vb);
}

/* ---------- Hybrid binding ---------- */

int tdi_kx_hybrid_bind(uint8_t out[32], const uint8_t binding[32], const uint8_t pk[TD18_PUBLICKEYBYTES])
{
    td18_hybrid_bind(out, binding, pk);
    return 0;
}

/* ---------- MAC ---------- */

int tdi_kx_mac(uint8_t mac[TD18_MAC_BYTES], const uint8_t ss[TD18_SSBYTES], const uint8_t ct[TD18_CIPHERTEXTBYTES])
{
    td18_mac(mac, ss, ct);
    return 0;
}

int tdi_kx_verify_mac(const uint8_t mac[TD18_MAC_BYTES], const uint8_t ss[TD18_SSBYTES], const uint8_t ct[TD18_CIPHERTEXTBYTES])
{
    return td18_verify_mac(mac, ss, ct);
}

/* ---------- Commitment ---------- */

int tdi_kx_generate_commitment(tdi_kx_commitment *commit,
                               const uint8_t ct[TD18_CIPHERTEXTBYTES],
                               const uint8_t edmesh[TD18_EDMESH_BYTES],
                               const uint8_t binding[32],
                               const uint8_t mac_tag[TD18_MAC_BYTES],
                               const uint8_t nonce[TD18_SYMBYTES])
{
    td18_gen_commitment((td18_commitment *)commit, ct, edmesh, binding, mac_tag, nonce);
    return 0;
}

int tdi_kx_verify_commitment(const tdi_kx_commitment *commit,
                             const uint8_t ct[TD18_CIPHERTEXTBYTES],
                             const uint8_t edmesh[TD18_EDMESH_BYTES],
                             const uint8_t binding[32],
                             const uint8_t mac_tag[TD18_MAC_BYTES])
{
    return td18_verify_commitment((const td18_commitment *)commit, ct, edmesh, binding, mac_tag);
}

/* ---------- Final key ---------- */

int tdi_kx_derive_final_key(uint8_t final_key[TD18_SSBYTES],
                            const uint8_t base_ss[TD18_SSBYTES],
                            const uint8_t binding[32],
                            const uint8_t pk[TD18_PUBLICKEYBYTES],
                            const tdi_kx_params *p)
{
    td18_derive_final_key(final_key, base_ss, binding, pk, (const td18_params *)p);
    return 0;
}

/* ---------- Trapdoor ---------- */

int tdi_kx_extract_trapdoor_id(uint8_t id[32], const uint8_t sk[TD18_SECRETKEYBYTES])
{
    td18_trapdoor_id(id, sk);
    return 0;
}
