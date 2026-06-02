/**
 * TessanDioKey V18 — Native C Implementation
 * Translated directly from Rust V18 sources.
 * Uses SHAKE-256 instead of BLAKE3 (structurally identical; bytes differ).
 */
#ifndef TESSANDIOCYLE_KEYX_H
#define TESSANDIOCYLE_KEYX_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ==================== Parameters ==================== */
#define TD18_K           3
#define TD18_N           256
#define TD18_Q           3329

#define TD18_SYMBYTES    32
#define TD18_SSBYTES     32

#define TD18_POLYBYTES   384
#define TD18_POLYVECBYTES (TD18_K * TD18_POLYBYTES)

#define TD18_POLYCOMPRESSEDBYTES    128
#define TD18_POLYVECCOMPRESSEDBYTES (TD18_K * 320)

#define TD18_INDCPA_PUBLICKEYBYTES  (TD18_POLYVECBYTES + TD18_SYMBYTES)
#define TD18_INDCPA_SECRETKEYBYTES  (TD18_POLYVECBYTES)
#define TD18_INDCPA_BYTES           (TD18_POLYVECCOMPRESSEDBYTES + TD18_POLYCOMPRESSEDBYTES)

#define TD18_PUBLICKEYBYTES   TD18_INDCPA_PUBLICKEYBYTES
#define TD18_SECRETKEYBYTES   (TD18_INDCPA_SECRETKEYBYTES + TD18_INDCPA_PUBLICKEYBYTES + 2*TD18_SYMBYTES)
#define TD18_CIPHERTEXTBYTES  TD18_INDCPA_BYTES

#define TD18_RECON_BYTES      144
#define TD18_GRAPH_NODES      256
#define TD18_GRAPH_DEGREE     12
#define TD18_EDMESH_BYTES     64
#define TD18_BIND_BYTES       32
#define TD18_MAC_BYTES        2

#define TD18_QINV  (-3327)
#define TD18_MONT  (-1044)

/* ==================== Error codes ==================== */
typedef enum {
    TD18_OK = 0,
    TD18_ERR_INVALID = -1,
    TD18_ERR_VERIFY  = -2,
} td18_err;

/* ==================== Types ==================== */
typedef struct { int16_t coeffs[TD18_N]; } td18_poly;
typedef struct { td18_poly vec[TD18_K]; } td18_polyvec;

typedef struct {
    uint8_t graph_seeds[TD18_K][TD18_SYMBYTES];
    uint16_t starts[TD18_K];
    uint8_t epoch_seed[TD18_SYMBYTES];
    uint64_t epoch;
} td18_params;

typedef struct {
    uint8_t hash[32];
    uint8_t nonce[32];
} td18_commitment;

/* Legacy naming compatibility */
typedef td18_params tdi_kx_params;
typedef td18_commitment tdi_kx_commitment;

#define TDI_KX_PUBLICKEYBYTES        TD18_PUBLICKEYBYTES
#define TDI_KX_SECRETKEYBYTES        TD18_SECRETKEYBYTES
#define TDI_KX_CIPHERTEXTBYTES       TD18_CIPHERTEXTBYTES
#define TDI_KX_SSBYTES               TD18_SSBYTES
#define TDI_KX_EDMESH_BYTES          TD18_EDMESH_BYTES
#define TDI_KX_HYBRID_BINDING_BYTES  TD18_BIND_BYTES
#define TDI_KX_MAC_BYTES             TD18_MAC_BYTES
#define TDI_KX_SYMBYTES              TD18_SYMBYTES
#define TDI_KX_RECONCILE_TOTAL_BYTES TD18_RECON_BYTES
#define TDI_KX_OK                    TD18_OK

/* ==================== Low-level arithmetic ==================== */
int16_t td18_montgomery_reduce(int32_t a);
int16_t td18_barrett_reduce(int16_t a);

/* NTT with Feistel shuffle */
void td18_ntt_seed(uint64_t seed);
void td18_ntt(int16_t r[TD18_N]);
void td18_invntt(int16_t r[TD18_N]);
void td18_basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta);

/* CBD */
void td18_cbd2(td18_poly *r, const uint8_t buf[128]);
void td18_poly_getnoise_eta1(td18_poly *r, const uint8_t seed[TD18_SYMBYTES], uint8_t nonce);
void td18_poly_getnoise_eta2(td18_poly *r, const uint8_t seed[TD18_SYMBYTES], uint8_t nonce);

/* Verify / cmov */
uint8_t td18_verify(const uint8_t *a, const uint8_t *b, size_t len);
void td18_cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b);

/* Symmetric (SHAKE-based, structurally matching Rust V18) */
void td18_hash_h(uint8_t out[32], const uint8_t *in, size_t inlen);
void td18_hash_g(uint8_t out[64], const uint8_t *in, size_t inlen);
void td18_xof(const uint8_t seed[TD18_SYMBYTES], uint8_t x, uint8_t y, uint8_t *out, size_t outlen);
void td18_prf(uint8_t *out, size_t outlen, const uint8_t key[TD18_SYMBYTES], uint8_t nonce);
void td18_rkprf(uint8_t out[32], const uint8_t key[32], const uint8_t *in, size_t inlen);

/* ==================== Polynomial ==================== */
void td18_poly_compress(uint8_t r[TD18_POLYCOMPRESSEDBYTES], const td18_poly *a);
void td18_poly_decompress(td18_poly *r, const uint8_t a[TD18_POLYCOMPRESSEDBYTES]);
void td18_poly_tobytes(uint8_t r[TD18_POLYBYTES], const td18_poly *a);
void td18_poly_frombytes(td18_poly *r, const uint8_t a[TD18_POLYBYTES]);
void td18_poly_frommsg(td18_poly *r, const uint8_t msg[TD18_SYMBYTES]);
void td18_poly_tomsg(uint8_t msg[TD18_SYMBYTES], const td18_poly *a);

void td18_poly_ntt(td18_poly *r);
void td18_poly_invntt_tomont(td18_poly *r);
void td18_poly_basemul_montgomery(td18_poly *r, const td18_poly *a, const td18_poly *b);
void td18_poly_tomont(td18_poly *r);
void td18_poly_reduce(td18_poly *r);
void td18_poly_add(td18_poly *r, const td18_poly *a, const td18_poly *b);
void td18_poly_sub(td18_poly *r, const td18_poly *a, const td18_poly *b);

/* ==================== PolyVec ==================== */
void td18_polyvec_compress(uint8_t r[TD18_POLYVECCOMPRESSEDBYTES], const td18_polyvec *a);
void td18_polyvec_decompress(td18_polyvec *r, const uint8_t a[TD18_POLYVECCOMPRESSEDBYTES]);
void td18_polyvec_tobytes(uint8_t r[TD18_POLYVECBYTES], const td18_polyvec *a);
void td18_polyvec_frombytes(td18_polyvec *r, const uint8_t a[TD18_POLYVECBYTES]);

void td18_polyvec_ntt(td18_polyvec *r);
void td18_polyvec_invntt_tomont(td18_polyvec *r);
void td18_polyvec_basemul_acc_montgomery(td18_poly *r, const td18_polyvec *a, const td18_polyvec *b);
void td18_polyvec_reduce(td18_polyvec *r);
void td18_polyvec_add(td18_polyvec *r, const td18_polyvec *a, const td18_polyvec *b);

/* ==================== IND-CPA ==================== */
void td18_indcpa_keypair_derand(uint8_t pk[TD18_INDCPA_PUBLICKEYBYTES],
                                uint8_t sk[TD18_INDCPA_SECRETKEYBYTES],
                                const uint8_t coins[TD18_SYMBYTES]);
void td18_indcpa_enc(uint8_t c[TD18_INDCPA_BYTES],
                     const uint8_t m[TD18_SYMBYTES],
                     const uint8_t pk[TD18_INDCPA_PUBLICKEYBYTES],
                     const uint8_t coins[TD18_SYMBYTES]);
void td18_indcpa_dec(uint8_t m[TD18_SYMBYTES],
                     const uint8_t c[TD18_INDCPA_BYTES],
                     const uint8_t sk[TD18_INDCPA_SECRETKEYBYTES]);

/* ==================== CCA KEM ==================== */
void td18_kem_keypair_derand(uint8_t pk[TD18_PUBLICKEYBYTES],
                             uint8_t sk[TD18_SECRETKEYBYTES],
                             const uint8_t coins[2*TD18_SYMBYTES]);
void td18_kem_enc_derand(uint8_t ct[TD18_CIPHERTEXTBYTES],
                         uint8_t ss[TD18_SSBYTES],
                         const uint8_t pk[TD18_PUBLICKEYBYTES],
                         const uint8_t coins[TD18_SYMBYTES]);
void td18_kem_enc(uint8_t ct[TD18_CIPHERTEXTBYTES],
                  uint8_t ss[TD18_SSBYTES],
                  const uint8_t pk[TD18_PUBLICKEYBYTES]);
void td18_kem_dec(uint8_t ss[TD18_SSBYTES],
                  const uint8_t ct[TD18_CIPHERTEXTBYTES],
                  const uint8_t sk[TD18_SECRETKEYBYTES]);

/* ==================== Graph / EDMesh ==================== */
void td18_graph_from_seed(const uint8_t seed[32],
                          uint16_t adj[TD18_GRAPH_NODES][TD18_GRAPH_DEGREE],
                          uint8_t deg[TD18_GRAPH_NODES]);
void td18_edmesh_derive(uint8_t out[TD18_EDMESH_BYTES],
                        const uint8_t seed[TD18_SYMBYTES],
                        const td18_params *p);

/* ==================== Reconciliation ==================== */
void td18_reconcile_alice(uint8_t hints[TD18_RECON_BYTES], const int16_t v[TD18_N]);
int  td18_reconcile_verify(const int16_t va[TD18_N], const int16_t vb[TD18_N]);

/* ==================== Protocol ==================== */
int td18_params_init(td18_params *p);
int td18_params_evolve(td18_params *p);
void td18_hybrid_bind(uint8_t out[32], const uint8_t binding[32], const uint8_t pk[TD18_PUBLICKEYBYTES]);
void td18_mac(uint8_t mac[TD18_MAC_BYTES], const uint8_t ss[TD18_SSBYTES], const uint8_t ct[TD18_CIPHERTEXTBYTES]);
int  td18_verify_mac(const uint8_t mac[TD18_MAC_BYTES], const uint8_t ss[TD18_SSBYTES], const uint8_t ct[TD18_CIPHERTEXTBYTES]);

void td18_gen_commitment(td18_commitment *commit,
                         const uint8_t ct[TD18_CIPHERTEXTBYTES],
                         const uint8_t edmesh[TD18_EDMESH_BYTES],
                         const uint8_t binding[32],
                         const uint8_t mac_tag[TD18_MAC_BYTES],
                         const uint8_t nonce[TD18_SYMBYTES]);
int  td18_verify_commitment(const td18_commitment *commit,
                            const uint8_t ct[TD18_CIPHERTEXTBYTES],
                            const uint8_t edmesh[TD18_EDMESH_BYTES],
                            const uint8_t binding[32],
                            const uint8_t mac_tag[TD18_MAC_BYTES]);

void td18_derive_final_key(uint8_t final_key[TD18_SSBYTES],
                           const uint8_t base_ss[TD18_SSBYTES],
                           const uint8_t binding[32],
                           const uint8_t pk[TD18_PUBLICKEYBYTES],
                           const td18_params *p);

/* ==================== Trapdoor ==================== */
typedef struct {
    td18_polyvec a_row;
    td18_polyvec basis1;
    td18_polyvec basis2;
} td18_trapdoor_authority;

typedef struct {
    td18_poly u;
    uint8_t challenge[32];
    uint8_t t_commitment[32];
} td18_identity_commitment;

void td18_generate_trapdoor_authority(td18_trapdoor_authority *out);
void td18_alice_commit_identity(td18_identity_commitment *commit,
                                td18_polyvec *t_out,
                                const td18_trapdoor_authority *authority,
                                const uint8_t id_hash[32]);
int  td18_authority_verify_and_trace(const td18_trapdoor_authority *authority,
                                     const td18_identity_commitment *commit,
                                     const uint8_t claimed_id[32]);

/* ==================== Merkle ==================== */
typedef struct {
    uint8_t (*layers)[32];
    size_t *layer_counts;
    size_t num_layers;
} td18_merkle_tree;

typedef struct {
    size_t sibling_idx;
    uint8_t hash[32];
} td18_merkle_proof_step;

typedef struct {
    td18_merkle_proof_step steps[8];
    size_t num_steps;
} td18_merkle_proof;

void td18_merkle_build_tree(td18_merkle_tree *tree, const int16_t coeffs[], size_t n);
void td18_merkle_free_tree(td18_merkle_tree *tree);
void td18_merkle_proof_generate(td18_merkle_proof *proof,
                                const td18_merkle_tree *tree,
                                size_t index);
int  td18_merkle_verify(const uint8_t root[32],
                        size_t index,
                        int16_t coeff,
                        const td18_merkle_proof *proof);

/* ==================== Secure ==================== */
void td18_secure_zero(void *p, size_t len);
void td18_secure_copy(uint8_t *dst, const uint8_t *src, size_t len);
void td18_ct_cswap(uint8_t *a, uint8_t *b, uint8_t swap);

/* VDF sequential hash proxy */
void td18_vdf_hash(uint8_t seed[32], uint32_t iterations);

/* Trapdoor id stub (now just hashes sk prefix) */
void td18_trapdoor_id(uint8_t id[32], const uint8_t sk[TD18_SECRETKEYBYTES]);

/* ---------- Legacy convenient wrappers (still supported) ---------- */
int tdi_kx_keypair(uint8_t pk[TD18_PUBLICKEYBYTES], uint8_t sk[TD18_SECRETKEYBYTES]);
int tdi_kx_encaps(uint8_t ct[TD18_CIPHERTEXTBYTES], uint8_t ss[TD18_SSBYTES],
                  const uint8_t pk[TD18_PUBLICKEYBYTES]);
int tdi_kx_decaps(uint8_t ss[TD18_SSBYTES], const uint8_t ct[TD18_CIPHERTEXTBYTES],
                  const uint8_t sk[TD18_SECRETKEYBYTES]);

int tdi_kx_params_init(tdi_kx_params *p);
int tdi_kx_params_evolve(tdi_kx_params *p);
int tdi_kx_edmesh_derive(uint8_t out[TD18_EDMESH_BYTES], const uint8_t seed[TD18_SYMBYTES],
                         const tdi_kx_params *p);
int tdi_kx_evolve_epoch_seed(uint8_t seed[TD18_SYMBYTES], uint32_t work_factor);
int tdi_kx_reconcile_alice(uint8_t hints[TD18_RECON_BYTES], const int16_t v[TD18_N]);
int tdi_kx_reconcile_verify(const int16_t va[TD18_N], const int16_t vb[TD18_N]);
int tdi_kx_hybrid_bind(uint8_t out[32], const uint8_t binding[32], const uint8_t pk[TD18_PUBLICKEYBYTES]);
int tdi_kx_mac(uint8_t mac[TD18_MAC_BYTES], const uint8_t ss[TD18_SSBYTES], const uint8_t ct[TD18_CIPHERTEXTBYTES]);
int tdi_kx_verify_mac(const uint8_t mac[TD18_MAC_BYTES], const uint8_t ss[TD18_SSBYTES], const uint8_t ct[TD18_CIPHERTEXTBYTES]);
int tdi_kx_generate_commitment(tdi_kx_commitment *commit,
                               const uint8_t ct[TD18_CIPHERTEXTBYTES],
                               const uint8_t edmesh[TD18_EDMESH_BYTES],
                               const uint8_t binding[32],
                               const uint8_t mac_tag[TD18_MAC_BYTES],
                               const uint8_t nonce[TD18_SYMBYTES]);
int tdi_kx_verify_commitment(const tdi_kx_commitment *commit,
                             const uint8_t ct[TD18_CIPHERTEXTBYTES],
                             const uint8_t edmesh[TD18_EDMESH_BYTES],
                             const uint8_t binding[32],
                             const uint8_t mac_tag[TD18_MAC_BYTES]);
int tdi_kx_derive_final_key(uint8_t final_key[TD18_SSBYTES],
                            const uint8_t base_ss[TD18_SSBYTES],
                            const uint8_t binding[32],
                            const uint8_t pk[TD18_PUBLICKEYBYTES],
                            const tdi_kx_params *p);
int tdi_kx_extract_trapdoor_id(uint8_t id[32], const uint8_t sk[TD18_SECRETKEYBYTES]);

#ifdef __cplusplus
}
#endif

#endif
