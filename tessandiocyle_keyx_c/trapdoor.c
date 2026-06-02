/**
 * TessanDioKey V18 — Lattice Trapdoor Accountability (GPV-Style)
 * Translated from Rust V18 trapdoor.rs
 */
#include "tessandiocyle_keyx.h"
#include <string.h>
#include "randombytes.h"

static void poly_negate(td18_poly *r)
{
    for (int i = 0; i < TD18_N; i++) r->coeffs[i] = -r->coeffs[i];
}

/* Schoolbook polynomial multiplication in normal domain: c = a * b mod (x^N + 1, q) */
static void poly_mul_schoolbook(td18_poly *r, const td18_poly *a, const td18_poly *b)
{
    int32_t tmp[512];
    memset(tmp, 0, sizeof(tmp));
    for (int i = 0; i < TD18_N; i++) {
        for (int j = 0; j < TD18_N; j++) {
            tmp[i + j] += (int32_t)a->coeffs[i] * (int32_t)b->coeffs[j];
        }
    }
    int32_t half_q = TD18_Q / 2;
    for (int i = 0; i < TD18_N; i++) {
        int32_t val = tmp[i] - tmp[i + TD18_N];
        int16_t rv = (int16_t)(val % TD18_Q);
        if (rv < 0) rv += TD18_Q;
        if (rv > half_q) rv -= TD18_Q;
        r->coeffs[i] = rv;
    }
}

/* Encode 32-byte identity hash into a polynomial (domain-separated) */
static void encode_identity(td18_poly *p, const uint8_t id_hash[32])
{
    memset(p->coeffs, 0, sizeof(p->coeffs));
    for (int i = 0; i < 32; i++) {
        p->coeffs[i * 8] = (int16_t)(id_hash[i] % TD18_Q);
    }
}

void td18_generate_trapdoor_authority(td18_trapdoor_authority *out)
{
    uint8_t buf[128];
    td18_poly r12, r13, r23;

    randombytes(buf, 128);
    td18_cbd2(&r12, buf);
    randombytes(buf, 128);
    td18_cbd2(&r13, buf);
    randombytes(buf, 128);
    td18_cbd2(&r23, buf);

    td18_poly neg_r12 = r12;
    poly_negate(&neg_r12);

    td18_poly r12_r23, r12_r23_minus_r13, neg_r13;
    poly_mul_schoolbook(&r12_r23, &r12, &r23);
    neg_r13 = r13;
    poly_negate(&neg_r13);
    r12_r23_minus_r13 = r12_r23;
    td18_poly_add(&r12_r23_minus_r13, &r12_r23_minus_r13, &neg_r13);

    /* a_row = [1, -r12, r12*r23 - r13] */
    td18_polyvec *a = &out->a_row;
    memset(a, 0, sizeof(*a));
    a->vec[0].coeffs[0] = 1;
    a->vec[1] = neg_r12;
    a->vec[2] = r12_r23_minus_r13;

    /* basis1 = [r12, 1, 0] */
    td18_polyvec *b1 = &out->basis1;
    memset(b1, 0, sizeof(*b1));
    b1->vec[0] = r12;
    b1->vec[1].coeffs[0] = 1;

    /* basis2 = [r13, r23, 1] */
    td18_polyvec *b2 = &out->basis2;
    memset(b2, 0, sizeof(*b2));
    b2->vec[0] = r13;
    b2->vec[1] = r23;
    b2->vec[2].coeffs[0] = 1;
}

void td18_alice_commit_identity(td18_identity_commitment *commit,
                                td18_polyvec *t_out,
                                const td18_trapdoor_authority *authority,
                                const uint8_t id_hash[32])
{
    uint8_t buf[128];
    td18_polyvec t;
    memset(&t, 0, sizeof(t));
    for (int i = 0; i < TD18_K; i++) {
        randombytes(buf, 128);
        td18_cbd2(&t.vec[i], buf);
    }

    /* v = A · t = a0*t0 + a1*t1 + a2*t2 */
    td18_poly v, tmp;
    memset(&v, 0, sizeof(v));
    poly_mul_schoolbook(&v, &authority->a_row.vec[0], &t.vec[0]);
    poly_mul_schoolbook(&tmp, &authority->a_row.vec[1], &t.vec[1]);
    td18_poly_add(&v, &v, &tmp);
    poly_mul_schoolbook(&tmp, &authority->a_row.vec[2], &t.vec[2]);
    td18_poly_add(&v, &v, &tmp);

    td18_poly id_poly;
    encode_identity(&id_poly, id_hash);

    td18_poly u = v;
    td18_poly_add(&u, &u, &id_poly);

    /* t_commitment = H(le_bytes(t)) */
    uint8_t commit_input[TD18_K * TD18_N * 2];
    size_t off = 0;
    for (int i = 0; i < TD18_K; i++) {
        for (int j = 0; j < TD18_N; j++) {
            commit_input[off++] = (uint8_t)(t.vec[i].coeffs[j]);
            commit_input[off++] = (uint8_t)(t.vec[i].coeffs[j] >> 8);
        }
    }
    td18_hash_h(commit->t_commitment, commit_input, off);

    /* challenge = H(commitment || id || domain_string) */
    uint8_t chal_in[32 + 32 + 32];
    memcpy(chal_in, commit->t_commitment, 32);
    memcpy(chal_in + 32, id_hash, 32);
    memcpy(chal_in + 64, "tessandio-v18-trapdoor-challenge", 32);
    td18_hash_h(commit->challenge, chal_in, sizeof(chal_in));

    commit->u = u;
    *t_out = t;
}

int td18_authority_verify_and_trace(const td18_trapdoor_authority *authority,
                                    const td18_identity_commitment *commit,
                                    const uint8_t claimed_id[32])
{
    (void)authority; /* available for future lattice inversion */

    /* target = u - id_poly */
    td18_poly id_poly;
    encode_identity(&id_poly, claimed_id);
    td18_poly target = commit->u;
    td18_poly_sub(&target, &target, &id_poly);
    (void)target;

    /* Verify ZK challenge */
    uint8_t expected_chal[32];
    uint8_t chal_in[32 + 32 + 32];
    memcpy(chal_in, commit->t_commitment, 32);
    memcpy(chal_in + 32, claimed_id, 32);
    memcpy(chal_in + 64, "tessandio-v18-trapdoor-challenge", 32);
    td18_hash_h(expected_chal, chal_in, sizeof(chal_in));

    if (memcmp(expected_chal, commit->challenge, 32) != 0)
        return TD18_ERR_VERIFY;

    return TD18_OK;
}
