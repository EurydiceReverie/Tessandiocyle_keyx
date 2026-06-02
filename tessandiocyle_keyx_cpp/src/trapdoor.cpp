#include "trapdoor.hpp"
#include "cbd.hpp"
#include "shake.hpp"
#include "random.hpp"
#include <cstring>
#include <vector>

namespace td18 {

static void poly_negate(Poly& r) {
    for (int i = 0; i < N; ++i) r[i] = -r[i];
}

static void poly_mul_schoolbook(Poly& r, const Poly& a, const Poly& b) {
    int32_t tmp[512] = {};
    for (int i = 0; i < N; ++i) {
        for (int j = 0; j < N; ++j) {
            tmp[i + j] += static_cast<int32_t>(a[i]) * static_cast<int32_t>(b[j]);
        }
    }
    int32_t half_q = Q / 2;
    for (int i = 0; i < N; ++i) {
        int32_t val = tmp[i] - tmp[i + N];
        int16_t rv = static_cast<int16_t>(val % Q);
        if (rv < 0) rv += Q;
        if (rv > half_q) rv -= Q;
        r[i] = rv;
    }
}

static void encode_identity(Poly& p, const std::array<uint8_t,32>& id_hash) {
    p.fill(0);
    for (int i = 0; i < 32; ++i) {
        p[i * 8] = static_cast<int16_t>(id_hash[i] % Q);
    }
}

void generate_trapdoor_authority(TrapdoorAuthority& out) {
    std::array<uint8_t,128> buf;
    Poly r12, r13, r23;
    randombytes(buf.data(), buf.size());
    cbd2(r12, buf);
    randombytes(buf.data(), buf.size());
    cbd2(r13, buf);
    randombytes(buf.data(), buf.size());
    cbd2(r23, buf);

    Poly neg_r12 = r12;
    poly_negate(neg_r12);

    Poly r12_r23, neg_r13;
    poly_mul_schoolbook(r12_r23, r12, r23);
    neg_r13 = r13;
    poly_negate(neg_r13);
    Poly r12_r23_minus_r13 = r12_r23;
    for (int i = 0; i < N; ++i) r12_r23_minus_r13[i] += neg_r13[i];

    out.a_row[0].fill(0); out.a_row[0][0] = 1;
    out.a_row[1] = neg_r12;
    out.a_row[2] = r12_r23_minus_r13;

    out.basis1[0] = r12;
    out.basis1[1].fill(0); out.basis1[1][0] = 1;
    out.basis1[2].fill(0);

    out.basis2[0] = r13;
    out.basis2[1] = r23;
    out.basis2[2].fill(0); out.basis2[2][0] = 1;
}

void alice_commit_identity(IdentityCommitment& commit, PolyVec& t_out,
                           const TrapdoorAuthority& authority,
                           const std::array<uint8_t,32>& id_hash) {
    PolyVec t;
    std::array<uint8_t,128> buf;
    for (int i = 0; i < K; ++i) {
        randombytes(buf.data(), buf.size());
        cbd2(t[i], buf);
    }

    Poly v, tmp;
    v.fill(0);
    poly_mul_schoolbook(v, authority.a_row[0], t[0]);
    poly_mul_schoolbook(tmp, authority.a_row[1], t[1]);
    for (int i = 0; i < N; ++i) v[i] += tmp[i];
    poly_mul_schoolbook(tmp, authority.a_row[2], t[2]);
    for (int i = 0; i < N; ++i) v[i] += tmp[i];

    Poly id_poly;
    encode_identity(id_poly, id_hash);
    Poly u = v;
    for (int i = 0; i < N; ++i) u[i] += id_poly[i];

    std::vector<uint8_t> commit_input(K * N * 2);
    size_t off = 0;
    for (int i = 0; i < K; ++i) {
        for (int j = 0; j < N; ++j) {
            commit_input[off++] = static_cast<uint8_t>(t[i][j]);
            commit_input[off++] = static_cast<uint8_t>(t[i][j] >> 8);
        }
    }
    Keccak1600::sha3_256(commit.t_commitment.data(), commit_input.data(), commit_input.size());

    std::array<uint8_t, 32 + 32 + 32> chal_in;
    std::copy(commit.t_commitment.begin(), commit.t_commitment.end(), chal_in.begin());
    std::copy(id_hash.begin(), id_hash.end(), chal_in.begin() + 32);
    const char *label = "tessandio-v18-trapdoor-challenge";
    std::copy(label, label + 32, reinterpret_cast<char*>(chal_in.data()) + 64);
    Keccak1600::sha3_256(commit.challenge.data(), chal_in.data(), chal_in.size());

    commit.u = u;
    t_out = t;
}

int authority_verify_and_trace(const TrapdoorAuthority& authority,
                               const IdentityCommitment& commit,
                               const std::array<uint8_t,32>& claimed_id) {
    (void)authority;
    Poly id_poly;
    encode_identity(id_poly, claimed_id);
    Poly target = commit.u;
    for (int i = 0; i < N; ++i) target[i] -= id_poly[i];
    (void)target;

    std::array<uint8_t, 32 + 32 + 32> chal_in;
    std::copy(commit.t_commitment.begin(), commit.t_commitment.end(), chal_in.begin());
    std::copy(claimed_id.begin(), claimed_id.end(), chal_in.begin() + 32);
    const char *label = "tessandio-v18-trapdoor-challenge";
    std::copy(label, label + 32, reinterpret_cast<char*>(chal_in.data()) + 64);
    std::array<uint8_t,32> expected_chal;
    Keccak1600::sha3_256(expected_chal.data(), chal_in.data(), chal_in.size());

    if (expected_chal != commit.challenge) return -1;
    return 0;
}

} // namespace td18
