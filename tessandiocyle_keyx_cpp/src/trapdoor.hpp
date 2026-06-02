#pragma once
#include "params.hpp"
#include <array>

namespace td18 {

struct TrapdoorAuthority {
    PolyVec a_row;
    PolyVec basis1;
    PolyVec basis2;
};

struct IdentityCommitment {
    Poly u;
    std::array<uint8_t,32> challenge;
    std::array<uint8_t,32> t_commitment;
};

void generate_trapdoor_authority(TrapdoorAuthority& out);
void alice_commit_identity(IdentityCommitment& commit, PolyVec& t_out,
                           const TrapdoorAuthority& authority,
                           const std::array<uint8_t,32>& id_hash);
int authority_verify_and_trace(const TrapdoorAuthority& authority,
                               const IdentityCommitment& commit,
                               const std::array<uint8_t,32>& claimed_id);

} // namespace td18
