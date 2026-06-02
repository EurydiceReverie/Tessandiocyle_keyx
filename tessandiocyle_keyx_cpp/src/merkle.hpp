#pragma once
#include "params.hpp"
#include <vector>
#include <array>
#include <cstdint>

namespace td18 {

struct MerkleTree {
    std::vector<std::vector<std::array<uint8_t,32>>> layers;
};

using MerkleProof = std::vector<std::pair<size_t, std::array<uint8_t,32>>>;

MerkleTree merkle_build_tree(const Poly& coeffs);
MerkleProof merkle_proof(const MerkleTree& tree, size_t index);
int merkle_verify(const std::array<uint8_t,32>& root, size_t index,
                  int16_t coeff, const MerkleProof& proof);

} // namespace td18
