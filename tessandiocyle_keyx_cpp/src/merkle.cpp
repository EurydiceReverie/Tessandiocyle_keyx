#include "merkle.hpp"
#include "shake.hpp"
#include <cstring>

namespace td18 {

static void hash_leaf(std::array<uint8_t,32>& out, size_t index, int16_t coeff) {
    uint8_t in[10];
    in[0] = static_cast<uint8_t>(index);
    in[1] = static_cast<uint8_t>(index >> 8);
    in[2] = static_cast<uint8_t>(index >> 16);
    in[3] = static_cast<uint8_t>(index >> 24);
    in[4] = static_cast<uint8_t>(index >> 32);
    in[5] = static_cast<uint8_t>(index >> 40);
    in[6] = static_cast<uint8_t>(index >> 48);
    in[7] = static_cast<uint8_t>(index >> 56);
    in[8] = static_cast<uint8_t>(coeff);
    in[9] = static_cast<uint8_t>(coeff >> 8);
    Keccak1600::sha3_256(out.data(), in, sizeof(in));
}

static void hash_node(std::array<uint8_t,32>& out,
                      const std::array<uint8_t,32>& left,
                      const std::array<uint8_t,32>& right) {
    uint8_t in[64];
    std::copy(left.begin(), left.end(), in);
    std::copy(right.begin(), right.end(), in + 32);
    Keccak1600::sha3_256(out.data(), in, sizeof(in));
}

MerkleTree merkle_build_tree(const Poly& coeffs) {
    MerkleTree tree;
    std::vector<std::array<uint8_t,32>> current;
    for (int i = 0; i < N; ++i) {
        std::array<uint8_t,32> h;
        hash_leaf(h, i, coeffs[i]);
        current.push_back(h);
    }
    tree.layers.push_back(current);
    while (current.size() > 1) {
        std::vector<std::array<uint8_t,32>> next;
        for (size_t i = 0; i < current.size(); i += 2) {
            if (i + 1 < current.size()) {
                std::array<uint8_t,32> h;
                hash_node(h, current[i], current[i+1]);
                next.push_back(h);
            } else {
                next.push_back(current[i]);
            }
        }
        current = next;
        tree.layers.push_back(current);
    }
    return tree;
}

MerkleProof merkle_proof(const MerkleTree& tree, size_t index) {
    MerkleProof proof;
    size_t idx = index;
    for (size_t layer = 0; layer + 1 < tree.layers.size(); ++layer) {
        size_t sibling = (idx % 2 == 0) ? (idx + 1) : (idx - 1);
        if (sibling >= tree.layers[layer].size()) sibling = idx;
        proof.push_back({sibling, tree.layers[layer][sibling]});
        idx /= 2;
    }
    return proof;
}

int merkle_verify(const std::array<uint8_t,32>& root, size_t index,
                  int16_t coeff, const MerkleProof& proof) {
    std::array<uint8_t,32> current;
    hash_leaf(current, index, coeff);
    size_t idx = index;
    for (const auto& step : proof) {
        std::array<uint8_t,32> h;
        if (idx % 2 == 0) {
            hash_node(h, current, step.second);
        } else {
            hash_node(h, step.second, current);
        }
        current = h;
        idx /= 2;
    }
    return (current == root) ? 0 : -1;
}

} // namespace td18
