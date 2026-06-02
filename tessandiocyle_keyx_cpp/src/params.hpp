#pragma once
#include <array>
#include <cstdint>
#include <cstddef>

namespace td18 {

constexpr int K = 3;
constexpr int N = 256;
constexpr int Q = 3329;
constexpr int SYMBYTES = 32;
constexpr int SSBYTES = 32;

constexpr int POLYBYTES = 384;
constexpr int POLYVECBYTES = K * POLYBYTES;
constexpr int POLYCOMPRESSEDBYTES = 128;
constexpr int POLYVECCOMPRESSEDBYTES = K * 320;

constexpr int INDCPA_PUBLICKEYBYTES = POLYVECBYTES + SYMBYTES;
constexpr int INDCPA_SECRETKEYBYTES = POLYVECBYTES;
constexpr int INDCPA_BYTES = POLYVECCOMPRESSEDBYTES + POLYCOMPRESSEDBYTES;

constexpr int PUBLICKEYBYTES = INDCPA_PUBLICKEYBYTES;
constexpr int SECRETKEYBYTES = INDCPA_SECRETKEYBYTES + PUBLICKEYBYTES + 2 * SYMBYTES;
constexpr int CIPHERTEXTBYTES = INDCPA_BYTES;

constexpr int RECON_BYTES = 144;
constexpr int GRAPH_NODES = 256;
constexpr int GRAPH_DEGREE = 12;
constexpr int EDMESH_BYTES = 64;
constexpr int BIND_BYTES = 32;
constexpr int MAC_BYTES = 2;

constexpr int QINV = -3327;
constexpr int MONT = -1044;

using Poly = std::array<int16_t, N>;
using PolyVec = std::array<Poly, K>;

struct Params {
    std::array<std::array<uint8_t, SYMBYTES>, K> graph_seeds;
    std::array<uint16_t, K> starts;
    std::array<uint8_t, SYMBYTES> epoch_seed;
    uint64_t epoch = 0;
};

struct Commitment {
    std::array<uint8_t, 32> hash;
    std::array<uint8_t, 32> nonce;
};

} // namespace td18
