#include "graph.hpp"
#include "shake.hpp"
#include <cstring>

namespace td18 {

void graph_from_seed(const std::array<uint8_t,32>& seed,
                     std::array<std::array<uint16_t,GRAPH_DEGREE>,GRAPH_NODES>& adj,
                     std::array<uint8_t,GRAPH_NODES>& deg) {
    for (int i = 0; i < GRAPH_NODES; ++i) deg[i] = 0;
    std::array<uint8_t, 64> buf;
    Keccak1600::shake256(buf.data(), buf.size(), seed.data(), seed.size());
    for (int u = 0; u < GRAPH_NODES; ++u) {
        for (int e = 0; e < GRAPH_DEGREE; ++e) {
            uint32_t idx = (u * GRAPH_DEGREE + e) % 64;
            uint16_t v = (buf[idx] | (static_cast<uint16_t>(buf[(idx+1)%64]) << 8)) % GRAPH_NODES;
            if (v != u && deg[u] < GRAPH_DEGREE) {
                adj[u][deg[u]++] = v;
            }
        }
    }
}

void edmesh_derive(std::array<uint8_t,EDMESH_BYTES>& out,
                   const std::array<uint8_t,SYMBYTES>& seed,
                   const Params& p) {
    std::array<std::array<uint16_t,GRAPH_DEGREE>,GRAPH_NODES> adj{};
    std::array<uint8_t,GRAPH_NODES> deg{};
    std::array<uint8_t,EDMESH_BYTES> expanded{};
    size_t off = 0;
    for (int i = 0; i < K && off < EDMESH_BYTES; ++i) {
        graph_from_seed(p.graph_seeds[i], adj, deg);
        uint16_t node = p.starts[i];
        for (int step = 0; step < 8 && off < EDMESH_BYTES; ++step) {
            if (deg[node] > 0) {
                node = adj[node][node % deg[node]];
            }
            expanded[off++] = static_cast<uint8_t>(node);
            expanded[off++] = static_cast<uint8_t>(node >> 8);
        }
    }
    std::array<uint8_t, SYMBYTES + EDMESH_BYTES> in;
    std::copy(seed.begin(), seed.end(), in.begin());
    std::copy(expanded.begin(), expanded.end(), in.begin() + SYMBYTES);
    Keccak1600::shake256(out.data(), out.size(), in.data(), in.size());
}

} // namespace td18
