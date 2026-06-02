/**
 * TessanDioKey V18 — Graph / EDMesh
 * Translated from Rust V18 graph.rs
 */
#include "tessandiocyle_keyx.h"
#include <string.h>

#define PHI_G 0x9E3779B97F4A7C15ULL

static uint64_t ns(uint64_t s) { return s * PHI_G + PHI_G; }

void td18_graph_from_seed(const uint8_t seed[32],
                          uint16_t adj[TD18_GRAPH_NODES][TD18_GRAPH_DEGREE],
                          uint8_t deg[TD18_GRAPH_NODES])
{
    uint8_t state[32];
    memcpy(state, seed, 32);
    memset(deg, 0, TD18_GRAPH_NODES);
    memset(adj, 0, sizeof(uint16_t) * TD18_GRAPH_NODES * TD18_GRAPH_DEGREE);

    for (int node = 0; node < TD18_GRAPH_NODES; node++) {
        for (int d = 0; d < TD18_GRAPH_DEGREE; d++) {
            uint8_t tmp[32];
            td18_hash_h(tmp, state, 32);
            memcpy(state, tmp, 32);
            uint32_t nb = ((uint32_t)state[0]
                        | ((uint32_t)state[1] << 8)
                        | ((uint32_t)state[2] << 16)
                        | ((uint32_t)state[3] << 24)) % TD18_GRAPH_NODES;
            if (nb == (uint32_t)node) continue;
            int dup = 0;
            for (int k = 0; k < deg[node]; k++) if (adj[node][k] == (uint16_t)nb) { dup = 1; break; }
            if (dup || deg[node] >= TD18_GRAPH_DEGREE) continue;
            adj[node][deg[node]++] = (uint16_t)nb;
        }
    }
}

static void g1_permute(uint64_t seed,
                       const uint16_t adj[TD18_GRAPH_NODES][TD18_GRAPH_DEGREE],
                       const uint8_t deg[TD18_GRAPH_NODES],
                       uint16_t start,
                       uint16_t perm[TD18_GRAPH_NODES])
{
    for (int i = 0; i < TD18_GRAPH_NODES; i++) perm[i] = (uint16_t)i;
    uint64_t state = seed;
    uint16_t current = start;
    for (int i = TD18_GRAPH_NODES - 1; i > 0; i--) {
        state = ns(state);
        uint8_t td = deg[current % TD18_GRAPH_NODES];
        if (td > 0) {
            uint16_t idx = (uint16_t)((state >> 32) % td);
            current = adj[current % TD18_GRAPH_NODES][idx];
        } else {
            current = (current + 1) % TD18_GRAPH_NODES;
        }
        state = ns(state);
        uint16_t j = (uint16_t)(state % (i + 1));
        uint16_t tmp = perm[i]; perm[i] = perm[j]; perm[j] = tmp;
    }
}

static void g2_mask(uint64_t seed,
                    const uint16_t adj[TD18_GRAPH_NODES][TD18_GRAPH_DEGREE],
                    const uint8_t deg[TD18_GRAPH_NODES],
                    uint16_t start,
                    uint8_t mask[32])
{
    uint64_t state = seed;
    uint16_t current = start;
    for (int b = 0; b < 32; b++) {
        uint8_t val = 0;
        for (int bit = 0; bit < 8; bit++) {
            state = ns(state);
            uint8_t td = deg[current % TD18_GRAPH_NODES];
            if (td > 0) {
                uint16_t idx = (uint16_t)((state >> 32) % td);
                current = adj[current % TD18_GRAPH_NODES][idx];
            } else {
                current = (current + 1) % TD18_GRAPH_NODES;
            }
            uint8_t bit_val = (uint8_t)((deg[current % TD18_GRAPH_NODES] ^ (uint32_t)state) & 1);
            val |= bit_val << bit;
        }
        mask[b] = val;
    }
}

void td18_edmesh_derive(uint8_t out[TD18_EDMESH_BYTES],
                        const uint8_t seed[TD18_SYMBYTES],
                        const td18_params *p)
{
    uint8_t expanded[64];
    td18_xof(seed, 0, 0, expanded, 64);
    for (int i = 24; i < 64; i++) expanded[i] = 0; /* domain sep kludge removed: use raw shake */
    /* Actually correct: reuse shake with domain string inline in protocol.c */
    /* Simpler: expand via hash_g chain */
    uint8_t dom[] = "tessandio-v18-edmesh";
    uint8_t in[TD18_SYMBYTES + sizeof(dom) - 1];
    memcpy(in, seed, TD18_SYMBYTES);
    memcpy(in + TD18_SYMBYTES, dom, sizeof(dom) - 1);
    td18_hash_g(expanded, in, sizeof(in));

    uint64_t sub_seeds[TD18_K];
    for (int i = 0; i < TD18_K; i++) {
        sub_seeds[i] = 0;
        for (int j = 0; j < 8; j++)
            sub_seeds[i] |= ((uint64_t)expanded[i * 8 + j]) << (8 * j);
    }

    uint16_t adj[TD18_K][TD18_GRAPH_NODES][TD18_GRAPH_DEGREE];
    uint8_t  deg[TD18_K][TD18_GRAPH_NODES];
    for (int i = 0; i < TD18_K; i++)
        td18_graph_from_seed(p->graph_seeds[i], adj[i], deg[i]);

    /* Phase A: permute first 32 bytes */
    uint16_t perm[TD18_GRAPH_NODES];
    g1_permute(sub_seeds[0], adj[0], deg[0], p->starts[0], perm);
    int bits[256];
    for (int i = 0; i < 256; i++) {
        bits[perm[i] % 256] = (expanded[i / 8] >> (i % 8)) & 1;
    }
    for (int i = 0; i < 256; i++) {
        if (bits[i]) expanded[i / 8] |= (1 << (i % 8));
        else         expanded[i / 8] &= ~(1 << (i % 8));
    }

    /* Phase B */
    uint8_t mask1[32];
    g2_mask(sub_seeds[1], adj[1], deg[1], p->starts[1], mask1);
    for (int i = 0; i < 32; i++) expanded[i] ^= mask1[i];

    /* Phase C */
    uint8_t mask2[32];
    g2_mask(sub_seeds[2], adj[2], deg[2], p->starts[2], mask2);
    uint8_t blend[32];
    for (int i = 0; i < 32; i++) blend[i] = expanded[i] + mask2[i];
    for (int i = 0; i < 32; i++) expanded[32 + i] ^= blend[i];

    memcpy(out, expanded, 64);
}

void td18_vdf_hash(uint8_t seed[32], uint32_t iterations)
{
    for (uint32_t i = 0; i < iterations; i++) {
        uint8_t tmp[32];
        td18_hash_h(tmp, seed, 32);
        memcpy(seed, tmp, 32);
    }
}
