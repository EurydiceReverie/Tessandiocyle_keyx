/**
 * TessanDioKey V18 — Merkle Tree Polynomial Commitment
 * Translated from Rust V18 merkle.rs (BLAKE3 -> SHA3-256)
 */
#include "tessandiocyle_keyx.h"
#include <string.h>
#include <stdlib.h>

static void hash_leaf(uint8_t out[32], size_t index, int16_t coeff)
{
    uint8_t in[10];
    in[0] = (uint8_t)(index);
    in[1] = (uint8_t)(index >> 8);
    in[2] = (uint8_t)(index >> 16);
    in[3] = (uint8_t)(index >> 24);
    in[4] = (uint8_t)(index >> 32);
    in[5] = (uint8_t)(index >> 40);
    in[6] = (uint8_t)(index >> 48);
    in[7] = (uint8_t)(index >> 56);
    in[8] = (uint8_t)(coeff);
    in[9] = (uint8_t)(coeff >> 8);
    td18_hash_h(out, in, sizeof(in));
}

static void hash_node(uint8_t out[32], const uint8_t left[32], const uint8_t right[32])
{
    uint8_t in[64];
    memcpy(in, left, 32);
    memcpy(in + 32, right, 32);
    td18_hash_h(out, in, sizeof(in));
}

void td18_merkle_build_tree(td18_merkle_tree *tree, const int16_t coeffs[], size_t n)
{
    size_t max_layers = 1;
    size_t tmp = n;
    size_t max_total = n;
    while (tmp > 1) { tmp = (tmp + 1) / 2; max_layers++; max_total += tmp; }

    tree->layer_counts = (size_t *)malloc(max_layers * sizeof(size_t));
    tree->num_layers = 0;

    size_t cur_count = n;
    uint8_t *cur = (uint8_t *)malloc(cur_count * 32);
    for (size_t i = 0; i < n; i++) {
        hash_leaf(&cur[i * 32], i, coeffs[i]);
    }

    size_t offset = 0;
    uint8_t *buf = (uint8_t *)malloc(max_total * 32);

    while (cur_count > 0) {
        memcpy(buf + offset, cur, cur_count * 32);
        tree->layer_counts[tree->num_layers] = cur_count;
        tree->num_layers++;
        offset += cur_count * 32;

        if (cur_count == 1) break;

        size_t next_count = (cur_count + 1) / 2;
        uint8_t *next = (uint8_t *)malloc(next_count * 32);
        for (size_t i = 0; i < next_count; i++) {
            size_t l = 2 * i;
            size_t r = l + 1;
            if (r < cur_count) {
                hash_node(&next[i * 32], &cur[l * 32], &cur[r * 32]);
            } else {
                hash_node(&next[i * 32], &cur[l * 32], &cur[l * 32]);
            }
        }
        free(cur);
        cur = next;
        cur_count = next_count;
    }

    free(cur);
    tree->layers = (uint8_t (*)[32])realloc(buf, offset);
}

void td18_merkle_free_tree(td18_merkle_tree *tree)
{
    if (tree->layers) { free(tree->layers); tree->layers = NULL; }
    if (tree->layer_counts) { free(tree->layer_counts); tree->layer_counts = NULL; }
    tree->num_layers = 0;
}

void td18_merkle_proof_generate(td18_merkle_proof *proof,
                                const td18_merkle_tree *tree,
                                size_t index)
{
    proof->num_steps = 0;
    size_t idx = index;
    size_t offset = 0;

    for (size_t layer = 0; layer + 1 < tree->num_layers; layer++) {
        size_t count = tree->layer_counts[layer];
        size_t sibling = (idx % 2 == 0) ? (idx + 1) : (idx - 1);
        if (sibling >= count) sibling = idx; /* duplicate last node */

        proof->steps[proof->num_steps].sibling_idx = sibling;
        memcpy(proof->steps[proof->num_steps].hash,
               (uint8_t *)tree->layers + (offset + sibling) * 32, 32);
        proof->num_steps++;

        offset += count;
        idx /= 2;
    }
}

int td18_merkle_verify(const uint8_t root[32],
                       size_t index,
                       int16_t coeff,
                       const td18_merkle_proof *proof)
{
    uint8_t current[32];
    hash_leaf(current, index, coeff);
    size_t idx = index;

    for (size_t i = 0; i < proof->num_steps; i++) {
        if (idx % 2 == 0) {
            hash_node(current, current, proof->steps[i].hash);
        } else {
            hash_node(current, proof->steps[i].hash, current);
        }
        idx /= 2;
    }

    return (memcmp(current, root, 32) == 0) ? TD18_OK : TD18_ERR_VERIFY;
}
