// TessanDioKey v16 — Graph-walk novelty + Entropy-Diffusion Mesh + GraphEpoch evolution
use crate::params::{
    GRAPH_DEGREE, GRAPH_EPOCH_WORK_FACTOR, GRAPH_NODES, KYBER_K, KYBER_N,
};
use rand::rngs::OsRng;
use rand::RngCore;

const PHI: u64 = 0x9E3779B97F4A7C15;

/// Random graph represented as adjacency lists.
#[derive(Clone, Debug)]
pub struct Graph {
    pub adj: Vec<Vec<usize>>,
    pub degrees: Vec<u32>,
}

/// Generate a random undirected graph with `nodes` nodes and average degree `degree`.
pub fn generate_graph(nodes: usize, degree: usize) -> Graph {
    let mut adj = vec![vec![]; nodes];
    let mut buf = [0u8; 4];
    for node in 0..nodes {
        for _ in 0..degree {
            OsRng.fill_bytes(&mut buf);
            let nb = (u32::from_le_bytes(buf) as usize) % nodes;
            if nb != node && !adj[node].contains(&nb) {
                adj[node].push(nb);
                adj[nb].push(node);
            }
        }
    }
    let degrees: Vec<u32> = adj.iter().map(|v| v.len() as u32).collect();
    Graph { adj, degrees }
}

/// Deterministically generate a graph from a seed using sequential hashing.
pub fn generate_graph_from_seed(seed: &[u8; 32], nodes: usize, degree: usize) -> Graph {
    let mut adj = vec![vec![]; nodes];
    let mut state = *seed;
    for node in 0..nodes {
        for _ in 0..degree {
            // Use sequential state evolution to deterministically pick neighbors
            state = *blake3::hash(&state).as_bytes();
            let nb = (u32::from_le_bytes(state[..4].try_into().unwrap()) as usize) % nodes;
            if nb != node && !adj[node].contains(&nb) {
                adj[node].push(nb);
                adj[nb].push(node);
            }
        }
    }
    let degrees: Vec<u32> = adj.iter().map(|v| v.len() as u32).collect();
    Graph { adj, degrees }
}

/// Chaotic PRNG step.
#[inline]
fn ns(s: u64) -> u64 {
    s.wrapping_mul(PHI).wrapping_add(0x9E3779B97F4A7C15)
}

/// G1: Fisher-Yates permutation seeded by a graph walk.
pub fn g1_permutation(seed: u64, graph: &Graph, start: usize) -> Vec<usize> {
    let mut perm: Vec<usize> = (0..GRAPH_NODES).collect();
    let mut state = seed;
    let mut current = start;
    for i in (1..GRAPH_NODES).rev() {
        state = ns(state);
        let target_degree = graph.adj[current].len();
        if target_degree > 0 {
            let idx = ((state >> 32) as usize) % target_degree;
            current = graph.adj[current][idx];
        } else {
            current = (current + 1) % GRAPH_NODES;
        }
        state = ns(state);
        let j = (state as usize) % (i + 1);
        perm.swap(i, j);
    }
    perm
}

/// G2: Graph-walk entropy mask (32 bytes = 256 bits).
pub fn g2_entropy_mask(seed: u64, graph: &Graph, start: usize) -> [u8; 32] {
    let mut mask = [0u8; 32];
    let mut state = seed;
    let mut current = start;
    for byte in mask.iter_mut() {
        let mut val = 0u8;
        for bit_idx in 0..8 {
            state = ns(state);
            let target_degree = graph.adj[current].len();
            if target_degree > 0 {
                let idx = ((state >> 32) as usize) % target_degree;
                current = graph.adj[current][idx];
            } else {
                current = (current + 1) % GRAPH_NODES;
            }
            let bit = ((graph.degrees[current] ^ (state as u32)) & 1) as u8;
            val |= bit << bit_idx;
        }
        *byte = val;
    }
    mask
}

/// Entropy-Diffusion Mesh — interleaved graph walk across K polynomial domains
/// ---------------------------------------------------------------------------
/// Phase A: Walk G1 on polynomial-0 domain → permutation vector (K×N elements)
pub fn edmesh_permute(seed: u64, graph: &Graph, start: usize) -> Vec<usize> {
    // Produce a permutation of 0..KYBER_K*KYBER_N by walking the graph
    let total_nodes = KYBER_K * KYBER_N;
    let mut perm: Vec<usize> = (0..total_nodes).collect();
    let mut state = seed;
    let mut current = start;
    for i in (1..total_nodes).rev() {
        state = ns(state);
        let target_degree = graph.adj[current % GRAPH_NODES].len();
        if target_degree > 0 {
            let idx = ((state >> 32) as usize) % target_degree;
            current = graph.adj[current % GRAPH_NODES][idx];
        } else {
            current = (current + 1) % GRAPH_NODES;
        }
        state = ns(state);
        let j = (state as usize) % (i + 1);
        perm.swap(i, j);
    }
    perm
}

/// Phase B: Walk G2 on polynomial-1 domain → XOR mask (32 bytes)
/// Phase C: Walk G3 on polynomial-2 domain → entropy blend
/// Combined into a single 64-byte expanded output.
pub fn edmesh_derive(
    seed: &[u8; 32],
    graphs: &[Graph; KYBER_K],
    starts: &[usize; KYBER_K],
) -> [u8; 64] {
    let mut expanded = [0u8; 64];
    let mut hasher = blake3::Hasher::new();
    hasher.update(seed);
    hasher.update(b"tessandio-v16-edmesh");
    let mut reader = hasher.finalize_xof();
    std::io::Read::read_exact(&mut reader, &mut expanded).unwrap();

    // Generate sub-seeds for each phase from the first 24 bytes
    let mut sub_seeds = [0u64; KYBER_K];
    for (i, seed) in sub_seeds.iter_mut().enumerate().take(KYBER_K) {
        let off = i * 8;
        *seed = u64::from_le_bytes(expanded[off..off + 8].try_into().unwrap());
    }

    // Phase A: G1 permutation across K×N space
    let perm = edmesh_permute(sub_seeds[0], &graphs[0], starts[0]);
    let mut bits = vec![false; 256]; // we permute the first 32 bytes = 256 bits
    for (i, &p) in perm.iter().enumerate().take(256) {
        let src_byte = i / 8;
        let src_bit = i % 8;
        bits[p % 256] = ((expanded[src_byte] >> src_bit) & 1) != 0;
    }
    // Write permuted bits back into first 32 bytes of expanded
    for (i, bit) in bits.iter().enumerate() {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        if *bit {
            expanded[byte_idx] |= 1 << bit_idx;
        } else {
            expanded[byte_idx] &= !(1 << bit_idx);
        }
    }

    // Phase B: G2 entropy mask from graph 1
    let mask1 = g2_entropy_mask(sub_seeds[1], &graphs[1], starts[1]);
    for i in 0..32 {
        expanded[i] ^= mask1[i];
    }

    // Phase C: G3 entropy blend from graph 2
    let mask2 = g2_entropy_mask(sub_seeds[2], &graphs[2], starts[2]);
    let mut blend_perm = [0u8; 32];
    for i in 0..32 {
        blend_perm[i] = expanded[i].wrapping_add(mask2[i]);
    }
    // XOR blend_perm into second half of expanded
    for i in 0..32 {
        expanded[32 + i] ^= blend_perm[i];
    }

    expanded
}

/// ---------------------------------------------------------------------------
/// GraphEpoch — temporal evolution via sequential-hash VDF
/// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct GraphEpoch {
    pub epoch: u64,
    pub seed: [u8; 32],
    pub work_factor: u32,
}

/// Sequentially hash `iterations` times (non-parallelisable).
fn sequential_hash(seed: &[u8; 32], iterations: u32) -> [u8; 32] {
    let mut state = *seed;
    for _ in 0..iterations {
        state = *blake3::hash(&state).as_bytes();
    }
    state
}

/// Evolve the epoch: perform sequential work and produce next graph.
pub fn evolve_epoch(current: &GraphEpoch) -> (GraphEpoch, Graph) {
    let new_seed = sequential_hash(&current.seed, current.work_factor);
    let new_graph = generate_graph_from_seed(&new_seed, GRAPH_NODES, GRAPH_DEGREE);
    (
        GraphEpoch {
            epoch: current.epoch + 1,
            seed: new_seed,
            work_factor: current.work_factor,
        },
        new_graph,
    )
}

/// Create initial epoch from a random seed.
pub fn initial_epoch() -> GraphEpoch {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    GraphEpoch {
        epoch: 0,
        seed,
        work_factor: GRAPH_EPOCH_WORK_FACTOR,
    }
}

/// Apply permutation to a byte array (must be exactly GRAPH_NODES / 8 = 32 bytes).
pub fn apply_permutation(data: &mut [u8], perm: &[usize]) {
    assert_eq!(data.len() * 8, GRAPH_NODES);
    let mut bits = vec![false; GRAPH_NODES];
    for (i, &p) in perm.iter().enumerate() {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        bits[p] = ((data[byte_idx] >> bit_idx) & 1) != 0;
    }
    for (i, bit) in bits.iter().enumerate() {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        if *bit {
            data[byte_idx] |= 1 << bit_idx;
        } else {
            data[byte_idx] &= !(1 << bit_idx);
        }
    }
}

/// Apply XOR mask to byte array.
pub fn apply_mask(data: &mut [u8], mask: &[u8]) {
    assert_eq!(data.len(), mask.len());
    for (d, m) in data.iter_mut().zip(mask.iter()) {
        *d ^= *m;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graph_generation() {
        let g = generate_graph(256, 12);
        assert_eq!(g.adj.len(), 256);
    }

    #[test]
    fn test_g1_permutation_is_valid() {
        let g = generate_graph(256, 12);
        let perm = g1_permutation(0x12345678, &g, 0);
        assert_eq!(perm.len(), 256);
        let mut sorted = perm.clone();
        sorted.sort();
        for (i, &val) in sorted.iter().enumerate() {
            assert_eq!(val, i);
        }
    }

    #[test]
    fn test_g2_mask_deterministic() {
        let g = generate_graph(256, 12);
        let m1 = g2_entropy_mask(0xABCDEF, &g, 0);
        let m2 = g2_entropy_mask(0xABCDEF, &g, 0);
        assert_eq!(m1, m2);
    }

    #[test]
    fn test_edmesh_deterministic() {
        let g1 = generate_graph(256, 12);
        let g2 = generate_graph(256, 12);
        let g3 = generate_graph(256, 12);
        let graphs = [g1, g2, g3];
        let starts = [0usize, 1, 2];
        let seed = [0xAAu8; 32];
        let a = edmesh_derive(&seed, &graphs, &starts);
        let b = edmesh_derive(&seed, &graphs, &starts);
        assert_eq!(a, b);
    }

    #[test]
    fn test_edmesh_entropy_distribution() {
        let g1 = generate_graph(256, 12);
        let g2 = generate_graph(256, 12);
        let g3 = generate_graph(256, 12);
        let graphs = [g1, g2, g3];
        let starts = [10usize, 20, 30];
        let seed = [0xBBu8; 32];
        let out = edmesh_derive(&seed, &graphs, &starts);
        let mut zeros = 0usize;
        for &b in out.iter() {
            for i in 0..8 {
                if (b >> i) & 1 == 0 { zeros += 1; }
            }
        }
        let ones = out.len() * 8 - zeros;
        let ratio = ones as f64 / (out.len() * 8) as f64;
        assert!(ratio > 0.35 && ratio < 0.65, "EDMesh distribution biased: {}", ratio);
    }

    #[test]
    fn test_epoch_evolution_deterministic() {
        let epoch = GraphEpoch {
            epoch: 0,
            seed: [0xCCu8; 32],
            work_factor: 1000, // small for test speed
        };
        let (epoch2, g2) = evolve_epoch(&epoch);
        let (epoch3, g3) = evolve_epoch(&epoch2);
        assert_eq!(epoch2.epoch, 1);
        assert_eq!(epoch3.epoch, 2);
        assert_ne!(epoch2.seed, epoch.seed);
        assert_ne!(epoch3.seed, epoch2.seed);
        // Graphs should differ across epochs (with overwhelming probability)
        assert_ne!(g2.adj, g3.adj);
    }

    #[test]
    fn test_epoch_sequential_work() {
        // Verify that sequential hash with different factors gives different results
        let seed = [0xDDu8; 32];
        let a = sequential_hash(&seed, 100);
        let b = sequential_hash(&seed, 101);
        assert_ne!(a, b);
    }
}
