// TessanDioKey v18 — Merkle Tree Polynomial Commitment for Transparency
//
// During keypair generation, Alice builds a Merkle tree over her secret-key
// polynomial coefficients. She publishes the root hash alongside pk. Later,
// she can reveal individual coefficients (via Merkle paths) for audit or
// verifiable compromise detection without exposing the full secret key.

/// Compute a leaf hash for a single coefficient.
fn leaf_hash(index: usize, coeff: i16) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&index.to_le_bytes());
    hasher.update(&coeff.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Compute the parent hash of two child hashes.
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// Build a Merkle tree from a slice of coefficients.
/// Returns the root hash and the tree layers (bottom-up).
pub fn build_merkle_tree(coeffs: &[i16]) -> ([u8; 32], Vec<Vec<[u8; 32]>>) {
    let mut layers: Vec<Vec<[u8; 32]>> = Vec::new();

    // Bottom layer: leaf hashes
    let mut current: Vec<[u8; 32]> = coeffs.iter().enumerate()
        .map(|(i, c)| leaf_hash(i, *c))
        .collect();
    layers.push(current.clone());

    // Build upwards
    while current.len() > 1 {
        let mut next = Vec::new();
        for chunk in current.chunks(2) {
            if chunk.len() == 2 {
                next.push(node_hash(&chunk[0], &chunk[1]));
            } else {
                // Odd node: duplicate itself as sibling
                next.push(node_hash(&chunk[0], &chunk[0]));
            }
        }
        layers.push(next.clone());
        current = next;
    }

    (current[0], layers)
}

/// Generate a Merkle proof for coefficient at `index`.
/// Returns the sibling hashes from leaf to root.
pub fn merkle_proof(tree: &[Vec<[u8; 32]>], index: usize) -> Vec<(usize, [u8; 32])> {
    let mut proof = Vec::new();
    let mut idx = index;

    for layer in tree.iter().take(tree.len() - 1) {
        let sibling_idx = if idx.is_multiple_of(2) { idx + 1 } else { idx - 1 };
        let sibling = if sibling_idx < layer.len() {
            layer[sibling_idx]
        } else {
            // Duplicate current node if no sibling
            layer[idx]
        };
        proof.push((sibling_idx, sibling));
        idx /= 2;
    }

    proof
}

/// Verify a Merkle proof against a root hash.
/// `index` is the coefficient index, `coeff` is the claimed value,
/// `proof` is the list of sibling hashes.
pub fn verify_merkle_proof(root: &[u8; 32], index: usize, coeff: i16, proof: &[(usize, [u8; 32])]) -> bool {
    let mut current = leaf_hash(index, coeff);
    let mut idx = index;

    for (_sibling_idx, sibling_hash) in proof.iter() {
        current = if idx.is_multiple_of(2) {
            node_hash(&current, sibling_hash)
        } else {
            node_hash(sibling_hash, &current)
        };
        idx /= 2;
    }

    &current == root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_basic() {
        let coeffs: Vec<i16> = (0..256).map(|i| (i * 13 % 3329) as i16).collect();
        let (root, tree) = build_merkle_tree(&coeffs);
        assert!(!root.iter().all(|&b| b == 0));
        assert!(!tree.is_empty());
    }

    #[test]
    fn test_merkle_proof_verification() {
        let coeffs: Vec<i16> = (0..256).map(|i| (i * 13 % 3329) as i16).collect();
        let (root, tree) = build_merkle_tree(&coeffs);

        for idx in [0usize, 1, 127, 128, 255] {
            let proof = merkle_proof(&tree, idx);
            assert!(verify_merkle_proof(&root, idx, coeffs[idx], &proof));
        }
    }

    #[test]
    fn test_merkle_tamper_detected() {
        let coeffs: Vec<i16> = (0..256).map(|i| (i * 13 % 3329) as i16).collect();
        let (root, tree) = build_merkle_tree(&coeffs);
        let idx = 42;
        let proof = merkle_proof(&tree, idx);

        // Tamper with coefficient
        assert!(!verify_merkle_proof(&root, idx, coeffs[idx] + 1, &proof));
    }

    #[test]
    fn test_merkle_powers_of_two() {
        let coeffs: Vec<i16> = (0..16).map(|i| i as i16).collect();
        let (root, tree) = build_merkle_tree(&coeffs);
        assert_eq!(tree.len(), 5); // 16 → 8 → 4 → 2 → 1

        for (idx, coeff) in coeffs.iter().enumerate().take(16) {
            let proof = merkle_proof(&tree, idx);
            assert!(verify_merkle_proof(&root, idx, *coeff, &proof));
        }
    }
}
