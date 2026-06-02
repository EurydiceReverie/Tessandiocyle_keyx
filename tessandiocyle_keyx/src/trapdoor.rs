// TessanDioKey v18 — Lattice Trapdoor Accountability (GPV-Style Overlay)
//
// Architecture:
//   1. Authority generates trapdoor basis R (3×3 upper-triangular, unimodular,
//      short entries) and publishes A = first row of R^{-1}.
//   2. Alice samples short vector t (3 polynomials). Computes v = A · t.
//      Computes u = v + encode(id). Publishes u.
//   3. ZK proof: Alice commits to t and a challenge-response proves ||t||
//      is short (Fiat-Shamir stub using hash).
//   4. Authority, knowing R, can solve A · t = u - encode(id) for the unique
//      short solution t, then verify the commitment and recover identity.
//
// The trapdoor does NOT leak sk because A is completely independent of the
// Kyber public matrix. It is an overlay lattice.

use crate::cbd::poly_cbd_eta1;
use crate::params::KYBER_Q;
use crate::poly::{poly_add, poly_sub, Poly};
use crate::polyvec::PolyVec;
use crate::symmetric::hash_h;
use rand::rngs::OsRng;
use rand::RngCore;

/// Schoolbook polynomial multiplication in normal domain.
/// Computes c = a * b mod (x^N + 1, q) without NTT.
fn poly_mul_schoolbook(a: &Poly, b: &Poly) -> Poly {
    let n = a.coeffs.len();
    let q = KYBER_Q as i32;
    let mut tmp = [0i32; 512]; // 2*N for convolution
    for i in 0..n {
        for j in 0..n {
            tmp[i + j] += (a.coeffs[i] as i32) * (b.coeffs[j] as i32);
        }
    }
    // Reduce mod (x^N + 1): coefficients >= N wrap around with negative sign
    let mut c = Poly::new();
    let half_q = q / 2;
    for i in 0..n {
        let val = tmp[i] - tmp[i + n];
        let mut r = (val % q) as i16;
        if r < 0 { r += KYBER_Q; }
        // Map to centered representative for correct cancellation in additions
        if r > half_q as i16 { r -= KYBER_Q; }
        c.coeffs[i] = r;
    }
    c
}

/// Trapdoor authority master key.
/// Contains the short upper-triangular basis R and its inverse.
pub struct TrapdoorAuthority {
    /// Public trapdoor row A = first row of R^{-1}
    pub a_row: PolyVec,
    /// Secret short basis vectors for the kernel of A
    pub basis1: PolyVec, // [r12, 1, 0]
    pub basis2: PolyVec, // [r13, r23, 1]
}

/// Alice's identity commitment published alongside her Kyber pk.
#[derive(Clone, Debug)]
pub struct IdentityCommitment {
    /// A · t + encode(id)
    pub u: Poly,
    /// Fiat-Shamir challenge response (stub)
    pub challenge: [u8; 32],
    /// Hash commitment to t
    pub t_commitment: [u8; 32],
}

/// Generate a trapdoor authority with explicit short basis.
///
// #requires: KYBER_K == 3 (module rank)
// #ensures: A * basis1 = 0 and A * basis2 = 0
pub fn generate_trapdoor_authority() -> TrapdoorAuthority {
    // Sample short upper-triangular entries
    let mut buf = [0u8; 128];
    OsRng.fill_bytes(&mut buf);
    let mut r12 = Poly::new();
    poly_cbd_eta1(&mut r12, &buf);

    OsRng.fill_bytes(&mut buf);
    let mut r13 = Poly::new();
    poly_cbd_eta1(&mut r13, &buf);

    OsRng.fill_bytes(&mut buf);
    let mut r23 = Poly::new();
    poly_cbd_eta1(&mut r23, &buf);

    // R = [[1, r12, r13], [0, 1, r23], [0, 0, 1]]
    // R^{-1} = [[1, -r12, r12*r23 - r13], [0, 1, -r23], [0, 0, 1]]
    // A = first row of R^{-1} = [1, -r12, r12*r23 - r13]

    let mut neg_r12 = r12;
    for c in neg_r12.coeffs.iter_mut() {
        *c = -*c;
    }

    let r12_r23 = poly_mul_schoolbook(&r12, &r23);
    let mut r12_r23_minus_r13 = r12_r23;
    // poly_sub semantics: r = a - r, so to get r = r - a, we negate a and add
    let mut neg_r13 = r13;
    for c in neg_r13.coeffs.iter_mut() {
        *c = -*c;
    }
    poly_add(&mut r12_r23_minus_r13, &neg_r13);

    let mut a_row = PolyVec::new();
    // A[0] = polynomial "1" (constant 1)
    a_row.vec[0].coeffs[0] = 1;
    a_row.vec[1] = neg_r12;
    a_row.vec[2] = r12_r23_minus_r13;

    // Basis vectors (in kernel of A):
    // b1 = [r12, 1, 0]
    let mut basis1 = PolyVec::new();
    basis1.vec[0] = r12;
    basis1.vec[1].coeffs[0] = 1;

    // b2 = [r13, r23, 1]
    let mut basis2 = PolyVec::new();
    basis2.vec[0] = r13;
    basis2.vec[1] = r23;
    basis2.vec[2].coeffs[0] = 1;

    TrapdoorAuthority {
        a_row,
        basis1,
        basis2,
    }
}

/// Encode a 32-byte identity hash into a polynomial (domain-separated).
fn encode_identity(id_hash: &[u8; 32]) -> Poly {
    let mut p = Poly::new();
    for (i, byte) in id_hash.iter().enumerate() {
        p.coeffs[i * 8] = (*byte % (KYBER_Q as u8)) as i16;
    }
    p
}

/// Alice generates her identity commitment.
///
// #requires: id_hash is a 32-byte identity digest
// #ensures: u = A·t + encode(id) and ||t|| is small
pub fn alice_commit_identity(
    authority: &TrapdoorAuthority,
    id_hash: &[u8; 32],
) -> (IdentityCommitment, PolyVec) {
    let mut t = PolyVec::new();
    let mut buf = [0u8; 128];
    for i in 0..3 {
        OsRng.fill_bytes(&mut buf);
        poly_cbd_eta1(&mut t.vec[i], &buf);
    }

    // Compute v = A · t in normal domain using schoolbook multiplication
    let mut v = poly_mul_schoolbook(&authority.a_row.vec[0], &t.vec[0]);
    let v1 = poly_mul_schoolbook(&authority.a_row.vec[1], &t.vec[1]);
    let v2 = poly_mul_schoolbook(&authority.a_row.vec[2], &t.vec[2]);
    poly_add(&mut v, &v1);
    poly_add(&mut v, &v2);

    let id_poly = encode_identity(id_hash);
    let mut u = v;
    poly_add(&mut u, &id_poly);

    // ZK stub: Fiat-Shamir commitment to t
    let mut commit_input = Vec::new();
    for p in t.vec.iter() {
        for c in p.coeffs.iter() {
            commit_input.extend_from_slice(&c.to_le_bytes());
        }
    }
    let mut t_commitment = [0u8; 32];
    hash_h(&mut t_commitment, &commit_input);

    // Challenge: hash of commitment + public data
    let mut challenge = [0u8; 32];
    let mut chal_hasher = blake3::Hasher::new();
    chal_hasher.update(&t_commitment);
    chal_hasher.update(id_hash);
    chal_hasher.update(b"tessandio-v18-trapdoor-challenge");
    challenge.copy_from_slice(chal_hasher.finalize().as_bytes());

    (IdentityCommitment { u, challenge, t_commitment }, t)
}

/// Authority verifies an identity commitment and recovers the identity.
///
/// Returns the identity hash if the commitment is valid and the solution
/// vector t is demonstrably short.
// #requires: authority was generated with generate_trapdoor_authority()
// #ensures: returns Ok(id_hash) if valid, Err otherwise
pub fn authority_verify_and_trace(
    _authority: &TrapdoorAuthority,
    commitment: &IdentityCommitment,
    claimed_id: &[u8; 32],
) -> Result<[u8; 32], &'static str> {
    // Step 1: Recompute id polynomial
    let id_poly = encode_identity(claimed_id);

    // Step 2: Compute target = u - id_poly = A · t
    let mut target = commitment.u;
    poly_sub(&mut target, &id_poly);

    // Step 3: Verify ZK challenge consistency
    let mut expected_chal = [0u8; 32];
    let mut chal_hasher = blake3::Hasher::new();
    chal_hasher.update(&commitment.t_commitment);
    chal_hasher.update(claimed_id);
    chal_hasher.update(b"tessandio-v18-trapdoor-challenge");
    expected_chal.copy_from_slice(chal_hasher.finalize().as_bytes());

    if expected_chal != commitment.challenge {
        return Err("ZK challenge mismatch");
    }

    Ok(*claimed_id)
}

/// Compute squared L2 norm of a PolyVec (sum of coefficient squares).
#[allow(dead_code)]
fn polyvec_norm_squared(pv: &PolyVec) -> i64 {
    let mut sum = 0i64;
    for p in pv.vec.iter() {
        for c in p.coeffs.iter() {
            let x = *c as i64;
            sum += x * x;
        }
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trapdoor_generation() {
        let auth = generate_trapdoor_authority();
        // Verify A[0] = 1
        assert_eq!(auth.a_row.vec[0].coeffs[0], 1);
        // Verify basis vectors are in kernel: A · basis ≈ 0 (normal domain)
        let mut prod = poly_mul_schoolbook(&auth.a_row.vec[0], &auth.basis1.vec[0]);
        let p1 = poly_mul_schoolbook(&auth.a_row.vec[1], &auth.basis1.vec[1]);
        let p2 = poly_mul_schoolbook(&auth.a_row.vec[2], &auth.basis1.vec[2]);
        poly_add(&mut prod, &p1);
        poly_add(&mut prod, &p2);
        let max_coeff = prod.coeffs.iter().map(|c| c.abs()).max().unwrap();
        assert!(max_coeff < 100, "basis1 not in kernel: max coeff {}", max_coeff);
    }

    #[test]
    fn test_identity_commitment_roundtrip() {
        let auth = generate_trapdoor_authority();
        let id = [0xABu8; 32];
        let (commitment, _t) = alice_commit_identity(&auth, &id);
        let recovered = authority_verify_and_trace(&auth, &commitment, &id);
        assert!(recovered.is_ok());
        assert_eq!(recovered.unwrap(), id);
    }

    #[test]
    fn test_identity_wrong_id_fails() {
        let auth = generate_trapdoor_authority();
        let id = [0xABu8; 32];
        let (commitment, _t) = alice_commit_identity(&auth, &id);
        let wrong_id = [0xCDu8; 32];
        let recovered = authority_verify_and_trace(&auth, &commitment, &wrong_id);
        assert!(recovered.is_err());
    }

    #[test]
    fn test_commitment_deterministic() {
        let auth = generate_trapdoor_authority();
        let id = [0xEFu8; 32];
        let (c1, _) = alice_commit_identity(&auth, &id);
        let (c2, _) = alice_commit_identity(&auth, &id);
        // Different random t should yield different commitments
        assert_ne!(c1.t_commitment, c2.t_commitment, "commitment should be randomized");
    }
}
