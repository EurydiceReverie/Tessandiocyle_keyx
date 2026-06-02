// TessanDioKey v17 — Symmetric primitives using BLAKE3 with stateful XOF streaming
use std::io::Read;

/// Hash function H (replaces SHA3-256): 32-byte output.
pub fn hash_h(out: &mut [u8; 32], input: &[u8]) {
    let hash = blake3::hash(input);
    out.copy_from_slice(hash.as_bytes());
}

/// Hash function G (replaces SHA3-512): 64-byte output via XOF.
pub fn hash_g(out: &mut [u8; 64], input: &[u8]) {
    let mut hasher = blake3::Hasher::new();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    reader.read_exact(out).unwrap();
}

/// XOF for matrix generation: absorb seed||x||y, then squeeze `outlen` bytes.
/// Stateless convenience wrapper.
pub fn xof(seed: &[u8], x: u8, y: u8, out: &mut [u8]) {
    let mut hasher = blake3::Hasher::new();
    hasher.update(seed);
    hasher.update(&[x, y]);
    let mut reader = hasher.finalize_xof();
    reader.read_exact(out).unwrap();
}

/// Stateful XOF reader for matrix generation.
/// Created once per (seed, x, y) and used to squeeze blocks incrementally.
pub struct XofReader {
    reader: blake3::OutputReader,
}

impl XofReader {
    /// Absorb seed||x||y and create a streaming reader.
    pub fn new(seed: &[u8], x: u8, y: u8) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(seed);
        hasher.update(&[x, y]);
        XofReader {
            reader: hasher.finalize_xof(),
        }
    }

    /// Squeeze `out.len()` bytes into `out`.
    pub fn squeeze(&mut self, out: &mut [u8]) {
        self.reader.read_exact(out).unwrap();
    }
}

/// PRF for noise generation: keyed by `key`, domain-separated by `nonce`.
/// Fills `out` (which must be sized exactly to the needed length).
pub fn prf(out: &mut [u8], _len: usize, key: &[u8], nonce: u8) {
    let mut hasher = blake3::Hasher::new();
    hasher.update(key);
    hasher.update(&[nonce]);
    let mut reader = hasher.finalize_xof();
    reader.read_exact(out).unwrap();
}

/// Rejection key PRF: derive pseudo-random output for implicit rejection.
pub fn rkprf(out: &mut [u8; 32], key: &[u8; 32], input: &[u8]) {
    let mut hasher = blake3::Hasher::new();
    hasher.update(key);
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    reader.read_exact(out).unwrap();
}
