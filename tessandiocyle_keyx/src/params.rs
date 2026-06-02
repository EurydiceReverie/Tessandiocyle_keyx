// TessanDioKey v15 — Module-LWE parameters
// Based on CRYSTALS-Kyber reference with K=3 (Kyber-768 equivalent)

/// Security parameter: module rank
pub const KYBER_K: usize = 3;

/// Polynomial degree
pub const KYBER_N: usize = 256;

/// Modulus
pub const KYBER_Q: i16 = 3329;

/// Size of hashes/seeds in bytes
pub const KYBER_SYMBYTES: usize = 32;

/// Size of shared secret in bytes
pub const KYBER_SSBYTES: usize = 32;

// K-dependent parameters (for K=3)

/// ETA1 for CBD noise (K=3 uses 2)
pub const KYBER_ETA1: usize = 2;

/// ETA2 for CBD noise
pub const KYBER_ETA2: usize = 2;

/// Compressed polynomial bytes (du=10 for K=3 -> 320 bytes per polyvec element)
pub const KYBER_POLYCOMPRESSEDBYTES: usize = 128;

/// Compressed polyvec bytes (K * 320 for du=10)
pub const KYBER_POLYVECCOMPRESSEDBYTES: usize = KYBER_K * 320;

/// Serialized polynomial bytes
pub const KYBER_POLYBYTES: usize = 384;

/// Serialized polyvec bytes
pub const KYBER_POLYVECBYTES: usize = KYBER_K * KYBER_POLYBYTES;

/// INDCPA message bytes
pub const KYBER_INDCPA_MSGBYTES: usize = KYBER_SYMBYTES;

/// INDCPA public key bytes
pub const KYBER_INDCPA_PUBLICKEYBYTES: usize = KYBER_POLYVECBYTES + KYBER_SYMBYTES;

/// INDCPA secret key bytes
pub const KYBER_INDCPA_SECRETKEYBYTES: usize = KYBER_POLYVECBYTES;

/// INDCPA ciphertext bytes
pub const KYBER_INDCPA_BYTES: usize = KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES;

/// CCA public key bytes
pub const KYBER_PUBLICKEYBYTES: usize = KYBER_INDCPA_PUBLICKEYBYTES;

/// CCA secret key bytes (sk + pk + H(pk) + z)
pub const KYBER_SECRETKEYBYTES: usize =
    KYBER_INDCPA_SECRETKEYBYTES + KYBER_PUBLICKEYBYTES + 2 * KYBER_SYMBYTES;

/// CCA ciphertext bytes
pub const KYBER_CIPHERTEXTBYTES: usize = KYBER_INDCPA_BYTES;

// Dual-reconciliation parameters
pub const RECONCILE_Q_EFF: i16 = 8;
pub const RECONCILE_COARSE_BITS: usize = 3; // 3-bit bucket
pub const RECONCILE_FINE_BITS: usize = 1;   // 1-bit sub
pub const RECONCILE_SPECTRAL_BITS: usize = 2; // 2-bit Walsh-Hadamard spectral layer per 4-coeff block

// Graph-walk / epoch parameters
pub const GRAPH_NODES: usize = 256;
pub const GRAPH_DEGREE: usize = 12;
pub const GRAPH_EPOCH_WORK_FACTOR: u32 = 1 << 18; // ~262k sequential hashes (~5-10ms on modern CPU)

// Hybrid-binding & MAC parameters
pub const HYBRID_BINDING_BYTES: usize = 32;
pub const ALGEBRAIC_MAC_BYTES: usize = 2;
