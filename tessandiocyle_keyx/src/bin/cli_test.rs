use tessandiocyle_keyx::*;
use tessandiocyle_keyx::merkle::build_merkle_tree;
use tessandiocyle_keyx::trapdoor::{generate_trapdoor_authority, alice_commit_identity};

fn main() {
    println!("=== TessanDioKey v18 — Hardened Module-LWE KEM ===\n");

    let params = generate_params();
    println!("Parameters: Module-LWE K=3 (Kyber-768 equivalent), N=256, Q=3329");
    println!("Reconciliation: Tri-layer (coarse 3-bit + fine 1-bit + spectral 2-bit WHT)");
    println!("Novelty: Entropy-Diffusion Mesh + GraphEpoch VDF evolution");
    println!("Integrity: Hybrid binding (anti-UKS) + 2-byte session MAC + BLAKE3 commitment");
    println!("Defense-in-depth: Fail-safe XOR overlay (Base key XOR Novelty key)");
    println!("Accountability: Lattice trapdoor identity commitment");
    println!("Transparency: Merkle-tree polynomial commitment\n");

    // Honest exchange
    let (pk, sk) = keypair(&params);
    println!("Alice keypair generated.");

    let (cipher, bob_key) = bob_encapsulate(&params, &pk);
    println!("Bob encapsulated shared secret.");

    let alice_key = alice_decapsulate(&params, &sk, &pk, &cipher);
    println!("Alice decapsulated shared secret.");

    print!("Alice key: ");
    for b in &alice_key[..4] {
        print!("{:02x}", b);
    }
    println!("...");

    print!("Bob key:   ");
    for b in &bob_key[..4] {
        print!("{:02x}", b);
    }
    println!("...\n");

    let match_bytes = alice_key
        .iter()
        .zip(bob_key.iter())
        .filter(|(a, b)| a == b)
        .count();
    println!(
        "Match: {}/{} bytes ({:.1}%)",
        match_bytes,
        KYBER_SSBYTES,
        match_bytes as f64 / KYBER_SSBYTES as f64 * 100.0
    );

    if alice_key == bob_key {
        println!("\n[PASS] Keys match perfectly — protocol is sound.");
    } else {
        println!("\n[FAIL] Keys do not match!");
        std::process::exit(1);
    }

    // Demonstrate v18 features
    println!("\n--- v18 Features ---");
    println!("Binding ephemeral t:    {:02x}{:02x}...", cipher.binding[0], cipher.binding[1]);
    println!("Session MAC tag:        {:02x}{:02x}", cipher.mac_tag[0], cipher.mac_tag[1]);
    println!("Commitment nonce:       {:?}", &cipher.commitment.nonce[..8]);
    println!("Commitment hash:        {:02x}{:02x}...", cipher.commitment.hash[0], cipher.commitment.hash[1]);

    // Merkle tree over first polynomial coefficients
    let coeffs: Vec<i16> = (0..params::KYBER_N)
        .map(|i| (i as i16 * 13) % params::KYBER_Q)
        .collect();
    let (merkle_root, _tree) = build_merkle_tree(&coeffs);
    println!("Merkle root (coeffs):   {:02x}{:02x}...", merkle_root[0], merkle_root[1]);

    // Trapdoor identity commitment
    let auth = generate_trapdoor_authority();
    let id = [0x42u8; 32];
    let (trapdoor_commit, _t) = alice_commit_identity(&auth, &id);
    println!("Trapdoor challenge:     {:02x}{:02x}...", trapdoor_commit.challenge[0], trapdoor_commit.challenge[1]);
    println!("Trapdoor t-commitment:  {:02x}{:02x}...", trapdoor_commit.t_commitment[0], trapdoor_commit.t_commitment[1]);
}
