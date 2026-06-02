<h1 align="center">TessanDioKey V18</h1>
<p align="center"><strong>Primary Reference Implementation — Rust</strong></p>

<p align="center">
  <img src="https://img.shields.io/badge/language-Rust-dea584" alt="Language: Rust">
  <img src="https://img.shields.io/badge/tests-all%20passing-brightgreen" alt="Tests: all passing">
  <img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue" alt="License: MIT/Apache-2.0">
  <img src="https://img.shields.io/badge/post--quantum-KEM-9cf" alt="Post-Quantum: KEM">
  <img src="https://img.shields.io/badge/arithmetic-CRYSTALS--Kyber%20class-informational" alt="Arithmetic: CRYSTALS-Kyber class">
</p>

---

Native Rust implementation of the **TessanDioKey V18** post-quantum key-exchange protocol. This is the primary reference implementation against which the C and C++ ports are verified.

## What is TessanDioKey?

TessanDioKey V18 is a module-lattice-based key encapsulation mechanism (KEM) built on the CRYSTALS-Kyber arithmetic core. Unlike stock Kyber, it adds **protocol-layer hardening** designed for high-assurance deployments:

- **Feistel-shuffled NTT**
- **Graph-based key reconciliation**
- **Triple-redundant decapsulation**
- **Merkle proofs over polynomial coefficients**
- **Trapdoor identity commitments**
- **VDF rate-limiting**

### How is this different from standard CRYSTALS-Kyber?

| Feature | Standard Kyber | TessanDioKey V18 |
|---|---|---|
| NTT structure | Fixed butterfly order | **Feistel-shuffled per session** |
| Reconciliation | Modulus-switching hints | **Expander-graph based** |
| Decapsulation | Single path | **Triple-redundant + VDF rate-limit** |
| Transcript proof | None | **Merkle proofs over coefficients** |
| Identity escrow | None | **Trapdoor commitments** |
| Symmetric primitive | SHAKE-128 / SHA3 | **BLAKE3** (Rust), SHAKE/SHA3 (C/C++) |

## Key Exchange Protocol (Alice & Bob)

TessanDioKey follows the standard KEM flow with additional protocol-layer hardening:

```
Alice                                  Bob
  |                                      |
  |  1. Generate keypair                 |
  |     (pk, sk)                         |
  |                                      |
  |  2. Send public key pk  ──────────>  |
  |                                      |
  |                            3. Encapsulate(pk)
  |                               → ciphertext ct
  |                               → shared secret ss
  |                                      |
  |  4. Receive ct  <──────────────────  |
  |                                      |
  |  5. Decapsulate(ct, sk)              |
  |     → same shared secret ss          |
  |                                      |
  |  [Protocol Layer — TessanDioKey]     |
  |                                      |
  |  6. Graph reconciliation hints       |
  |     → verify coefficient agreement   |
  |                                      |
  |  7. MAC tag verification             |
  |     → anti-tamper binding            |
  |                                      |
  |  8. Merkle commitment                |
  |     → transcript integrity proof     |
  |                                      |
  |  9. Final key derivation             |
  |     → derive_final_key(ss, binding)  |
  |                                      |
  |  =====  Both now hold identical      |
  |        cryptographically bound keys  |
```

### What makes this flow unique?

| Step | Standard KEM | TessanDioKey V18 Addition |
|---|---|---|
| 1–5 | Basic encaps/decaps | Feistel-shuffled NTT for side-channel resistance |
| 6 | None | Graph reconciliation to avoid modulus-switching leakage |
| 7 | None | MAC tag binds ciphertext to shared secret |
| 8 | None | Merkle proof provides post-hoc transcript verification |
| 9 | Direct key use | Final key derivation with epoch parameters and binding |

## Security Parameters

| Parameter | Value |
|---|---|
| `K` | 3 |
| `N` | 256 |
| `Q` | 3329 |
| ETA1 | 2 |
| ETA2 | 2 |
| **Symmetric Primitive** | **BLAKE3** |

## Features

- Pure Rust, `no_std`-friendly core (only depends on `rand` and `blake3`).
- Deterministic and randomized key generation.
- Constant-time `cmov` and conditional-swap utilities.
- Secure zeroization helpers.
- Comprehensive internal unit tests (`cargo test`).
- CLI benchmark and DudeCT timing-test binaries included.

## Build

```bash
cargo build --release
```

## Test Commands

### Run all unit tests
```bash
cargo test
```

### Run a specific module test
```bash
cargo test ntt::tests
cargo test kem::tests
cargo test trapdoor::tests
```

### Run CLI integration test
```bash
cargo run --bin cli_test
```

### Run benchmark
```bash
cargo run --bin bench --release
```

### Run DudeCT constant-time test
```bash
cargo run --bin dudect --release
```

### Run example (deterministic verification)
```bash
cargo run --example verify_det
```

## Usage Example

### Basic key exchange

```rust
use tessandiocyle_keyx::{kem_keypair, kem_enc, kem_dec};

// Alice generates a keypair
let (pk, sk) = kem_keypair();

// Bob encapsulates a shared secret using Alice's public key
let (ct, ss_bob) = kem_enc(&pk);

// Alice decapsulates the shared secret using her secret key
let ss_alice = kem_dec(&ct, &sk);

assert_eq!(ss_bob, ss_alice);
```

### Displaying key material (hex dump)

```rust
use tessandiocyle_keyx::{kem_keypair, kem_enc, kem_dec, PUBLICKEYBYTES, SECRETKEYBYTES, CIPHERTEXTBYTES, SSBYTES};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    let (pk, sk) = kem_keypair();
    let (ct, ss_bob) = kem_enc(&pk);
    let ss_alice = kem_dec(&ct, &sk);

    println!("Alice Public Key  ({:>3} bytes): {}", PUBLICKEYBYTES, hex(&pk));
    println!("Alice Secret Key  ({:>3} bytes): {}", SECRETKEYBYTES, hex(&sk));
    println!("Ciphertext        ({:>3} bytes): {}", CIPHERTEXTBYTES, hex(&ct));
    println!("Shared Secret Bob ({:>3} bytes): {}", SSBYTES, hex(&ss_bob));
    println!("Shared Secret Alice ({:>1} bytes): {}", SSBYTES, hex(&ss_alice));
}
```

### Compile & run

```bash
# Save as main.rs and compile with cargo
cargo run --example verify_det
```

### Expected output

```
Alice Public Key  (1184 bytes): a1b2c3d4e5f6... (hex truncated)
Alice Secret Key  (2400 bytes): 7f8e9d0c1b2a... (hex truncated)
Ciphertext        (1088 bytes): 3e4f5a6b7c8d... (hex truncated)
Shared Secret Bob   (32 bytes): 8a9b0c1d2e3f... (hex truncated)
Shared Secret Alice (32 bytes): 8a9b0c1d2e3f... (hex truncated)
```
```

## License

This project is dual-licensed under either:

- MIT License ([LICENSE-MIT](LICENSE-MIT))
- Apache License 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project shall be dual-licensed as above, without any additional terms or conditions.