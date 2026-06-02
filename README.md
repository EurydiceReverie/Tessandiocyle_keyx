<h1 align="center">TessanDioKey V18</h1>
<p align="center"><strong>Post-Quantum Key Exchange Protocol</strong></p>

<p align="center">
  <img src="https://img.shields.io/badge/post--quantum-KEM-9cf" alt="Post-Quantum: KEM">
  <img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue" alt="License: MIT/Apache-2.0">
  <img src="https://img.shields.io/badge/arithmetic-CRYSTALS--Kyber%20class-informational" alt="Arithmetic: CRYSTALS-Kyber class">
</p>

<p align="center">
  <a href="tessandiocyle_keyx/">Rust</a> &bull;
  <a href="tessandiocyle_keyx_c/">C</a> &bull;
  <a href="tessandiocyle_keyx_cpp/">C++</a>
</p>

---

## What is TessanDioKey?

TessanDioKey V18 is a module-lattice-based key encapsulation mechanism (KEM) built on the CRYSTALS-Kyber arithmetic core with protocol-layer hardening designed for high-assurance deployments.

It establishes a shared secret between two parties — **Alice** and **Bob** — over an insecure channel, protected against both classical and quantum adversaries.

## How It Works (Alice & Bob)

```
Alice                                  Bob
  |                                      |
  |  1. Generate keypair (pk, sk)        |
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
  |  6. Graph reconciliation             |
  |  7. MAC tag verification             |
  |  8. Merkle commitment                |
  |  9. Final key derivation             |
  |                                      |
  |  ===== Both hold identical keys =====|
```

## Features

| Feature | Description |
|---|---|
| **Feistel-shuffled NTT** | Session-keyed Feistel network permutes butterfly indices to break DPA temporal alignment |
| **Graph-based reconciliation** | Expander-graph reconciliation avoids modulus-switching leakage |
| **Triple-redundant decapsulation** | Three independent decaps attempts detect fault-injection glitches |
| **Merkle proofs** | Post-hoc transcript integrity verification over polynomial coefficients |
| **Trapdoor commitments** | Privacy-preserving identity escrow for enterprise key-escrow requirements |
| **VDF rate-limiting** | Time-lock delays on repeated decapsulation attempts |

## How is this different from standard CRYSTALS-Kyber?

| Feature | Standard Kyber | TessanDioKey V18 |
|---|---|---|
| NTT structure | Fixed butterfly order | **Feistel-shuffled per session** |
| Reconciliation | Modulus-switching hints | **Expander-graph based** |
| Decapsulation | Single path | **Triple-redundant + VDF rate-limit** |
| Transcript proof | None | **Merkle proofs over coefficients** |
| Identity escrow | None | **Trapdoor commitments** |
| Symmetric primitive | SHAKE-128 / SHA3 | **BLAKE3** (Rust), **SHAKE/SHA3** (C/C++) |

## Security Parameters

| Parameter | Value |
|---|---|
| `K` | 3 |
| `N` | 256 |
| `Q` | 3329 |
| ETA1 | 2 |
| ETA2 | 2 |

## Implementations

Three independent, standalone implementations — all algorithmically equivalent (Rust is the primary reference):

| Language | Directory | Symmetric Primitive | Status |
|---|---|---|---|
| **Rust** (primary) | [`tessandiocyle_keyx/`](tessandiocyle_keyx/) | BLAKE3 | All tests passing |
| **C** | [`tessandiocyle_keyx_c/`](tessandiocyle_keyx_c/) | SHAKE-256 / SHA3 (FIPS 202) | All tests passing |
| **C++17** | [`tessandiocyle_keyx_cpp/`](tessandiocyle_keyx_cpp/) | SHAKE-256 / SHA3 (FIPS 202) | All tests passing |

Each implementation is fully self-contained with zero external dependencies. Click a language above for build instructions, usage examples, and API details.

## Quick Start

**Rust:**
```bash
cd tessandiocyle_keyx
cargo test
```

**C:**
```bash
cd tessandiocyle_keyx_c
make
./tests/cli_test
```

**C++:**
```bash
cd tessandiocyle_keyx_cpp
make
./cli_test.exe
```

## License

Dual-licensed under **MIT** or **Apache-2.0**.
