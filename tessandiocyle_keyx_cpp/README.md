<h1 align="center">TessanDioKey V18</h1>
<p align="center"><strong>Native C++17 Implementation</strong></p>

<p align="center">
  <img src="https://img.shields.io/badge/language-C%2B%2B17-00599C" alt="Language: C++17">
  <img src="https://img.shields.io/badge/tests-all%20passing-brightgreen" alt="Tests: all passing">
  <img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue" alt="License: MIT/Apache-2.0">
  <img src="https://img.shields.io/badge/post--quantum-KEM-9cf" alt="Post-Quantum: KEM">
  <img src="https://img.shields.io/badge/symmetric-SHAKE%2FSHA3%20(FIPS%20202)-informational" alt="Symmetric: SHAKE/SHA3 (FIPS 202)">
</p>

---

Pure native C++17 implementation of the **TessanDioKey V18** post-quantum key-exchange protocol. Translated directly from Rust V18 with no external crypto library dependencies.

## What is TessanDioKey?

TessanDioKey V18 is a module-lattice-based KEM (KYBER-768 class parameters) with advanced protocol hardening for high-assurance deployments:

- **Feistel-shuffled NTT** — session-keyed Feistel network permutes butterfly indices inside the NTT to break DPA temporal alignment.
- **Graph-based key reconciliation** — expander-graph reconciliation avoids traditional modulus-switching leakage.
- **Triple-redundant decapsulation** — three independent decapsulation attempts detect fault-injection glitches.
- **Merkle proofs over polynomial coefficients** — post-hoc transcript integrity verification.
- **Trapdoor identity commitments** — privacy-preserving identity escrow for enterprise key-escrow requirements.
- **VDF rate-limiting** — time-lock delays on repeated decapsulation attempts.

### How is this different from standard CRYSTALS-Kyber?

| Feature | Standard Kyber | TessanDioKey V18 |
|---|---|---|
| NTT structure | Fixed butterfly order | **Feistel-shuffled per session** |
| Reconciliation | Modulus-switching hints | **Expander-graph based** |
| Decapsulation | Single path | **Triple-redundant + VDF rate-limit** |
| Transcript proof | None | **Merkle proofs over coefficients** |
| Identity escrow | None | **Trapdoor commitments** |
| Symmetric primitive | SHAKE-128 / SHA3 | **SHAKE-256 / SHA3-256 / SHA3-512** (self-contained Keccak) |

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
| **Symmetric Primitive** | **SHAKE-256 / SHA3-256 / SHA3-512** *(FIPS 202)* |

> **Note:** SHAKE/SHA3 replaces BLAKE3 used in the Rust reference for structural equivalence. Deterministic byte outputs will differ from Rust, but the mathematical protocol is identical.

## Features

- Pure C++17 — no C artifacts compiled; entirely self-contained.
- Self-contained Keccak-f[1600] implementation in `shake.hpp/cpp` — no OpenSSL, no Crypto++.
- Cross-platform: GCC, Clang, MSVC compatible.
- Includes SHA3/SHAKE test-vector verification (`tests/test_hash.cpp`).
- Full integration test suite (`tests/cli_test.cpp`).

## Build

### Using Make (Linux / macOS / MinGW)

```bash
cd tessandiocyle_keyx_cpp
make
```

### Using CMake (cross-platform)

```bash
cd tessandiocyle_keyx_cpp
mkdir build && cd build
cmake ..
cmake --build .
```

### Manual compile (all platforms)

```bash
cd tessandiocyle_keyx_cpp
g++ -std=c++17 -O2 -Wall -Wextra -Isrc \
  -o cli_test.exe tests/cli_test.cpp \
  src/shake.cpp src/ntt.cpp src/cbd.cpp src/indcpa.cpp \
  src/kem.cpp src/graph.cpp src/reconcile.cpp \
  src/protocol.cpp src/merkle.cpp src/trapdoor.cpp \
  src/random.cpp
```

### Windows (MSVC)

```cmd
cd tessandiocyle_keyx_cpp
cl /std:c++17 /O2 /W3 /Isrc /Fecli_test.exe tests\cli_test.cpp src\*.cpp
```

## Test Commands

### Run full integration test
```bash
./cli_test.exe
```

### Run SHA3/SHAKE test-vector verification
```bash
g++ -std=c++17 -O2 -Wall -Wextra -Isrc -o test_hash.exe tests/test_hash.cpp src/shake.cpp
./test_hash.exe
```

### Run individual modules (compile specific test file if you add one)
```bash
g++ -std=c++17 -O2 -Isrc -o test_ntt.exe tests/test_ntt.cpp src/ntt.cpp src/shake.cpp ...
```

## Usage Example

### Basic key exchange

```cpp
#include "kem.hpp"
#include <cstdio>
#include <cstring>

int main() {
    std::array<uint8_t, td18::PUBLICKEYBYTES> pk;
    std::array<uint8_t, td18::SECRETKEYBYTES> sk;
    std::array<uint8_t, td18::CIPHERTEXTBYTES> ct;
    std::array<uint8_t, td18::SSBYTES> ss_enc, ss_dec;

    td18::kem_keypair(pk, sk);
    td18::kem_enc(ct, ss_enc, pk);
    td18::kem_dec(ss_dec, ct, sk);

    if (ss_enc == ss_dec) {
        printf("Shared secret matches!\n");
    }
    return 0;
}
```

### Displaying key material (hex dump)

```cpp
#include "kem.hpp"
#include <cstdio>
#include <array>

static void hex(const char *label, const uint8_t *buf, size_t len) {
    printf("%s (%3zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

int main() {
    std::array<uint8_t, td18::PUBLICKEYBYTES> pk;
    std::array<uint8_t, td18::SECRETKEYBYTES> sk;
    std::array<uint8_t, td18::CIPHERTEXTBYTES> ct;
    std::array<uint8_t, td18::SSBYTES> ss_enc, ss_dec;

    td18::kem_keypair(pk, sk);
    td18::kem_enc(ct, ss_enc, pk);
    td18::kem_dec(ss_dec, ct, sk);

    hex("Alice Public Key",    pk.data(), pk.size());
    hex("Alice Secret Key",    sk.data(), sk.size());
    hex("Ciphertext",          ct.data(), ct.size());
    hex("Shared Secret Bob",   ss_enc.data(), ss_enc.size());
    hex("Shared Secret Alice", ss_dec.data(), ss_dec.size());
    return 0;
}
```

### Compile & run

```bash
# Save as usage.cpp
g++ -std=c++17 -O2 -Wall -Wextra -Isrc \
  -o usage usage.cpp \
  src/shake.cpp src/ntt.cpp src/cbd.cpp src/indcpa.cpp \
  src/kem.cpp src/graph.cpp src/reconcile.cpp \
  src/protocol.cpp src/merkle.cpp src/trapdoor.cpp \
  src/random.cpp
./usage
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

## Expected Test Output

```
=== TessanDioKey V18 C++ Native Test ===
[PASS] params_init
[PASS] keypair
[PASS] indcpa_roundtrip
[PASS] encaps
[PASS] decaps
[PASS] base_kem_agreement
[PASS] final_key_agreement
[PASS] mac_verify
[PASS] commitment_verify
[PASS] reconcile_self_verify
[PASS] params_evolve
[PASS] trapdoor_id
[PASS] ct_cswap_on
[PASS] ct_cswap_off
[PASS] merkle_build
[PASS] merkle_verify
[PASS] merkle_tamper
[PASS] trapdoor_gen
[PASS] trapdoor_commit
[PASS] trapdoor_wrong_id
=== Result: ALL PASS ===
```

## Project Structure

```
tessandiocyle_keyx_cpp/
  Makefile               — Native build rules (Make)
  src/
    params.hpp       — Constants, Poly/PolyVec type aliases
    reduce.hpp       — Barrett and Montgomery reduction (inline)
    ntt.hpp / ntt.cpp — NTT with Feistel-shuffled butterflies
    poly.hpp         — Polynomial compression, tomsg/frommsg, arithmetic
    polyvec.hpp      — Poly-vector ops (NTT, basemul, compress)
    cbd.hpp / cbd.cpp — Centered binomial distribution noise sampling
    indcpa.hpp / indcpa.cpp — IND-CPA keygen, enc, dec
    kem.hpp / kem.cpp — CCA KEM encaps / decaps
    graph.hpp / graph.cpp — Expander graph for reconciliation
    reconcile.hpp / reconcile.cpp — Reconciliation hints & verify
    merkle.hpp / merkle.cpp — Merkle tree over coefficients
    trapdoor.hpp / trapdoor.cpp — Trapdoor authority & commitments
    protocol.hpp / protocol.cpp — Final key, MAC, commitment
    secure.hpp       — Constant-time cmov, zeroize
    verify.hpp       — Constant-time conditional swap
    random.hpp / random.cpp — Secure random bytes (Windows / Linux)
    shake.hpp / shake.cpp — Self-contained Keccak-f[1600] (FIPS 202)
  tests/
    cli_test.cpp     — Full integration test suite
    test_hash.cpp    — SHA3/SHAKE test-vector verification
```

### Design Notes

- **Pure C++17** — no compilation of C artifacts; entirely self-contained.
- **Self-contained Keccak** — `shake.hpp/cpp` implements Keccak-f[1600] directly in C++; no OpenSSL, no Crypto++.
- **Structurally equivalent to Rust V18** — same NTT structure, same Feistel permutation, same arithmetic. Only the hash primitive differs.
- **Deterministic tests** — `ntt_seed(0)` is used in tests for reproducible output.

## License

Dual-licensed under **MIT** or **Apache-2.0**.
