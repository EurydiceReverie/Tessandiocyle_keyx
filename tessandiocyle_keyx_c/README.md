<h1 align="center">TessanDioKey V18</h1>
<p align="center"><strong>Native C Implementation</strong></p>

<p align="center">
  <img src="https://img.shields.io/badge/language-C-blue" alt="Language: C">
  <img src="https://img.shields.io/badge/tests-all%20passing-brightgreen" alt="Tests: all passing">
  <img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue" alt="License: MIT/Apache-2.0">
  <img src="https://img.shields.io/badge/post--quantum-KEM-9cf" alt="Post-Quantum: KEM">
  <img src="https://img.shields.io/badge/symmetric-SHAKE%2FSHA3%20(FIPS%20202)-informational" alt="Symmetric: SHAKE/SHA3 (FIPS 202)">
</p>

---

Self-contained, native C implementation of the **TessanDioKey V18** post-quantum key-exchange protocol. Translated directly from Rust V18 with no external wrapper dependencies.

## What is TessanDioKey?

TessanDioKey V18 is a module-lattice-based KEM (KYBER-768 class arithmetic) with protocol-layer hardening for high-assurance deployments:

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
| Symmetric primitive | SHAKE-128 / SHA3 | **SHAKE-256 / SHA3-256 / SHA3-512** |

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

> **Note:** SHAKE/SHA3 replaces BLAKE3 used in the Rust reference for structural equivalence. Byte-level test vectors will differ, but the mathematical protocol is identical.

## Features

- Zero external dependencies — self-contained `fips202.c` and `randombytes.c`.
- Compatible with GCC, Clang, and MSVC.
- Includes standalone debug utilities in `debug_test_ref_c/` for troubleshooting.
- Full integration test suite (`tests/cli_test.c`).

## Build

### Using Make (Linux / macOS / MinGW)

```bash
cd tessandiocyle_keyx_c
make
```

### Using CMake (cross-platform)

```bash
cd tessandiocyle_keyx_c
mkdir build && cd build
cmake ..
cmake --build .
```

### Manual compile (GCC)

```bash
cd tessandiocyle_keyx_c
gcc -O2 -Wall -Wextra -o cli_test tests/cli_test.c *.c
```

### Windows (MSVC)

```cmd
cd tessandiocyle_keyx_c
cl /O2 /W3 /Fecli_test.exe tests/cli_test.c *.c
```

## Test Commands

### Run integration test
```bash
./tests/cli_test
# Windows:
cli_test.exe
```

### Run debug utilities (after `make` in debug_test_ref_c)
```bash
cd debug_test_ref_c
make
./debug_ntt
./debug_indcpa
./debug_compress
./debug_tomsg
./debug_frommsg
./debug_genmatrix
./debug_enc_detailed
./debug_cmp
```

## Usage Example

### Basic key exchange

```c
#include "tessandiocyle_keyx.h"
#include <stdio.h>
#include <string.h>

int main() {
    uint8_t pk[TD18_PUBLICKEYBYTES];
    uint8_t sk[TD18_SECRETKEYBYTES];
    uint8_t ct[TD18_CIPHERTEXTBYTES];
    uint8_t ss_enc[TD18_SSBYTES];
    uint8_t ss_dec[TD18_SSBYTES];

    td18_kem_keypair(pk, sk);
    td18_kem_enc(ct, ss_enc, pk);
    td18_kem_dec(ss_dec, ct, sk);

    if (memcmp(ss_enc, ss_dec, TD18_SSBYTES) == 0) {
        printf("Shared secret matches!\n");
    }
    return 0;
}
```

### Displaying key material (hex dump)

```c
#include "tessandiocyle_keyx.h"
#include <stdio.h>

static void hex(const char *label, const uint8_t *buf, size_t len) {
    printf("%s (%3zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

int main() {
    uint8_t pk[TD18_PUBLICKEYBYTES];
    uint8_t sk[TD18_SECRETKEYBYTES];
    uint8_t ct[TD18_CIPHERTEXTBYTES];
    uint8_t ss_enc[TD18_SSBYTES];
    uint8_t ss_dec[TD18_SSBYTES];

    td18_kem_keypair(pk, sk);
    td18_kem_enc(ct, ss_enc, pk);
    td18_kem_dec(ss_dec, ct, sk);

    hex("Alice Public Key",  pk, sizeof(pk));
    hex("Alice Secret Key",  sk, sizeof(sk));
    hex("Ciphertext",        ct, sizeof(ct));
    hex("Shared Secret Bob", ss_enc, sizeof(ss_enc));
    hex("Shared Secret Alice", ss_dec, sizeof(ss_dec));
    return 0;
}
```

### Compile & run

```bash
# Save as usage.c
gcc -O2 -Wall -o usage usage.c *.c
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

### Design Notes

- **No external dependencies** — `fips202.c` and `randombytes.c` are local copies; no dynamic linking to external crypto libraries.
- **Structurally equivalent to Rust V18** — same algorithms, same control flow, same constants; only the symmetric primitive differs.
- **Production + debug artifacts separated** — `debug_test_ref_c/` contains standalone diagnostic tools (not linked in normal builds).

## License

Dual-licensed under **MIT** or **Apache-2.0**.
