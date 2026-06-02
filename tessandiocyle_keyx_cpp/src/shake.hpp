#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <array>
#include <stdexcept>

namespace td18 {

/* Minimal self-contained SHAKE/SHA3 (FIPS 202) in C++.
   Keccak-f[1600] permutation, public domain.  */

class Keccak1600 {
    static constexpr size_t RATE_128 = 168; /* 1344 bits */
    static constexpr size_t RATE_256 = 136; /* 1088 bits */
    static constexpr size_t STATE_WORDS = 25;
    uint64_t st[STATE_WORDS]{};
    size_t pos{0};
    size_t rate{0};

    static void permute(uint64_t *s);
    void absorb(const uint8_t *in, size_t len);
    void squeeze(uint8_t *out, size_t len);

public:
    explicit Keccak1600(size_t r) : rate(r) {}

    /* SHAKE128/256: absorb, then squeeze */
    void shake128_absorb(const uint8_t *in, size_t len);
    void shake128_squeeze(uint8_t *out, size_t len);

    void shake256_absorb(const uint8_t *in, size_t len);
    void shake256_squeeze(uint8_t *out, size_t len);

    /* SHA3-256 / SHA3-512 one-shot */
    static void sha3_256(uint8_t out[32], const uint8_t *in, size_t len);
    static void sha3_512(uint8_t out[64], const uint8_t *in, size_t len);

    /* Convenience: SHAKE256 as XOF */
    static void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
};

} // namespace td18
