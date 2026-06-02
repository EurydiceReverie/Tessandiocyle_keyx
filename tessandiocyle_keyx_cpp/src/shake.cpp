#include "shake.hpp"

namespace td18 {

static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static uint64_t rotl(uint64_t x, unsigned n) { return (x << n) | (x >> (64 - n)); }

void Keccak1600::permute(uint64_t *s) {
    for (int round = 0; round < 24; ++round) {
        uint64_t C[5], D[5];
        /* theta */
        for (int x = 0; x < 5; ++x) C[x] = s[x] ^ s[x+5] ^ s[x+10] ^ s[x+15] ^ s[x+20];
        for (int x = 0; x < 5; ++x) D[x] = C[(x+4)%5] ^ rotl(C[(x+1)%5], 1);
        for (int x = 0; x < 5; ++x) for (int y = 0; y < 5; ++y) s[x + 5*y] ^= D[x];
        /* rho + pi */
        uint64_t B[25];
        static const unsigned rot[25] = {
            0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43,
            25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14
        };
        for (int x = 0; x < 5; ++x)
            for (int y = 0; y < 5; ++y)
                B[y + 5*((2*x+3*y)%5)] = rotl(s[x + 5*y], rot[x + 5*y]);
        /* chi */
        for (int x = 0; x < 5; ++x)
            for (int y = 0; y < 5; ++y)
                s[x + 5*y] = B[x + 5*y] ^ ((~B[(x+1)%5 + 5*y]) & B[(x+2)%5 + 5*y]);
        /* iota */
        s[0] ^= RC[round];
    }
}

void Keccak1600::absorb(const uint8_t *in, size_t len) {
    while (len > 0) {
        size_t chunk = (len < rate - pos) ? len : rate - pos;
        for (size_t i = 0; i < chunk; ++i)
            reinterpret_cast<uint8_t*>(st)[pos + i] ^= in[i];
        pos += chunk;
        in += chunk;
        len -= chunk;
        if (pos == rate) { permute(st); pos = 0; }
    }
}

void Keccak1600::squeeze(uint8_t *out, size_t len) {
    while (len > 0) {
        if (pos == rate) { permute(st); pos = 0; }
        size_t chunk = (len < rate - pos) ? len : rate - pos;
        std::memcpy(out, reinterpret_cast<uint8_t*>(st) + pos, chunk);
        pos += chunk;
        out += chunk;
        len -= chunk;
    }
}

void Keccak1600::shake128_absorb(const uint8_t *in, size_t len) {
    absorb(in, len);
    reinterpret_cast<uint8_t*>(st)[pos] ^= 0x1F;
    reinterpret_cast<uint8_t*>(st)[rate - 1] ^= 0x80;
    permute(st);
    pos = 0;
}

void Keccak1600::shake128_squeeze(uint8_t *out, size_t len) {
    squeeze(out, len);
}

void Keccak1600::shake256_absorb(const uint8_t *in, size_t len) {
    absorb(in, len);
    reinterpret_cast<uint8_t*>(st)[pos] ^= 0x1F;
    reinterpret_cast<uint8_t*>(st)[rate - 1] ^= 0x80;
    permute(st);
    pos = 0;
}

void Keccak1600::shake256_squeeze(uint8_t *out, size_t len) {
    squeeze(out, len);
}

void Keccak1600::sha3_256(uint8_t out[32], const uint8_t *in, size_t len) {
    Keccak1600 ctx(136);
    ctx.absorb(in, len);
    ctx.st[ctx.pos / 8] ^= 0x06ULL << (8 * (ctx.pos % 8));
    reinterpret_cast<uint8_t*>(ctx.st)[135] ^= 0x80;
    permute(ctx.st);
    std::memcpy(out, ctx.st, 32);
}

void Keccak1600::sha3_512(uint8_t out[64], const uint8_t *in, size_t len) {
    Keccak1600 ctx(72);
    ctx.absorb(in, len);
    ctx.st[ctx.pos / 8] ^= 0x06ULL << (8 * (ctx.pos % 8));
    reinterpret_cast<uint8_t*>(ctx.st)[71] ^= 0x80;
    permute(ctx.st);
    std::memcpy(out, ctx.st, 64);
}

void Keccak1600::shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
    Keccak1600 ctx(136);
    ctx.shake256_absorb(in, inlen);
    ctx.shake256_squeeze(out, outlen);
}

} // namespace td18
