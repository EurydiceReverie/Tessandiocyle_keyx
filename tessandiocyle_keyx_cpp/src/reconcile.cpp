#include "reconcile.hpp"

namespace td18 {

void reconcile_alice(std::array<uint8_t,RECON_BYTES>& hints, const Poly& v) {
    constexpr int16_t Q_EFF = 8;
    constexpr int COARSE_BITS = 3;
    constexpr int FINE_BITS = 1;
    constexpr int SPECTRAL_BITS = 2;
    constexpr int BLOCK = 4;
    size_t off = 0;
    for (int i = 0; i < N / BLOCK && off < RECON_BYTES; ++i) {
        int16_t bucket = 0;
        for (int j = 0; j < BLOCK; ++j) {
            int16_t t = v[i*BLOCK+j];
            t += (t >> 15) & Q;
            bucket += (t * Q_EFF + Q/2) / Q;
        }
        uint8_t coarse = bucket & ((1 << COARSE_BITS) - 1);
        uint8_t fine = (bucket >> COARSE_BITS) & ((1 << FINE_BITS) - 1);
        uint8_t spect = 0;
        for (int j = 0; j < 2 && off < RECON_BYTES; ++j) {
            int16_t a = v[i*BLOCK + 2*j];
            int16_t b = v[i*BLOCK + 2*j + 1];
            a += (a >> 15) & Q; b += (b >> 15) & Q;
            int16_t sum = a + b;
            int16_t diff = a - b;
            spect |= static_cast<uint8_t>((sum & 1) << (2*j));
            spect |= static_cast<uint8_t>((diff & 1) << (2*j + 1));
        }
        hints[off++] = coarse | (fine << COARSE_BITS) | (spect << (COARSE_BITS + FINE_BITS));
    }
}

int reconcile_verify(const Poly& va, const Poly& vb) {
    std::array<uint8_t,RECON_BYTES> ha{}, hb{};
    reconcile_alice(ha, va);
    reconcile_alice(hb, vb);
    for (int i = 0; i < RECON_BYTES; ++i) {
        if (ha[i] != hb[i]) return -1;
    }
    return 0;
}

} // namespace td18
