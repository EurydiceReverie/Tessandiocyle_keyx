#include "cbd.hpp"
#include "shake.hpp"
#include <algorithm>

namespace td18 {

void poly_getnoise_eta1(Poly& r, const std::array<uint8_t,SYMBYTES>& seed, uint8_t nonce) {
    std::array<uint8_t, 128> buf{};
    std::array<uint8_t, SYMBYTES + 1> in{};
    std::copy(seed.begin(), seed.end(), in.begin());
    in[SYMBYTES] = nonce;
    Keccak1600::shake256(buf.data(), buf.size(), in.data(), in.size());
    cbd2(r, buf);
}

void poly_getnoise_eta2(Poly& r, const std::array<uint8_t,SYMBYTES>& seed, uint8_t nonce) {
    poly_getnoise_eta1(r, seed, nonce);
}

} // namespace td18
