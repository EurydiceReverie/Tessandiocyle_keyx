#pragma once
#include "params.hpp"
#include <array>

namespace td18 {

void gen_matrix(std::array<PolyVec,K>& a, const std::array<uint8_t,SYMBYTES>& seed, bool transposed);

void indcpa_keypair_derand(std::array<uint8_t,INDCPA_PUBLICKEYBYTES>& pk,
                           std::array<uint8_t,INDCPA_SECRETKEYBYTES>& sk,
                           const std::array<uint8_t,SYMBYTES>& coins);

void indcpa_enc(std::array<uint8_t,INDCPA_BYTES>& c,
                const std::array<uint8_t,SYMBYTES>& m,
                const std::array<uint8_t,INDCPA_PUBLICKEYBYTES>& pk,
                const std::array<uint8_t,SYMBYTES>& coins);

void indcpa_dec(std::array<uint8_t,SYMBYTES>& m,
                const std::array<uint8_t,INDCPA_BYTES>& c,
                const std::array<uint8_t,INDCPA_SECRETKEYBYTES>& sk);

} // namespace td18
