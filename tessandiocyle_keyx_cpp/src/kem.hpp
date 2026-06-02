#pragma once
#include "params.hpp"
#include <array>

namespace td18 {

void kem_keypair_derand(std::array<uint8_t,PUBLICKEYBYTES>& pk,
                        std::array<uint8_t,SECRETKEYBYTES>& sk,
                        const std::array<uint8_t,2*SYMBYTES>& coins);

void kem_enc_derand(std::array<uint8_t,CIPHERTEXTBYTES>& ct,
                    std::array<uint8_t,SSBYTES>& ss,
                    const std::array<uint8_t,PUBLICKEYBYTES>& pk,
                    const std::array<uint8_t,SYMBYTES>& coins);

void kem_enc(std::array<uint8_t,CIPHERTEXTBYTES>& ct,
             std::array<uint8_t,SSBYTES>& ss,
             const std::array<uint8_t,PUBLICKEYBYTES>& pk);

void kem_dec(std::array<uint8_t,SSBYTES>& ss,
             const std::array<uint8_t,CIPHERTEXTBYTES>& ct,
             const std::array<uint8_t,SECRETKEYBYTES>& sk);

} // namespace td18
