#pragma once
#include "params.hpp"
#include <array>

namespace td18 {

int params_init(Params& p);
int params_evolve(Params& p);

void hybrid_bind(std::array<uint8_t,32>& out,
                 const std::array<uint8_t,32>& binding,
                 const std::array<uint8_t,PUBLICKEYBYTES>& pk);

void mac(std::array<uint8_t,MAC_BYTES>& mac_tag,
         const std::array<uint8_t,SSBYTES>& ss,
         const std::array<uint8_t,CIPHERTEXTBYTES>& ct);

int verify_mac(const std::array<uint8_t,MAC_BYTES>& mac_tag,
               const std::array<uint8_t,SSBYTES>& ss,
               const std::array<uint8_t,CIPHERTEXTBYTES>& ct);

void gen_commitment(Commitment& commit,
                    const std::array<uint8_t,CIPHERTEXTBYTES>& ct,
                    const std::array<uint8_t,EDMESH_BYTES>& edmesh,
                    const std::array<uint8_t,32>& binding,
                    const std::array<uint8_t,MAC_BYTES>& mac_tag,
                    const std::array<uint8_t,SYMBYTES>& nonce);

int verify_commitment(const Commitment& commit,
                      const std::array<uint8_t,CIPHERTEXTBYTES>& ct,
                      const std::array<uint8_t,EDMESH_BYTES>& edmesh,
                      const std::array<uint8_t,32>& binding,
                      const std::array<uint8_t,MAC_BYTES>& mac_tag);

void derive_final_key(std::array<uint8_t,SSBYTES>& final_key,
                      const std::array<uint8_t,SSBYTES>& base_ss,
                      const std::array<uint8_t,32>& binding,
                      const std::array<uint8_t,PUBLICKEYBYTES>& pk,
                      const Params& p);

void vdf_hash(std::array<uint8_t,32>& seed, uint32_t iterations);
void trapdoor_id(std::array<uint8_t,32>& id, const std::array<uint8_t,SECRETKEYBYTES>& sk);

} // namespace td18
