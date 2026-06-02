#pragma once
#include "params.hpp"
#include <array>

namespace td18 {

void graph_from_seed(const std::array<uint8_t,32>& seed,
                     std::array<std::array<uint16_t,GRAPH_DEGREE>,GRAPH_NODES>& adj,
                     std::array<uint8_t,GRAPH_NODES>& deg);

void edmesh_derive(std::array<uint8_t,EDMESH_BYTES>& out,
                   const std::array<uint8_t,SYMBYTES>& seed,
                   const Params& p);

} // namespace td18
