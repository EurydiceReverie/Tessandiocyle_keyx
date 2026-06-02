#pragma once
#include "params.hpp"
#include <array>

namespace td18 {

void reconcile_alice(std::array<uint8_t,RECON_BYTES>& hints, const Poly& v);
int reconcile_verify(const Poly& va, const Poly& vb);

} // namespace td18
