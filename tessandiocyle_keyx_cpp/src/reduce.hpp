#pragma once
#include "params.hpp"
#include <cstdint>

namespace td18 {

constexpr int32_t BARRETT_V = ((1 << 26) + Q / 2) / Q;

inline int16_t barrett_reduce(int16_t a) {
    int32_t t = (static_cast<int32_t>(BARRETT_V) * static_cast<int32_t>(a) + (1 << 25)) >> 26;
    return a - static_cast<int16_t>(t * Q);
}

inline int16_t montgomery_reduce(int32_t a) {
    int16_t t = static_cast<int16_t>(a);
    int32_t u = a - static_cast<int32_t>(static_cast<int16_t>(t * QINV)) * Q;
    return static_cast<int16_t>(u >> 16);
}

} // namespace td18
