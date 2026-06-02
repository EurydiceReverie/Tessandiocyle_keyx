#pragma once
#include <array>
#include <cstdint>
#include <cstddef>

namespace td18 {

template<std::size_t N>
class SecureArray {
    std::array<uint8_t, N> data_{};
public:
    SecureArray() = default;
    explicit SecureArray(const std::array<uint8_t, N>& arr) : data_{arr} {}
    ~SecureArray() { secure_zero(); }
    SecureArray(const SecureArray&) = default;
    SecureArray& operator=(const SecureArray&) = default;
    SecureArray(SecureArray&&) = default;
    SecureArray& operator=(SecureArray&&) = default;

    uint8_t* data() { return data_.data(); }
    const uint8_t* data() const { return data_.data(); }
    constexpr std::size_t size() const { return N; }
    uint8_t& operator[](std::size_t i) { return data_[i]; }
    const uint8_t& operator[](std::size_t i) const { return data_[i]; }
    auto& bytes() { return data_; }
    const auto& bytes() const { return data_; }

    void secure_zero() {
        for (auto& b : data_) {
            volatile uint8_t* p = &b;
            *p = 0;
        }
    }
};

inline void secure_zero(void *p, size_t len) {
    volatile uint8_t *vp = static_cast<volatile uint8_t*>(p);
    while (len--) *vp++ = 0;
}

inline void secure_copy(uint8_t *dst, const uint8_t *src, size_t len) {
    volatile uint8_t *d = reinterpret_cast<volatile uint8_t*>(dst);
    volatile const uint8_t *s = reinterpret_cast<volatile const uint8_t*>(src);
    while (len--) *d++ = *s++;
}

inline void ct_cswap(uint8_t *a, uint8_t *b, uint8_t swap) {
    uint8_t mask = static_cast<uint8_t>(-static_cast<int8_t>(swap));
    uint8_t diff = *a ^ *b;
    uint8_t t = mask & diff;
    *a ^= t; *b ^= t;
}

} // namespace td18
