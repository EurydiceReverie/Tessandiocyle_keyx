#include "kem.hpp"
#include "indcpa.hpp"
#include "verify.hpp"
#include "shake.hpp"
#include "random.hpp"
#include "secure.hpp"
#include "ntt.hpp"
#include <cstring>
#include <vector>

namespace td18 {

static uint64_t derive_ntt_seed(const std::array<uint8_t,SYMBYTES>& coins) {
    std::array<uint8_t,32> hash;
    Keccak1600::sha3_256(hash.data(), coins.data(), coins.size());
    uint64_t s = 0;
    for (int i = 0; i < 8; ++i) s |= static_cast<uint64_t>(hash[i]) << (8 * i);
    return s;
}

static void decaps_state_mac(const std::array<uint8_t,SECRETKEYBYTES>& sk,
                             const std::array<uint8_t,2*SYMBYTES>& buf,
                             const std::array<uint8_t,CIPHERTEXTBYTES>& ct,
                             std::array<uint8_t,16>& mac) {
    std::array<uint8_t,SYMBYTES> key;
    std::copy(sk.end() - SYMBYTES, sk.end(), key.begin());
    std::array<uint8_t, SYMBYTES + 24 + 2*SYMBYTES + CIPHERTEXTBYTES> in;
    size_t off = 0;
    std::copy(key.begin(), key.end(), in.begin() + off); off += SYMBYTES;
    const char *label = "tessandio-v18-decaps-mac";
    std::copy(label, label + 24, reinterpret_cast<char*>(in.data()) + off); off += 24;
    std::copy(buf.begin(), buf.end(), in.begin() + off); off += buf.size();
    std::copy(ct.begin(), ct.end(), in.begin() + off); off += ct.size();
    std::array<uint8_t,32> hash;
    Keccak1600::sha3_256(hash.data(), in.data(), off);
    std::copy(hash.begin(), hash.begin() + 16, mac.begin());
}

static void vdf_prove(std::array<uint8_t,32>& out, const uint8_t *in, size_t inlen, uint32_t iterations) {
    Keccak1600::sha3_256(out.data(), in, inlen);
    for (uint32_t i = 0; i < iterations; ++i) {
        std::array<uint8_t,32> tmp;
        Keccak1600::sha3_256(tmp.data(), out.data(), 32);
        out = tmp;
    }
}

static void majority_vote(const uint8_t *a, const uint8_t *b, const uint8_t *c, uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; ++i)
        out[i] = (a[i] == b[i] || a[i] == c[i]) ? a[i] : b[i];
}

static void triple_decaps_buf(const std::array<uint8_t,CIPHERTEXTBYTES>& ct,
                              const std::array<uint8_t,SECRETKEYBYTES>& sk,
                              std::array<uint8_t,2*SYMBYTES>& out) {
    std::array<uint8_t,2*SYMBYTES> buf0{}, buf1{}, buf2{};
    indcpa_dec(*reinterpret_cast<std::array<uint8_t,SYMBYTES>*>(&buf0[0]), ct,
               *reinterpret_cast<const std::array<uint8_t,INDCPA_SECRETKEYBYTES>*>(&sk[0]));
    indcpa_dec(*reinterpret_cast<std::array<uint8_t,SYMBYTES>*>(&buf1[0]), ct,
               *reinterpret_cast<const std::array<uint8_t,INDCPA_SECRETKEYBYTES>*>(&sk[0]));
    indcpa_dec(*reinterpret_cast<std::array<uint8_t,SYMBYTES>*>(&buf2[0]), ct,
               *reinterpret_cast<const std::array<uint8_t,INDCPA_SECRETKEYBYTES>*>(&sk[0]));

    std::copy(sk.end() - 2*SYMBYTES, sk.end() - SYMBYTES, buf0.begin() + SYMBYTES);
    std::copy(sk.end() - 2*SYMBYTES, sk.end() - SYMBYTES, buf1.begin() + SYMBYTES);
    std::copy(sk.end() - 2*SYMBYTES, sk.end() - SYMBYTES, buf2.begin() + SYMBYTES);

    majority_vote(buf0.data(), buf1.data(), buf2.data(), out.data(), out.size());
}

void kem_keypair_derand(std::array<uint8_t,PUBLICKEYBYTES>& pk,
                        std::array<uint8_t,SECRETKEYBYTES>& sk,
                        const std::array<uint8_t,2*SYMBYTES>& coins) {
    std::array<uint8_t,SYMBYTES> first_coins;
    std::copy(coins.begin(), coins.begin() + SYMBYTES, first_coins.begin());
    ntt_seed(derive_ntt_seed(first_coins));
    std::array<uint8_t,INDCPA_SECRETKEYBYTES> indcpa_sk;
    indcpa_keypair_derand(pk, indcpa_sk, *reinterpret_cast<const std::array<uint8_t,SYMBYTES>*>(&coins[0]));

    std::copy(indcpa_sk.begin(), indcpa_sk.end(), sk.begin());
    std::copy(pk.begin(), pk.end(), sk.begin() + INDCPA_SECRETKEYBYTES);

    std::array<uint8_t,32> hpk;
    Keccak1600::sha3_256(hpk.data(), pk.data(), pk.size());
    std::copy(hpk.begin(), hpk.end(), sk.end() - 2 * SYMBYTES);
    std::copy(coins.begin() + SYMBYTES, coins.end(), sk.end() - SYMBYTES);

    secure_zero(indcpa_sk.data(), indcpa_sk.size());
}

void kem_enc_derand(std::array<uint8_t,CIPHERTEXTBYTES>& ct,
                    std::array<uint8_t,SSBYTES>& ss,
                    const std::array<uint8_t,PUBLICKEYBYTES>& pk,
                    const std::array<uint8_t,SYMBYTES>& coins) {
    ntt_seed(derive_ntt_seed(coins));
    std::array<uint8_t,2*SYMBYTES> buf;
    std::copy(coins.begin(), coins.end(), buf.begin());
    std::array<uint8_t,32> hpk;
    Keccak1600::sha3_256(hpk.data(), pk.data(), pk.size());
    std::copy(hpk.begin(), hpk.end(), buf.begin() + SYMBYTES);

    std::array<uint8_t,64> kr;
    Keccak1600::sha3_512(kr.data(), buf.data(), buf.size());

    indcpa_enc(ct, *reinterpret_cast<std::array<uint8_t,SYMBYTES>*>(&buf[0]), pk,
               *reinterpret_cast<std::array<uint8_t,SYMBYTES>*>(&kr[SYMBYTES]));
    std::copy(kr.begin(), kr.begin() + SYMBYTES, ss.begin());

    secure_zero(kr.data(), kr.size());
}

void kem_enc(std::array<uint8_t,CIPHERTEXTBYTES>& ct,
             std::array<uint8_t,SSBYTES>& ss,
             const std::array<uint8_t,PUBLICKEYBYTES>& pk) {
    std::array<uint8_t,SYMBYTES> coins;
    randombytes(coins.data(), coins.size());
    kem_enc_derand(ct, ss, pk, coins);
}

void kem_dec(std::array<uint8_t,SSBYTES>& ss,
             const std::array<uint8_t,CIPHERTEXTBYTES>& ct,
             const std::array<uint8_t,SECRETKEYBYTES>& sk) {
    uint32_t vdf_iters = 1u << 18;
    std::vector<uint8_t> vdf_input(sk.size() + ct.size());
    std::copy(sk.begin(), sk.end(), vdf_input.begin());
    std::copy(ct.begin(), ct.end(), vdf_input.begin() + sk.size());
    std::array<uint8_t,32> vdf_proof;
    vdf_prove(vdf_proof, vdf_input.data(), vdf_input.size(), vdf_iters);
    (void)vdf_proof;

    ntt_seed(derive_ntt_seed(*reinterpret_cast<const std::array<uint8_t,SYMBYTES>*>(&sk[sk.size() - SYMBYTES])));

    std::array<uint8_t,2*SYMBYTES> buf;
    triple_decaps_buf(ct, sk, buf);

    std::array<uint8_t,16> mac;
    decaps_state_mac(sk, buf, ct, mac);
    (void)mac;

    std::array<uint8_t,64> kr0, kr1, kr2, kr;
    Keccak1600::sha3_512(kr0.data(), buf.data(), buf.size());
    Keccak1600::sha3_512(kr1.data(), buf.data(), buf.size());
    Keccak1600::sha3_512(kr2.data(), buf.data(), buf.size());
    majority_vote(kr0.data(), kr1.data(), kr2.data(), kr.data(), kr.size());

    std::array<uint8_t,INDCPA_BYTES> cmp0, cmp1, cmp2, cmp;
    indcpa_enc(cmp0, *reinterpret_cast<std::array<uint8_t,SYMBYTES>*>(&buf[0]),
               *reinterpret_cast<const std::array<uint8_t,PUBLICKEYBYTES>*>(&sk[INDCPA_SECRETKEYBYTES]),
               *reinterpret_cast<std::array<uint8_t,SYMBYTES>*>(&kr[SYMBYTES]));
    indcpa_enc(cmp1, *reinterpret_cast<std::array<uint8_t,SYMBYTES>*>(&buf[0]),
               *reinterpret_cast<const std::array<uint8_t,PUBLICKEYBYTES>*>(&sk[INDCPA_SECRETKEYBYTES]),
               *reinterpret_cast<std::array<uint8_t,SYMBYTES>*>(&kr[SYMBYTES]));
    indcpa_enc(cmp2, *reinterpret_cast<std::array<uint8_t,SYMBYTES>*>(&buf[0]),
               *reinterpret_cast<const std::array<uint8_t,PUBLICKEYBYTES>*>(&sk[INDCPA_SECRETKEYBYTES]),
               *reinterpret_cast<std::array<uint8_t,SYMBYTES>*>(&kr[SYMBYTES]));
    majority_vote(cmp0.data(), cmp1.data(), cmp2.data(), cmp.data(), cmp.size());

    uint8_t fail = verify(ct.data(), cmp.data(), INDCPA_BYTES);

    std::array<uint8_t,SSBYTES> tmp_ss;
    std::array<uint8_t,SYMBYTES + CIPHERTEXTBYTES> rkprf_in;
    std::copy(sk.end() - SYMBYTES, sk.end(), rkprf_in.begin());
    std::copy(ct.begin(), ct.end(), rkprf_in.begin() + SYMBYTES);
    Keccak1600::shake256(tmp_ss.data(), tmp_ss.size(), rkprf_in.data(), rkprf_in.size());

    cmov(ss.data(), kr.data(), SSBYTES, static_cast<uint8_t>(1 - fail));
    cmov(ss.data(), tmp_ss.data(), SSBYTES, fail);

    secure_zero(kr0.data(), kr0.size());
    secure_zero(kr1.data(), kr1.size());
    secure_zero(kr2.data(), kr2.size());
    secure_zero(buf.data(), buf.size());
}

} // namespace td18
