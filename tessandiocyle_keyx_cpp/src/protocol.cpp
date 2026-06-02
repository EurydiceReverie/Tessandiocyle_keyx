#include "protocol.hpp"
#include "shake.hpp"
#include "graph.hpp"
#include "reconcile.hpp"
#include "random.hpp"
#include "secure.hpp"
#include <cstring>

namespace td18 {

int params_init(Params& p) {
    randombytes(p.epoch_seed.data(), p.epoch_seed.size());
    for (int i = 0; i < K; ++i) randombytes(p.graph_seeds[i].data(), p.graph_seeds[i].size());
    for (int i = 0; i < K; ++i) {
        std::array<uint8_t,8> buf;
        randombytes(buf.data(), buf.size());
        uint64_t s = 0;
        for (int j = 0; j < 8; ++j) s |= static_cast<uint64_t>(buf[j]) << (8 * j);
        p.starts[i] = static_cast<uint16_t>(s % GRAPH_NODES);
    }
    p.epoch = 0;
    return 0;
}

int params_evolve(Params& p) {
    for (int i = 0; i < K; ++i) vdf_hash(p.graph_seeds[i], 1u << 18);
    for (int i = 0; i < K; ++i) {
        std::array<uint8_t,8> buf;
        randombytes(buf.data(), buf.size());
        uint64_t s = 0;
        for (int j = 0; j < 8; ++j) s |= static_cast<uint64_t>(buf[j]) << (8 * j);
        p.starts[i] = static_cast<uint16_t>(s % GRAPH_NODES);
    }
    ++p.epoch;
    return 0;
}

void hybrid_bind(std::array<uint8_t,32>& out,
                 const std::array<uint8_t,32>& binding,
                 const std::array<uint8_t,PUBLICKEYBYTES>& pk) {
    std::array<uint8_t, 32 + PUBLICKEYBYTES> in;
    std::copy(binding.begin(), binding.end(), in.begin());
    std::copy(pk.begin(), pk.end(), in.begin() + 32);
    Keccak1600::sha3_256(out.data(), in.data(), in.size());
}

void mac(std::array<uint8_t,MAC_BYTES>& mac_tag,
         const std::array<uint8_t,SSBYTES>& ss,
         const std::array<uint8_t,CIPHERTEXTBYTES>& ct) {
    std::array<uint8_t, SSBYTES + CIPHERTEXTBYTES + 17> in;
    size_t off = 0;
    std::copy(ss.begin(), ss.end(), in.begin() + off); off += ss.size();
    std::copy(ct.begin(), ct.end(), in.begin() + off); off += ct.size();
    const char *label = "tessandio-v18-mac";
    std::copy(label, label + 17, reinterpret_cast<char*>(in.data()) + off); off += 17;
    std::array<uint8_t,32> hash;
    Keccak1600::sha3_256(hash.data(), in.data(), off);
    mac_tag[0] = hash[0];
    mac_tag[1] = hash[1];
}

int verify_mac(const std::array<uint8_t,MAC_BYTES>& mac_tag,
               const std::array<uint8_t,SSBYTES>& ss,
               const std::array<uint8_t,CIPHERTEXTBYTES>& ct) {
    std::array<uint8_t,MAC_BYTES> expected;
    mac(expected, ss, ct);
    return (mac_tag[0] == expected[0] && mac_tag[1] == expected[1]) ? 0 : -1;
}

void gen_commitment(Commitment& commit,
                    const std::array<uint8_t,CIPHERTEXTBYTES>& ct,
                    const std::array<uint8_t,EDMESH_BYTES>& edmesh,
                    const std::array<uint8_t,32>& binding,
                    const std::array<uint8_t,MAC_BYTES>& mac_tag,
                    const std::array<uint8_t,SYMBYTES>& nonce) {
    std::array<uint8_t, CIPHERTEXTBYTES + EDMESH_BYTES + 32 + MAC_BYTES + SYMBYTES> in;
    size_t off = 0;
    std::copy(ct.begin(), ct.end(), in.begin() + off); off += ct.size();
    std::copy(edmesh.begin(), edmesh.end(), in.begin() + off); off += edmesh.size();
    std::copy(binding.begin(), binding.end(), in.begin() + off); off += binding.size();
    std::copy(mac_tag.begin(), mac_tag.end(), in.begin() + off); off += mac_tag.size();
    std::copy(nonce.begin(), nonce.end(), in.begin() + off); off += nonce.size();
    Keccak1600::sha3_256(commit.hash.data(), in.data(), off);
    commit.nonce = nonce;
}

int verify_commitment(const Commitment& commit,
                      const std::array<uint8_t,CIPHERTEXTBYTES>& ct,
                      const std::array<uint8_t,EDMESH_BYTES>& edmesh,
                      const std::array<uint8_t,32>& binding,
                      const std::array<uint8_t,MAC_BYTES>& mac_tag) {
    std::array<uint8_t, CIPHERTEXTBYTES + EDMESH_BYTES + 32 + MAC_BYTES + SYMBYTES> in;
    size_t off = 0;
    std::copy(ct.begin(), ct.end(), in.begin() + off); off += ct.size();
    std::copy(edmesh.begin(), edmesh.end(), in.begin() + off); off += edmesh.size();
    std::copy(binding.begin(), binding.end(), in.begin() + off); off += binding.size();
    std::copy(mac_tag.begin(), mac_tag.end(), in.begin() + off); off += mac_tag.size();
    std::copy(commit.nonce.begin(), commit.nonce.end(), in.begin() + off); off += commit.nonce.size();
    std::array<uint8_t,32> hash;
    Keccak1600::sha3_256(hash.data(), in.data(), off);
    return (hash == commit.hash) ? 0 : -1;
}

void derive_final_key(std::array<uint8_t,SSBYTES>& final_key,
                      const std::array<uint8_t,SSBYTES>& base_ss,
                      const std::array<uint8_t,32>& binding,
                      const std::array<uint8_t,PUBLICKEYBYTES>& pk,
                      const Params& p) {
    /* Base key */
    std::array<uint8_t, SSBYTES + 18> in0;
    std::copy(base_ss.begin(), base_ss.end(), in0.begin());
    const char *base_label = "tessandio-v18-base";
    std::copy(base_label, base_label + 18, reinterpret_cast<char*>(in0.data()) + SSBYTES);
    std::array<uint8_t,32> base_key;
    Keccak1600::sha3_256(base_key.data(), in0.data(), in0.size());

    /* Hybrid binding c */
    std::array<uint8_t,32> c;
    hybrid_bind(c, binding, pk);

    /* EDMesh */
    std::array<uint8_t,EDMESH_BYTES> expanded;
    edmesh_derive(expanded, base_ss, p);

    /* Pseudo-poly + reconcile */
    std::array<uint8_t, SSBYTES + 24> in1;
    std::copy(base_ss.begin(), base_ss.end(), in1.begin());
    const char *poly_label = "tessandio-v18-pseudopoly";
    std::copy(poly_label, poly_label + 24, reinterpret_cast<char*>(in1.data()) + SSBYTES);
    std::array<uint8_t,512> poly_bytes;
    std::array<uint8_t,64> tmp64;
    Keccak1600::sha3_512(tmp64.data(), in1.data(), in1.size());
    std::copy(tmp64.begin(), tmp64.begin() + 64, poly_bytes.begin());
    for (int block = 1; block < 8; ++block) {
        Keccak1600::sha3_512(tmp64.data(), poly_bytes.data() + (block-1)*64, 64);
        std::copy(tmp64.begin(), tmp64.begin() + 64, poly_bytes.begin() + block*64);
    }
    Poly pseudo_poly;
    for (int i = 0; i < N; ++i) {
        uint16_t val = static_cast<uint16_t>(poly_bytes[2*i]) | (static_cast<uint16_t>(poly_bytes[2*i+1]) << 8);
        pseudo_poly[i] = static_cast<int16_t>(val % Q);
    }
    std::array<uint8_t,RECON_BYTES> reconcile_data;
    reconcile_alice(reconcile_data, pseudo_poly);

    /* Overlay KDF */
    std::array<uint8_t, 64 + 32 + 32 + RECON_BYTES + 21> in2;
    size_t off = 0;
    std::copy(expanded.begin(), expanded.end(), in2.begin() + off); off += expanded.size();
    std::copy(c.begin(), c.end(), in2.begin() + off); off += c.size();
    std::copy(binding.begin(), binding.end(), in2.begin() + off); off += binding.size();
    std::copy(reconcile_data.begin(), reconcile_data.end(), in2.begin() + off); off += reconcile_data.size();
    const char *overlay_label = "tessandio-v18-overlay";
    std::copy(overlay_label, overlay_label + 21, reinterpret_cast<char*>(in2.data()) + off); off += 21;
    std::array<uint8_t,32> overlay;
    Keccak1600::sha3_256(overlay.data(), in2.data(), off);

    for (int i = 0; i < 32; ++i) final_key[i] = base_key[i] ^ overlay[i];
}

void vdf_hash(std::array<uint8_t,32>& seed, uint32_t iterations) {
    for (uint32_t i = 0; i < iterations; ++i) {
        std::array<uint8_t,32> tmp;
        Keccak1600::sha3_256(tmp.data(), seed.data(), seed.size());
        seed = tmp;
    }
}

void trapdoor_id(std::array<uint8_t,32>& id, const std::array<uint8_t,SECRETKEYBYTES>& sk) {
    Keccak1600::sha3_256(id.data(), sk.data(), POLYVECBYTES);
}

} // namespace td18
