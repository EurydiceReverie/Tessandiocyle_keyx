// TessanDioKey v15 — IND-CPA secure public-key encryption
use crate::params::{
    KYBER_K, KYBER_N,
    KYBER_POLYVECBYTES, KYBER_POLYVECCOMPRESSEDBYTES, KYBER_Q, KYBER_SYMBYTES,
};
use crate::poly::{
    poly_add, poly_compress, poly_decompress, poly_frommsg, poly_getnoise_eta1,
    poly_getnoise_eta2, poly_invntt_tomont, poly_reduce, poly_sub,
    poly_tomont, poly_tomsg, Poly,
};
use crate::polyvec::{
    polyvec_add, polyvec_basemul_acc_montgomery, polyvec_compress, polyvec_decompress,
    polyvec_frombytes, polyvec_invntt_tomont, polyvec_ntt, polyvec_reduce, polyvec_tobytes,
    PolyVec,
};
use crate::symmetric::{hash_g, XofReader};

fn pack_pk(r: &mut [u8], pk: &PolyVec, seed: &[u8]) {
    const END: usize = KYBER_SYMBYTES + KYBER_POLYVECBYTES;
    polyvec_tobytes(r, pk);
    r[KYBER_POLYVECBYTES..END].copy_from_slice(&seed[..KYBER_SYMBYTES]);
}

fn unpack_pk(pk: &mut PolyVec, seed: &mut [u8], packedpk: &[u8]) {
    const END: usize = KYBER_SYMBYTES + KYBER_POLYVECBYTES;
    polyvec_frombytes(pk, packedpk);
    seed[..KYBER_SYMBYTES].copy_from_slice(&packedpk[KYBER_POLYVECBYTES..END]);
}

fn pack_sk(r: &mut [u8], sk: &PolyVec) {
    polyvec_tobytes(r, sk);
}

fn unpack_sk(sk: &mut PolyVec, packedsk: &[u8]) {
    polyvec_frombytes(sk, packedsk);
}

fn pack_ciphertext(r: &mut [u8], b: &PolyVec, v: Poly) {
    polyvec_compress(r, *b);
    poly_compress(&mut r[KYBER_POLYVECCOMPRESSEDBYTES..], v);
}

fn unpack_ciphertext(b: &mut PolyVec, v: &mut Poly, c: &[u8]) {
    polyvec_decompress(b, c);
    poly_decompress(v, &c[KYBER_POLYVECCOMPRESSEDBYTES..]);
}

fn rej_uniform(r: &mut [i16], len: usize, buf: &[u8], buflen: usize) -> usize {
    let (mut ctr, mut pos) = (0usize, 0usize);
    let (mut val0, mut val1);

    while ctr < len && pos + 3 <= buflen {
        val0 = (buf[pos] as u16 | (buf[pos + 1] as u16) << 8) & 0xFFF;
        val1 = ((buf[pos + 1] >> 4) as u16 | (buf[pos + 2] as u16) << 4) & 0xFFF;
        pos += 3;

        if val0 < KYBER_Q as u16 {
            r[ctr] = val0 as i16;
            ctr += 1;
        }
        if ctr < len && val1 < KYBER_Q as u16 {
            r[ctr] = val1 as i16;
            ctr += 1;
        }
    }
    ctr
}

fn gen_a(a: &mut [PolyVec], b: &[u8]) {
    gen_matrix(a, b, false);
}

fn gen_at(a: &mut [PolyVec], b: &[u8]) {
    gen_matrix(a, b, true);
}

fn gen_matrix(a: &mut [PolyVec], seed: &[u8], transposed: bool) {
    let mut ctr;
    const GEN_MATRIX_NBLOCKS: usize =
        (12 * KYBER_N / 8 * (1 << 12) / (KYBER_Q as usize) + 168) / 168;
    const BLOCK_SIZE: usize = 168;
    let mut buf = [0u8; GEN_MATRIX_NBLOCKS * BLOCK_SIZE + 2];
    let mut buflen: usize;
    let mut off: usize;

    for (i, ai) in a.iter_mut().enumerate() {
        for (j, poly) in ai.vec.iter_mut().enumerate() {
            // Create one stateful XOF reader per polynomial — much faster than
            // restarting BLAKE3 for every extra block during rejection sampling.
            let mut xof_reader = if transposed {
                XofReader::new(seed, i as u8, j as u8)
            } else {
                XofReader::new(seed, j as u8, i as u8)
            };

            let mut xof_buf = [0u8; GEN_MATRIX_NBLOCKS * BLOCK_SIZE];
            xof_reader.squeeze(&mut xof_buf);
            buflen = GEN_MATRIX_NBLOCKS * BLOCK_SIZE;
            ctr = rej_uniform(&mut poly.coeffs, KYBER_N, &xof_buf, buflen);

            while ctr < KYBER_N {
                off = buflen % 3;
                for k in 0..off {
                    buf[k] = buf[buflen - off + k];
                }
                let mut extra = [0u8; BLOCK_SIZE];
                xof_reader.squeeze(&mut extra);
                buf[off..off + BLOCK_SIZE].copy_from_slice(&extra);
                buflen = off + BLOCK_SIZE;
                ctr += rej_uniform(&mut poly.coeffs[ctr..], KYBER_N - ctr, &buf, buflen);
            }
        }
    }
}

pub fn indcpa_keypair_derand(
    pk: &mut [u8],
    sk: &mut [u8],
    coins: &[u8],
) {
    let mut a = [PolyVec::new(); KYBER_K];
    let (mut e, mut pkpv, mut skpv) = (PolyVec::new(), PolyVec::new(), PolyVec::new());
    let mut nonce = 0u8;
    let mut buf = [0u8; 2 * KYBER_SYMBYTES];

    buf[..KYBER_SYMBYTES].copy_from_slice(coins);
    buf[KYBER_SYMBYTES] = KYBER_K as u8;
    let mut input = [0u8; KYBER_SYMBYTES + 1];
    input.copy_from_slice(&buf[..KYBER_SYMBYTES + 1]);
    hash_g(&mut buf, &input);

    let (publicseed, noiseseed) = buf.split_at(KYBER_SYMBYTES);
    gen_a(&mut a, publicseed);

    for i in 0..KYBER_K {
        poly_getnoise_eta1(&mut skpv.vec[i], noiseseed, nonce);
        nonce += 1;
    }
    for i in 0..KYBER_K {
        poly_getnoise_eta1(&mut e.vec[i], noiseseed, nonce);
        nonce += 1;
    }

    polyvec_ntt(&mut skpv);
    polyvec_ntt(&mut e);

    for (i, pkpv_i) in pkpv.vec.iter_mut().enumerate() {
        polyvec_basemul_acc_montgomery(pkpv_i, &a[i], &skpv);
        poly_tomont(pkpv_i);
    }
    polyvec_add(&mut pkpv, &e);
    polyvec_reduce(&mut pkpv);

    pack_sk(sk, &skpv);
    pack_pk(pk, &pkpv, publicseed);
}

pub fn indcpa_enc(
    c: &mut [u8],
    m: &[u8],
    pk: &[u8],
    coins: &[u8],
) {
    let mut at = [PolyVec::new(); KYBER_K];
    let (mut sp, mut pkpv, mut ep, mut b) = (
        PolyVec::new(),
        PolyVec::new(),
        PolyVec::new(),
        PolyVec::new(),
    );
    let (mut v, mut k, mut epp) = (Poly::new(), Poly::new(), Poly::new());
    let mut seed = [0u8; KYBER_SYMBYTES];
    let mut nonce = 0u8;

    unpack_pk(&mut pkpv, &mut seed, pk);
    poly_frommsg(&mut k, m);
    gen_at(&mut at, &seed);

    for i in 0..KYBER_K {
        poly_getnoise_eta1(&mut sp.vec[i], coins, nonce);
        nonce += 1;
    }
    for i in 0..KYBER_K {
        poly_getnoise_eta2(&mut ep.vec[i], coins, nonce);
        nonce += 1;
    }
    poly_getnoise_eta2(&mut epp, coins, nonce);

    polyvec_ntt(&mut sp);

    for (i, b_i) in b.vec.iter_mut().enumerate() {
        polyvec_basemul_acc_montgomery(b_i, &at[i], &sp);
    }

    polyvec_basemul_acc_montgomery(&mut v, &pkpv, &sp);
    polyvec_invntt_tomont(&mut b);
    poly_invntt_tomont(&mut v);

    polyvec_add(&mut b, &ep);
    poly_add(&mut v, &epp);
    poly_add(&mut v, &k);
    polyvec_reduce(&mut b);
    poly_reduce(&mut v);

    pack_ciphertext(c, &b, v);
}

pub fn indcpa_dec(
    m: &mut [u8],
    c: &[u8],
    sk: &[u8],
) {
    let (mut b, mut skpv) = (PolyVec::new(), PolyVec::new());
    let (mut v, mut mp) = (Poly::new(), Poly::new());

    unpack_ciphertext(&mut b, &mut v, c);
    unpack_sk(&mut skpv, sk);

    polyvec_ntt(&mut b);
    polyvec_basemul_acc_montgomery(&mut mp, &skpv, &b);
    poly_invntt_tomont(&mut mp);

    poly_sub(&mut mp, &v);
    poly_reduce(&mut mp);

    poly_tomsg(m, mp);
}
