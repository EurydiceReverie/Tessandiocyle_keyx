// TessanDioKey v15 — Vector of polynomials
use crate::params::{
    KYBER_K, KYBER_N, KYBER_POLYBYTES,
    KYBER_Q,
};
use crate::poly::{
    poly_add, poly_basemul_montgomery, poly_frombytes, poly_invntt_tomont, poly_ntt,
    poly_reduce, poly_tobytes, Poly,
};

#[derive(Clone, Copy, Debug)]
pub struct PolyVec {
    pub vec: [Poly; KYBER_K],
}

impl Default for PolyVec {
    fn default() -> Self {
        PolyVec {
            vec: [Poly::new(); KYBER_K],
        }
    }
}

impl PolyVec {
    pub fn new() -> Self {
        Self::default()
    }
}

pub fn polyvec_compress(r: &mut [u8], a: PolyVec) {
    let mut t = [0u16; 4];
    let mut idx = 0usize;
    for i in 0..KYBER_K {
        for j in 0..KYBER_N / 4 {
            for (k, &coeff) in a.vec[i].coeffs[4 * j..4 * j + 4].iter().enumerate() {
                t[k] = coeff as u16;
                t[k] = t[k].wrapping_add((((t[k] as i16) >> 15) & KYBER_Q) as u16);
                t[k] = (((((t[k] as u32) << 10) + (KYBER_Q as u32) / 2) / (KYBER_Q as u32)) & 0x3ff)
                    as u16;
            }
            r[idx] = t[0] as u8;
            r[idx + 1] = ((t[0] >> 8) | (t[1] << 2)) as u8;
            r[idx + 2] = ((t[1] >> 6) | (t[2] << 4)) as u8;
            r[idx + 3] = ((t[2] >> 4) | (t[3] << 6)) as u8;
            r[idx + 4] = (t[3] >> 2) as u8;
            idx += 5;
        }
    }
}

pub fn polyvec_decompress(r: &mut PolyVec, a: &[u8]) {
    let mut idx = 0usize;
    let mut t = [0u16; 4];
    for i in 0..KYBER_K {
        for j in 0..KYBER_N / 4 {
            t[0] = a[idx] as u16 | (a[idx + 1] as u16) << 8;
            t[1] = (a[idx + 1] >> 2) as u16 | (a[idx + 2] as u16) << 6;
            t[2] = (a[idx + 2] >> 4) as u16 | (a[idx + 3] as u16) << 4;
            t[3] = (a[idx + 3] >> 6) as u16 | (a[idx + 4] as u16) << 2;
            idx += 5;
            for (k, &tval) in t.iter().enumerate() {
                r.vec[i].coeffs[4 * j + k] =
                    ((((tval as u32) & 0x3FF) * (KYBER_Q as u32) + 512) >> 10) as i16;
            }
        }
    }
}

pub fn polyvec_tobytes(r: &mut [u8], a: &PolyVec) {
    for i in 0..KYBER_K {
        poly_tobytes(&mut r[i * KYBER_POLYBYTES..], a.vec[i]);
    }
}

pub fn polyvec_frombytes(r: &mut PolyVec, a: &[u8]) {
    for i in 0..KYBER_K {
        poly_frombytes(&mut r.vec[i], &a[i * KYBER_POLYBYTES..]);
    }
}

pub fn polyvec_ntt(r: &mut PolyVec) {
    for i in 0..KYBER_K {
        poly_ntt(&mut r.vec[i]);
    }
}

pub fn polyvec_invntt_tomont(r: &mut PolyVec) {
    for i in 0..KYBER_K {
        poly_invntt_tomont(&mut r.vec[i]);
    }
}

pub fn polyvec_basemul_acc_montgomery(r: &mut Poly, a: &PolyVec, b: &PolyVec) {
    let mut t = Poly::new();
    poly_basemul_montgomery(r, &a.vec[0], &b.vec[0]);
    for i in 1..KYBER_K {
        poly_basemul_montgomery(&mut t, &a.vec[i], &b.vec[i]);
        poly_add(r, &t);
    }
    poly_reduce(r);
}

pub fn polyvec_reduce(r: &mut PolyVec) {
    for i in 0..KYBER_K {
        poly_reduce(&mut r.vec[i]);
    }
}

pub fn polyvec_add(r: &mut PolyVec, b: &PolyVec) {
    for i in 0..KYBER_K {
        poly_add(&mut r.vec[i], &b.vec[i]);
    }
}
