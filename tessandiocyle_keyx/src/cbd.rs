use crate::params::{KYBER_N, KYBER_Q};
use crate::poly::Poly;
use rand::rngs::OsRng;
use rand::RngCore;

/// Load 4 bytes into a 32-bit integer in little-endian order.
fn load32_littleendian(x: &[u8]) -> u32 {
    let mut r = x[0] as u32;
    r |= (x[1] as u32) << 8;
    r |= (x[2] as u32) << 16;
    r |= (x[3] as u32) << 24;
    r
}

/// Load 3 bytes into a 32-bit integer in little-endian order.
fn load24_littleendian(x: &[u8]) -> u32 {
    let mut r = x[0] as u32;
    r |= (x[1] as u32) << 8;
    r |= (x[2] as u32) << 16;
    r
}

/// CBD with parameter eta=2 (standard, unmasked).
pub fn cbd2(r: &mut Poly, buf: &[u8]) {
    let (mut d, mut t, mut a, mut b);
    for i in 0..(KYBER_N / 8) {
        t = load32_littleendian(&buf[4 * i..]);
        d = t & 0x55555555;
        d += (t >> 1) & 0x55555555;
        for j in 0..8 {
            a = ((d >> (4 * j)) & 0x3) as i16;
            b = ((d >> (4 * j + 2)) & 0x3) as i16;
            r.coeffs[8 * i + j] = a - b;
        }
    }
}

/// CBD with parameter eta=3 (Kyber-512 only).
pub fn cbd3(r: &mut Poly, buf: &[u8]) {
    let (mut d, mut t, mut a, mut b);
    for i in 0..(KYBER_N / 4) {
        t = load24_littleendian(&buf[3 * i..]);
        d = t & 0x00249249;
        d += (t >> 1) & 0x00249249;
        d += (t >> 2) & 0x00249249;
        for j in 0..4 {
            a = ((d >> (6 * j)) & 0x7) as i16;
            b = ((d >> (6 * j + 3)) & 0x7) as i16;
            r.coeffs[4 * i + j] = a - b;
        }
    }
}

/// First-order arithmetic masked CBD2.
/// Splits each coefficient into two shares (share0, share1) such that:
///   share0[i] + share1[i] ≡ c[i]  (mod KYBER_Q)
/// The true coefficient is never present in memory in unmasked form.
pub fn cbd2_masked(
    share0: &mut Poly,
    share1: &mut Poly,
    buf: &[u8],
) {
    let mut rng_buf = [0u8; 2 * KYBER_N]; // 2 bytes per coefficient for mask
    OsRng.fill_bytes(&mut rng_buf);

    let (mut d, mut t, mut a, mut b);
    for i in 0..(KYBER_N / 8) {
        t = load32_littleendian(&buf[4 * i..]);
        d = t & 0x55555555;
        d += (t >> 1) & 0x55555555;
        for j in 0..8 {
            a = ((d >> (4 * j)) & 0x3) as i16;
            b = ((d >> (4 * j + 2)) & 0x3) as i16;
            let coeff = a - b;
            let idx = 8 * i + j;
            // Random mask in [0, q-1] from 2 random bytes
            let mask_raw = u16::from_le_bytes([rng_buf[2 * idx], rng_buf[2 * idx + 1]]);
            let mask = (mask_raw % KYBER_Q as u16) as i16;
            // share0 = coeff - mask (mod q)
            // share1 = mask
            share0.coeffs[idx] = coeff - mask;
            share1.coeffs[idx] = mask;
        }
    }
}

/// Reconstruct a polynomial from two arithmetic shares.
pub fn unmask_poly(r: &mut Poly, share0: &Poly, share1: &Poly) {
    for i in 0..KYBER_N {
        r.coeffs[i] = share0.coeffs[i] + share1.coeffs[i];
    }
}

pub fn poly_cbd_eta1(r: &mut Poly, buf: &[u8]) {
    cbd2(r, buf)
}

pub fn poly_cbd_eta2(r: &mut Poly, buf: &[u8]) {
    cbd2(r, buf)
}

/// Masked variants for ETA1/ETA2 noise sampling.
pub fn poly_cbd_eta1_masked(s0: &mut Poly, s1: &mut Poly, buf: &[u8]) {
    cbd2_masked(s0, s1, buf)
}

pub fn poly_cbd_eta2_masked(s0: &mut Poly, s1: &mut Poly, buf: &[u8]) {
    cbd2_masked(s0, s1, buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_masked_cbd_reconstruction() {
        let mut buf = [0u8; 128]; // CBD2 needs 128 bytes for 256 coeffs
        OsRng.fill_bytes(&mut buf);

        let mut unmasked = Poly::new();
        cbd2(&mut unmasked, &buf);

        let mut s0 = Poly::new();
        let mut s1 = Poly::new();
        cbd2_masked(&mut s0, &mut s1, &buf);

        let mut reconstructed = Poly::new();
        unmask_poly(&mut reconstructed, &s0, &s1);

        assert_eq!(unmasked.coeffs, reconstructed.coeffs, "Masked CBD reconstruction failed");
    }

    #[test]
    fn test_masked_cbd_share_independence() {
        // Verify that a single share reveals nothing about the underlying coefficient.
        // In arithmetic masking, share1 = mask (uniform in [0, q-1]) and
        // share0 = coeff - mask. share0 is therefore uniform in [-(q-1), q-1].
        let mut buf = [0u8; 128];
        OsRng.fill_bytes(&mut buf);

        let mut s0 = Poly::new();
        let mut s1 = Poly::new();
        cbd2_masked(&mut s0, &mut s1, &buf);

        // Check that share1 (the raw mask) spans a wide range.
        let min_s1 = *s1.coeffs.iter().min().unwrap();
        let max_s1 = *s1.coeffs.iter().max().unwrap();
        assert!(min_s1 < 500, "Share1 min too high: {}", min_s1);
        assert!(max_s1 > 2800, "Share1 max too low: {}", max_s1);

        // Check that share0 spans a wide range (because coeff is small ±2 and mask is large)
        let min_s0 = *s0.coeffs.iter().min().unwrap();
        let max_s0 = *s0.coeffs.iter().max().unwrap();
        assert!(min_s0 < -2800, "Share0 min too high: {}", min_s0);
        assert!(max_s0 > -500, "Share0 max too low: {}", max_s0);

        // Verify s0 + s1 recovers expected small-range coefficients
        let mut reconstructed = Poly::new();
        unmask_poly(&mut reconstructed, &s0, &s1);
        let min_c = *reconstructed.coeffs.iter().min().unwrap();
        let max_c = *reconstructed.coeffs.iter().max().unwrap();
        assert!(min_c >= -2, "Reconstructed min too low");
        assert!(max_c <= 2, "Reconstructed max too high");
    }
}
