// TessanDioKey v15 — Modular reduction (Barrett and Montgomery)
use crate::params::KYBER_Q;

/// Montgomery reduction constant: -q^{-1} mod 2^16.
/// q * (-3327) ≡ 1 (mod 65536), so QINV = -3327 as i16.
pub const QINV: i16 = -3327;

/// Montgomery factor: 2^16 mod q = -1044.
pub const MONT: i16 = -1044;

/// Barrett reduction multiplier: floor(2^26 / q) with rounding.
const V: i32 = ((1i32 << 26) + (KYBER_Q as i32) / 2) / (KYBER_Q as i32);

/// Barrett reduction: maps a to centered representative mod q.
#[inline]
pub fn barrett_reduce(a: i16) -> i16 {
    let t = (V * (a as i32) + (1i32 << 25)) >> 26;
    a - (t * (KYBER_Q as i32)) as i16
}

/// Montgomery reduction: given 32-bit a, returns a * R^{-1} mod q where R = 2^16.
#[inline]
pub fn montgomery_reduce(a: i32) -> i16 {
    let t = (a as i16).wrapping_mul(QINV) as i32;
    let u = a.wrapping_sub(t.wrapping_mul(KYBER_Q as i32));
    (u >> 16) as i16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_barrett_reduce() {
        let a = 5000i16;
        let r = barrett_reduce(a);
        // 5000 mod 3329 = 1671, centered rep is 1671 - 3329 = -1658
        assert_eq!(r, -1658);
    }

    #[test]
    fn test_montgomery_reduce_identity() {
        // Test that montgomery_reduce of a value in Montgomery range works
        let a = 1000i32;
        let ar = montgomery_reduce(a * 65536);
        // ar should be approximately a mod q
        let centered = barrett_reduce(ar);
        let expected = if a >= (KYBER_Q as i32) {
            a - (KYBER_Q as i32)
        } else {
            a
        };
        assert_eq!(centered, expected as i16);
    }
}
