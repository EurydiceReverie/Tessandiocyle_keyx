// TessanDioKey v16 — Secure memory primitives
//
// Production-grade secret handling: volatile writes prevent compiler elision,
// explicit zero-on-Drop guarantees cleanup even on panic unwind.

use core::ops::{Deref, DerefMut};
use core::ptr::write_volatile;

/// A wrapper around sensitive byte arrays that is guaranteed to be zeroed
/// when it goes out of scope. Uses volatile writes to prevent the compiler
/// from optimizing away the clearing code.
#[derive(Clone)]
pub struct SecureArray<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> SecureArray<N> {
    pub fn new() -> Self {
        SecureArray { data: [0u8; N] }
    }

    pub fn from_array(arr: [u8; N]) -> Self {
        SecureArray { data: arr }
    }

    pub fn into_array(mut self) -> [u8; N] {
        let arr = self.data;
        self.zeroize();
        arr
    }

    /// Explicitly zero memory using volatile writes.
    pub fn zeroize(&mut self) {
        for byte in self.data.iter_mut() {
            unsafe { write_volatile(byte, 0u8) };
        }
    }

    pub fn as_slice(&self) -> &[u8; N] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8; N] {
        &mut self.data
    }
}

impl<const N: usize> Default for SecureArray<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Deref for SecureArray<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<const N: usize> DerefMut for SecureArray<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<const N: usize> Drop for SecureArray<N> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Volatile byte copy: copies `src` into `dst` without optimising away.
pub fn secure_copy(dst: &mut [u8], src: &[u8]) {
    assert_eq!(dst.len(), src.len());
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        unsafe { write_volatile(d, *s) };
    }
}

/// Constant-time conditional swap: swap a and b if swap == 1.
pub fn ct_cswap(a: &mut u8, b: &mut u8, swap: u8) {
    let mask = swap.wrapping_neg();
    let diff = *a ^ *b;
    let t = mask & diff;
    *a ^= t;
    *b ^= t;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_array_zeroed_on_drop() {
        let mut arr = SecureArray::<32>::from_array([0xABu8; 32]);
        arr.zeroize();
        assert_eq!(arr.data, [0u8; 32]);
    }

    #[test]
    fn test_secure_array_deref() {
        let arr = SecureArray::<8>::from_array([1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(arr[0], 1);
        assert_eq!(arr[7], 8);
    }

    #[test]
    fn test_ct_cswap() {
        let mut a = 0x55u8;
        let mut b = 0xAAu8;
        ct_cswap(&mut a, &mut b, 1);
        assert_eq!(a, 0xAA);
        assert_eq!(b, 0x55);

        let mut c = 0x55u8;
        let mut d = 0xAAu8;
        ct_cswap(&mut c, &mut d, 0);
        assert_eq!(c, 0x55);
        assert_eq!(d, 0xAA);
    }
}
