use tessandiocyle_keyx::indcpa::{indcpa_keypair_derand, indcpa_enc, indcpa_dec};
use tessandiocyle_keyx::params::*;
use tessandiocyle_keyx::ntt::set_ntt_seed;

fn main() {
    // Deterministic coins
    let mut coins = [0u8; KYBER_SYMBYTES];
    for i in 0..KYBER_SYMBYTES { coins[i] = (0x11u8).wrapping_mul(i as u8); }
    let mut pk = [0u8; KYBER_PUBLICKEYBYTES];
    let mut sk = [0u8; KYBER_INDCPA_SECRETKEYBYTES];
    
    set_ntt_seed(0);
    indcpa_keypair_derand(&mut pk, &mut sk, &coins);
    
    println!("pk[0..16]: {:02x?}", &pk[0..16]);
    println!("pk[1152..1184] (seed): {:02x?}", &pk[KYBER_POLYVECBYTES..KYBER_PUBLICKEYBYTES]);
    println!("sk[0..16]: {:02x?}", &sk[0..16]);
    
    // Encrypt
    let mut m = [0u8; KYBER_SYMBYTES];
    for i in 0..KYBER_SYMBYTES { m[i] = 0xAAu8.wrapping_add(i as u8); }
    let mut enc_coins = [0u8; KYBER_SYMBYTES];
    for i in 0..KYBER_SYMBYTES { enc_coins[i] = 0x55u8.wrapping_add(i as u8); }
    let mut ct = [0u8; KYBER_INDCPA_BYTES];
    set_ntt_seed(0);
    indcpa_enc(&mut ct, &m, &pk, &enc_coins);
    println!("ct[0..16]: {:02x?}", &ct[0..16]);
    
    // Decrypt
    let mut m_dec = [0u8; KYBER_SYMBYTES];
    set_ntt_seed(0);
    indcpa_dec(&mut m_dec, &ct, &sk);
    println!("m:     {:02x?}", &m[..16]);
    println!("m_dec: {:02x?}", &m_dec[..16]);
    assert_eq!(m, m_dec, "IND-CPA roundtrip failed!");
    println!("IND-CPA roundtrip: OK");
}
