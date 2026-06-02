use std::time::Instant;
use tessandiocyle_keyx::kem::{crypto_kem_dec, crypto_kem_enc_derand, crypto_kem_keypair_derand};
use tessandiocyle_keyx::params::*;
use tessandiocyle_keyx::secure::SecureArray;

const SAMPLES: usize = 100_000;
const THRESHOLD: f64 = 10.0; // |t| < 10 is considered safe

fn main() {
    println!("=== TessanDioKey v16 — Timing Side-Channel Detection (dudect-style) ===\n");
    println!("Collecting {} timing samples per class...\n", SAMPLES);

    let mut pk = [0u8; KYBER_PUBLICKEYBYTES];
    let mut sk_random = [0u8; KYBER_SECRETKEYBYTES];
    let mut sk_fixed = [0u8; KYBER_SECRETKEYBYTES];

    let kp_coins = [0x01u8; 2 * KYBER_SYMBYTES];
    crypto_kem_keypair_derand(&mut pk, &mut sk_random, &kp_coins);
    crypto_kem_keypair_derand(&mut pk, &mut sk_fixed, &kp_coins);

    // Pre-generate a fixed ciphertext to avoid encapsulation noise in timing
    let mut ct = [0u8; KYBER_CIPHERTEXTBYTES];
    let mut ss = [0u8; KYBER_SSBYTES];
    let enc_coins = [0xAAu8; KYBER_SYMBYTES];
    crypto_kem_enc_derand(&mut ct, &mut ss, &pk, &enc_coins);

    let mut times_random: Vec<f64> = Vec::with_capacity(SAMPLES);
    let mut times_fixed: Vec<f64> = Vec::with_capacity(SAMPLES);

    // Warm-up to stabilize CPU caches / branch predictors
    let mut tmp = [0u8; KYBER_SSBYTES];
    for _ in 0..100 {
        crypto_kem_dec(&mut tmp, &ct, &sk_random);
        crypto_kem_dec(&mut tmp, &ct, &sk_fixed);
    }

    // Collect interleaved samples to mitigate temporal drift
    for i in 0..SAMPLES {
        // Random-key class
        let start = Instant::now();
        let mut out = SecureArray::<KYBER_SSBYTES>::new();
        crypto_kem_dec(&mut out, &ct, &sk_random);
        let elapsed = start.elapsed().as_nanos() as f64;
        times_random.push(elapsed);

        // Fixed-key class
        let start = Instant::now();
        let mut out = SecureArray::<KYBER_SSBYTES>::new();
        crypto_kem_dec(&mut out, &ct, &sk_fixed);
        let elapsed = start.elapsed().as_nanos() as f64;
        times_fixed.push(elapsed);

        if (i + 1) % (SAMPLES / 10) == 0 {
            println!("  Progress: {}%", (i + 1) * 100 / SAMPLES);
        }
    }

    // Compute Welch's t-test
    let (mean_r, var_r) = mean_var(&times_random);
    let (mean_f, var_f) = mean_var(&times_fixed);

    let n = SAMPLES as f64;
    let pooled_var = (var_r + var_f) / n;
    let t_stat = if pooled_var > 0.0 {
        (mean_r - mean_f).abs() / pooled_var.sqrt()
    } else {
        0.0
    };

    println!("\nResults:");
    println!("  Random-key mean: {:.2} ns", mean_r);
    println!("  Fixed-key  mean: {:.2} ns", mean_f);
    println!("  t-statistic:     {:.2}", t_stat);

    if t_stat < THRESHOLD {
        println!("\n[PASS] |t| < {} — no significant timing leakage detected.", THRESHOLD);
    } else {
        println!("\n[WARNING] |t| >= {} — possible timing side-channel detected!", THRESHOLD);
        std::process::exit(1);
    }
}

fn mean_var(data: &[f64]) -> (f64, f64) {
    let n = data.len() as f64;
    let mean = data.iter().sum::<f64>() / n;
    let var = data.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
    (mean, var)
}
