//! Golden-output regression test for `utils::replace_with_rng`.
//!
//! Asserts that with a fixed `ChaCha20Rng` seed and fixed inputs, the bytes
//! written into the template are bit-for-bit stable across machines. This is
//! the load-bearing test that proves the seeded-RNG plumbing in
//! `replace_with_rng` actually makes the random padding deterministic.
//!
//! If this test fails after an intentional change to `replace` semantics
//! (different padding scheme, different ordering, etc.), update the expected
//! SHA-256 below to the new value and explain the change in the commit.

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

const HOLDER: &[u8] = b"$$SHELLCODE$$";
const REPLACEMENT: &[u8] = b"\x90\x90\x90\xc3";
const MAX_LEN: usize = 32;

/// Stable hash of (HOLDER, REPLACEMENT, MAX_LEN, seed=0) under the v1.1.2
/// `replace_with_rng` implementation. Computed via test self-print on Linux
/// x86_64; ChaCha20Rng output is platform-independent so the same hash must
/// appear on macOS/Windows too.
const EXPECTED_SHA256: &str = "a080586ef98f9ccd07fbdbcc0d5612dae0a676c97fe245a497c82937f5737071";

fn build_template() -> Vec<u8> {
    let mut bin = Vec::new();
    bin.extend_from_slice(&[0xAB; 64]);
    bin.extend_from_slice(HOLDER);
    bin.extend(std::iter::repeat_n(b'0', MAX_LEN - HOLDER.len()));
    bin.extend_from_slice(&[0xCD; 64]);
    bin
}

#[test]
fn replace_with_rng_is_deterministic_under_fixed_seed() {
    let mut bin = build_template();
    let mut rng = ChaCha20Rng::seed_from_u64(0);

    pumpbin::utils::replace_with_rng(&mut bin, HOLDER, REPLACEMENT, MAX_LEN, &mut rng)
        .expect("replace_with_rng failed");

    let actual = format!("{:x}", Sha256::digest(&bin));

    if actual != EXPECTED_SHA256 {
        // Self-print so the first run can capture the right value. Update
        // EXPECTED_SHA256 to this value if the change is intentional.
        panic!(
            "golden output drift.\n  expected: {}\n  actual:   {}\n  full bin (hex): {}",
            EXPECTED_SHA256,
            actual,
            hex_dump(&bin),
        );
    }
}

#[test]
fn replace_with_rng_is_stable_across_two_runs_same_seed() {
    let mut bin_a = build_template();
    let mut bin_b = build_template();

    pumpbin::utils::replace_with_rng(
        &mut bin_a,
        HOLDER,
        REPLACEMENT,
        MAX_LEN,
        &mut ChaCha20Rng::seed_from_u64(0xDEAD_BEEF),
    )
    .unwrap();
    pumpbin::utils::replace_with_rng(
        &mut bin_b,
        HOLDER,
        REPLACEMENT,
        MAX_LEN,
        &mut ChaCha20Rng::seed_from_u64(0xDEAD_BEEF),
    )
    .unwrap();

    assert_eq!(bin_a, bin_b, "same seed must produce identical output");
}

fn hex_dump(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
