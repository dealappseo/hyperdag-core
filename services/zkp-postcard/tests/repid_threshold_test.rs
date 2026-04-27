use sha2::{Digest, Sha256};
use zkp_postcard::circuit::prove_repid_threshold;

fn hash_commitment(holder: &[u8; 20], nonce: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(holder);
    hasher.update(nonce);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

#[test]
fn test_case_1_threshold_met_cleanly() {
    let holder = [1u8; 20];
    let nonce = [2u8; 32];
    let commitment = hash_commitment(&holder, &nonce);
    let result = prove_repid_threshold(8500, 7000, holder, nonce, commitment);
    assert!(result.is_ok(), "Proof should verify when R >= T");
}

#[test]
fn test_case_2_threshold_not_met() {
    let holder = [1u8; 20];
    let nonce = [2u8; 32];
    let commitment = hash_commitment(&holder, &nonce);
    let result = prove_repid_threshold(6500, 7000, holder, nonce, commitment);
    assert!(result.is_err(), "Proof generation should fail when R < T");
}

#[test]
fn test_case_3_forged_commitment() {
    let holder = [1u8; 20];
    let nonce = [2u8; 32];
    let mut forged_commitment = hash_commitment(&holder, &nonce);
    forged_commitment[0] ^= 0xFF; // tamper
    let result = prove_repid_threshold(8500, 7000, holder, nonce, forged_commitment);
    assert_eq!(result.err(), Some("commitment_mismatch".to_string()));
}

#[test]
fn test_case_4_boundary_case() {
    let holder = [1u8; 20];
    let nonce = [2u8; 32];
    let commitment = hash_commitment(&holder, &nonce);
    let result = prove_repid_threshold(7000, 7000, holder, nonce, commitment);
    assert!(result.is_ok(), "Proof should verify when R == T");
}

#[test]
fn test_case_5_out_of_bounds_r() {
    let holder = [1u8; 20];
    let nonce = [2u8; 32];
    let commitment = hash_commitment(&holder, &nonce);
    let result = prove_repid_threshold(10001, 7000, holder, nonce, commitment);
    assert!(result.is_err(), "Proof should fail when R > 10000");
}
