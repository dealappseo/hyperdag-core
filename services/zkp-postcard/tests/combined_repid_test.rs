use sha2::{Digest, Sha256};
use zkp_postcard::variants::prove_combined_repid;

fn hash_commitment(holder: &[u8; 20], nonce: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(holder);
    hasher.update(nonce);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

#[test]
fn test_combined_happy_path() {
    let holder = [1u8; 20]; let nonce = [2u8; 32];
    let c = hash_commitment(&holder, &nonce);
    let earned_proof = b"mock_earned".to_vec();
    let perceived_proof = b"mock_perceived".to_vec();
    let res = prove_combined_repid(earned_proof, perceived_proof, 5000, holder, nonce, c);
    assert!(res.is_ok());
}

#[test]
fn test_combined_missing_inner() {
    let holder = [1u8; 20]; let nonce = [2u8; 32];
    let c = hash_commitment(&holder, &nonce);
    let earned_proof = vec![];
    let perceived_proof = b"mock_perceived".to_vec();
    let res = prove_combined_repid(earned_proof, perceived_proof, 5000, holder, nonce, c);
    assert!(res.is_err());
}

#[test]
fn test_combined_forged_commitment() {
    let holder = [1u8; 20]; let nonce = [2u8; 32];
    let mut forged = hash_commitment(&holder, &nonce);
    forged[0] ^= 0xFF;
    let earned_proof = b"mock_earned".to_vec();
    let perceived_proof = b"mock_perceived".to_vec();
    let res = prove_combined_repid(earned_proof, perceived_proof, 5000, holder, nonce, forged);
    assert_eq!(res.err(), Some("commitment_mismatch".to_string()));
}
