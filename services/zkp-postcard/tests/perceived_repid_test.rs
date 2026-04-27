use sha2::{Digest, Sha256};
use zkp_postcard::variants::prove_perceived_repid;

fn hash_commitment(holder: &[u8; 20], nonce: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(holder);
    hasher.update(nonce);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

#[test]
fn test_perceived_happy_path() {
    let holder = [1u8; 20]; let nonce = [2u8; 32];
    let c = hash_commitment(&holder, &nonce);
    let atts = vec![500, 1000]; // sum = 1500
    let res = prove_perceived_repid(atts, 1000, holder, nonce, c);
    assert!(res.is_ok());
}

#[test]
fn test_perceived_boundary() {
    let holder = [1u8; 20]; let nonce = [2u8; 32];
    let c = hash_commitment(&holder, &nonce);
    let atts = vec![1000]; // sum = 1000
    let res = prove_perceived_repid(atts, 1000, holder, nonce, c);
    assert!(res.is_ok());
}

#[test]
fn test_perceived_failure() {
    let holder = [1u8; 20]; let nonce = [2u8; 32];
    let c = hash_commitment(&holder, &nonce);
    let atts = vec![500]; // sum = 500
    let res = prove_perceived_repid(atts, 1000, holder, nonce, c);
    assert!(res.is_err());
}
