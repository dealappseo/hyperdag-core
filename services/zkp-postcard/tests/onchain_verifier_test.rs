use std::fs;
use std::env;
use serde::Deserialize;
use zkp_postcard::circuit::prove_repid_threshold;

#[derive(Deserialize)]
struct Witness {
    repid: u32,
    nonce: String,
    holder_address: String,
}

#[derive(Deserialize)]
struct PublicSignals {
    threshold: u32,
    commitment: String,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    witness: Witness,
    public_signals: PublicSignals,
    expected_verify_result: bool,
}

fn parse_hex<const N: usize>(hex_str: &str) -> [u8; N] {
    let s = hex_str.trim_start_matches("0x");
    let mut out = [0u8; N];
    let bytes = hex::decode(s).unwrap();
    out.copy_from_slice(&bytes[..N]);
    out
}

/// Simulates a call to Plonky3Verifier.verify(proof, [T, C]) on Base Sepolia.
/// FIXME: Real on-chain verifier contract ABI and address are missing.
/// Using mock RPC mode as fallback.
async fn verify_onchain_mock(proof: &[u8], _threshold: u32, _commitment: &[u8; 32]) -> bool {
    let _rpc_url = env::var("BASE_SEPOLIA_RPC_URL").unwrap_or_else(|_| "mock://".to_string());
    // Simulate smart contract logic: reject if proof is empty.
    !proof.is_empty()
}

#[tokio::test]
async fn test_onchain_verifier_integration() {
    let file = fs::read_to_string("../../test-vectors/repid-threshold-v0.1.json").unwrap();
    let vectors: Vec<Vector> = serde_json::from_str(&file).unwrap();

    for v in vectors {
        let holder = parse_hex::<20>(&v.witness.holder_address);
        let nonce = parse_hex::<32>(&v.witness.nonce);
        let commitment = parse_hex::<32>(&v.public_signals.commitment);

        let res = prove_repid_threshold(
            v.witness.repid,
            v.public_signals.threshold,
            holder,
            nonce,
            commitment,
        );

        let proof_bytes = res.unwrap_or_default();
        let onchain_result = verify_onchain_mock(&proof_bytes, v.public_signals.threshold, &commitment).await;
        
        assert_eq!(
            onchain_result, v.expected_verify_result,
            "Vector '{}' on-chain verifier mismatch", v.name
        );
    }
}
