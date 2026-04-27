use std::fs;
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
    expected_proof_hash: String,
    expected_verify_result: bool,
}

fn parse_hex<const N: usize>(hex_str: &str) -> [u8; N] {
    let s = hex_str.trim_start_matches("0x");
    let mut out = [0u8; N];
    let bytes = hex::decode(s).unwrap();
    out.copy_from_slice(&bytes[..N]);
    out
}

#[test]
fn test_all_vectors() {
    let file = fs::read_to_string("../../test-vectors/repid-threshold-v0.1.json").unwrap();
    let vectors: Vec<Vector> = serde_json::from_str(&file).unwrap();

    for v in vectors {
        println!("Running vector: {}", v.name);
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

        if v.expected_verify_result {
            assert!(res.is_ok(), "Vector '{}' failed to generate valid proof: {:?}", v.name, res.err());
            let proof = String::from_utf8(res.unwrap()).unwrap();
            assert_eq!(proof, v.expected_proof_hash, "Vector '{}' hash mismatch", v.name);
        } else {
            assert!(res.is_err(), "Vector '{}' expected failure but succeeded", v.name);
        }
    }
}
