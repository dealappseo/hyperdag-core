//! KAT tests (B3 gate): prove the leaf's permutation + scoped nullifier match CC2's
//! canonical vectors (test-vectors/poseidon2_babybear_kat_v1.json) — i.e. we use the
//! SAME constants (default_babybear_poseidon2_16), not our own. If these pass on the
//! pinned build, the leaf's Poseidon2 + Inv-2 nullifier are correct-by-construction.

use babybear_leaf::{nullifier, permute16, poseidon2_16, WIDTH};
use serde_json::Value;

fn load_kat() -> Value {
    let raw = include_str!("../test-vectors/poseidon2_babybear_kat_v1.json");
    serde_json::from_str(raw).expect("parse KAT json")
}

fn u32s(v: &Value) -> Vec<u32> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_u64().unwrap() as u32)
        .collect()
}

#[test]
fn permutation_matches_canonical_kat() {
    let p = poseidon2_16();
    let kat = load_kat();
    for v in kat["permutation_kats"].as_array().unwrap() {
        let inp = u32s(&v["in"]);
        let exp = u32s(&v["out"]);
        let mut arr = [0u32; WIDTH];
        for (i, x) in inp.iter().enumerate() {
            arr[i] = *x;
        }
        let got = permute16(&p, arr).to_vec();
        assert_eq!(
            got,
            exp,
            "permutation KAT '{}' mismatch — leaf is NOT using the canonical constants",
            v["name"].as_str().unwrap_or("?")
        );
    }
}

#[test]
fn nullifier_matches_canonical_kat() {
    let p = poseidon2_16();
    let kat = load_kat();
    for v in kat["nullifier_kats"].as_array().unwrap() {
        let secret = v["secret"].as_u64().unwrap() as u32;
        let scope = v["scope"].as_u64().unwrap() as u32;
        let exp = v["nullifier"].as_u64().unwrap() as u32;
        assert_eq!(
            nullifier(&p, secret, scope),
            exp,
            "nullifier KAT secret={secret} scope={scope} mismatch"
        );
    }
}

#[test]
fn scope_separation_inv2() {
    // Inv-2 unlinkability: same secret, different scope => different nullifier.
    let p = poseidon2_16();
    let s = 1234567u32;
    let a = nullifier(&p, s, 1001); // ownership scope (agentId)
    let b = nullifier(&p, s, 1002);
    let c = nullifier(&p, s, 7777); // reserved health-vertical scope
    assert_ne!(a, b);
    assert_ne!(a, c);
    assert_ne!(b, c);
    // different secret, same scope => different nullifier.
    assert_ne!(nullifier(&p, 1234567, 1001), nullifier(&p, 7654321, 1001));
}
