//! BabyBear identity leaf (B3) — WITNESS-LEVEL computation over the CANONICAL
//! Poseidon2-16 permutation (`p3_baby_bear::default_babybear_poseidon2_16()` — NO
//! hand-rolled constants). Ports the BN254/circom `reputation_proof.circom` leaf to
//! BabyBear per ZK_BABYBEAR_LEAF_PORT_SPEC. Scoped nullifier per Inv-2.
//!
//! SCOPE OF THIS FILE: the field computations only (commitment, Merkle membership,
//! scoped nullifier) + KAT tests proving they match CC2's canonical vectors. The
//! IN-CIRCUIT AIR constraints (proving these relations inside a STARK) are the next
//! layer; the points/contrib range-checks reuse zkp-postcard's existing u32 range-check
//! AIR. The BN254 circom leaf is NOT deleted — retirement waits until this is load-bearing.
//!
//! Mirrors CC2's generator (03_specs/poseidon2_kat_generator) exactly so the leaf is
//! correct-by-construction against poseidon2_babybear_kat_v1.json.

use p3_baby_bear::{BabyBear, default_babybear_poseidon2_16};
use p3_field::PrimeField32;
use p3_symmetric::Permutation;

pub const WIDTH: usize = 16;

/// The canonical width-16 Poseidon2-BabyBear permutation (pinned-rev fixed constants).
pub fn poseidon2_16() -> impl Permutation<[BabyBear; WIDTH]> {
    default_babybear_poseidon2_16()
}

/// Apply the permutation to a 16-wide u32 state; return the 16-wide u32 output.
pub fn permute16(p: &impl Permutation<[BabyBear; WIDTH]>, x: [u32; WIDTH]) -> [u32; WIDTH] {
    let mut s = BabyBear::new_array(x);
    p.permute_mut(&mut s);
    let mut out = [0u32; WIDTH];
    for (i, e) in s.iter().enumerate() {
        out[i] = e.as_canonical_u32();
    }
    out
}

/// Single-field digest: `permute([inputs.., 0-pad])[0]`. ONE hash primitive for the
/// leaf, all from the canonical permutation. (Capacity / domain-separation layout is
/// Track B's to ratify — matches the KAT's `nullifier_def` note.)
pub fn hash(p: &impl Permutation<[BabyBear; WIDTH]>, inputs: &[u32]) -> u32 {
    let mut a = [0u32; WIDTH];
    for (i, x) in inputs.iter().take(WIDTH).enumerate() {
        a[i] = *x;
    }
    permute16(p, a)[0]
}

/// Identity commitment `C1 = hash(secret, nullifier, trapdoor)` (Semaphore-style),
/// porting circom `identityCommitment = Poseidon(3)(secret, nullifier, trapdoor)`.
pub fn commitment(
    p: &impl Permutation<[BabyBear; WIDTH]>,
    secret: u32,
    nullifier: u32,
    trapdoor: u32,
) -> u32 {
    hash(p, &[secret, nullifier, trapdoor])
}

/// Merkle 2-to-1 compression for membership, porting circom `Poseidon(2)` pair hash.
pub fn merkle_compress(p: &impl Permutation<[BabyBear; WIDTH]>, left: u32, right: u32) -> u32 {
    hash(p, &[left, right])
}

/// SCOPED nullifier (Inv-2): `N(secret, scope) = permute([secret, scope, 0..])[0]`.
/// `scope` is a PARAMETER — agentId for ownership, studyId (reserved) for the health
/// vertical — NEVER hardcoded (the circom leaf's `Poseidon(2)(nullifier, 1)` literal `1`
/// is exactly the Inv-2 violation this fixes). Different scope => different nullifier.
pub fn nullifier(p: &impl Permutation<[BabyBear; WIDTH]>, secret: u32, scope: u32) -> u32 {
    hash(p, &[secret, scope])
}

/// Recompute the Merkle root from a leaf + path (porting the circom 20-level loop with
/// `Mux1` ordering). `index_bits[i]`: 0 => accumulator on the left, 1 => on the right.
pub fn merkle_root(
    p: &impl Permutation<[BabyBear; WIDTH]>,
    leaf: u32,
    siblings: &[u32],
    index_bits: &[u8],
) -> u32 {
    assert_eq!(
        siblings.len(),
        index_bits.len(),
        "siblings/index_bits length mismatch"
    );
    let mut acc = leaf;
    for (sib, bit) in siblings.iter().zip(index_bits.iter()) {
        acc = if *bit == 0 {
            merkle_compress(p, acc, *sib)
        } else {
            merkle_compress(p, *sib, acc)
        };
    }
    acc
}
