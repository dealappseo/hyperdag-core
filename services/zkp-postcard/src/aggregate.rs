// P2 — PACKAGE aggregation (ZKP aggregation-depth sprint, 2026-06-10).
//
// Folds N real Poseidon2/BabyBear leaves (from P1's corpus) into ONE aggregation root, and proves
// the whole batch's range property (every agent's repid > its threshold) in ONE STARK.
//
// HONEST SCOPE — recursion-over-DATA, not recursion-over-PROOFS:
//   * The fold is a Poseidon2 binary Merkle tree (canonical default_babybear_poseidon2_16 via the
//     `babybear-leaf` crate) → one root, golden-KAT-frozen. Each leaf gets a membership path that
//     reproduces the root. This is the aggregation DATA STRUCTURE the architecture's AGGREGATION
//     tier anchors (one root for many leaves), and it is aggregation-READY because the leaves are
//     Poseidon2, not sha256 (Invariant 1).
//   * The batch STARK (`RepIdBatchRangeCheckAir`) proves N value-bound 16-bit range relations
//     (repid_i > threshold_i for every row) in a single proof, with the aggregation root bound
//     into the Fiat-Shamir transcript (public value) so the proof is non-transferable across
//     batches — exactly the agent-binding mechanism, lifted to the batch.
//   * What this is NOT (documented, deferred): a recursive STARK that VERIFIES each leaf's FRI
//     proof inside the AIR. True proof-recursion needs an in-circuit FRI/Poseidon2 verifier, which
//     the pinned Plonky3 (27d59f7350) does not ship; it is the next tier. Likewise the binding of
//     the in-trace (repid_i, threshold_i) to the in-leaf values is witness-level (checkable by
//     recomputing the leaf), not an in-AIR Poseidon2 constraint — the same Poseidon2-in-AIR gap
//     LETTER documents. No mock-as-real: the fold is real, the batch range-proof is real, the
//     leaf↔trace arithmetic binding is the named upgrade.

#![allow(dead_code)]

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::FriParameters as FriConfig;
use p3_keccak::Keccak256Hash;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_monty_31::dft::RecursiveDft;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{prove, verify, StarkConfig};

/* ----------------------------------------------------------------------- */
/* Poseidon2 Merkle aggregation (the fold)                                  */
/* ----------------------------------------------------------------------- */

/// Aggregation root over `leaves` (the postcard Poseidon2 leaf felts), folded with the canonical
/// Poseidon2 2-to-1 compression. Bitcoin-style odd-level handling: a lone node is paired with
/// itself. Empty set → 0. Single leaf → that leaf. Deterministic.
pub fn aggregate_root(leaves: &[u32]) -> u32 {
    if leaves.is_empty() {
        return 0;
    }
    let p = babybear_leaf::poseidon2_16();
    let mut level: Vec<u32> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() { level[i + 1] } else { left }; // odd → duplicate
            next.push(babybear_leaf::merkle_compress(&p, left, right));
            i += 2;
        }
        level = next;
    }
    level[0]
}

#[derive(Debug, Clone, PartialEq)]
pub struct MembershipProof {
    pub leaf: u32,
    pub index: usize,
    /// (sibling, sibling_is_right) per level, leaf→root.
    pub siblings: Vec<(u32, bool)>,
    pub root: u32,
}

/// Build a membership path for `index` against the same tree `aggregate_root` builds.
pub fn membership_proof(leaves: &[u32], index: usize) -> MembershipProof {
    assert!(!leaves.is_empty() && index < leaves.len(), "index out of range");
    let p = babybear_leaf::poseidon2_16();
    let mut siblings = Vec::new();
    let mut level: Vec<u32> = leaves.to_vec();
    let mut idx = index;
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() { level[i + 1] } else { left };
            next.push(babybear_leaf::merkle_compress(&p, left, right));
            i += 2;
        }
        if idx % 2 == 0 {
            let sib = if idx + 1 < level.len() { level[idx + 1] } else { level[idx] };
            siblings.push((sib, true)); // sibling on the right
        } else {
            siblings.push((level[idx - 1], false)); // sibling on the left
        }
        idx /= 2;
        level = next;
    }
    MembershipProof { leaf: leaves[index], index, siblings, root: level[0] }
}

/// Verify a membership path reproduces the root.
pub fn verify_membership(proof: &MembershipProof) -> bool {
    let p = babybear_leaf::poseidon2_16();
    let mut acc = proof.leaf;
    for (sib, sib_is_right) in &proof.siblings {
        acc = if *sib_is_right {
            babybear_leaf::merkle_compress(&p, acc, *sib)
        } else {
            babybear_leaf::merkle_compress(&p, *sib, acc)
        };
    }
    acc == proof.root
}

/* ----------------------------------------------------------------------- */
/* Batch range-check STARK (one proof, N value-bound range relations)       */
/* ----------------------------------------------------------------------- */

const BATCH_WIDTH: usize = 34; // [0..32]=gap bits (big-endian), [32]=repid, [33]=threshold
const COL_REPID: usize = 32;
const COL_THRESHOLD: usize = 33;
/// Public values: [0]=aggregation root felt, [1]=leaf count.
pub const BATCH_NUM_PUBLIC_VALUES: usize = 2;

pub struct RepIdBatchRangeCheckAir;

impl<F: Field> BaseAir<F> for RepIdBatchRangeCheckAir {
    fn width(&self) -> usize {
        BATCH_WIDTH
    }
    fn num_public_values(&self) -> usize {
        BATCH_NUM_PUBLIC_VALUES
    }
}

impl<AB: AirBuilder> Air<AB> for RepIdBatchRangeCheckAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();

        let repid = row[COL_REPID];
        let threshold = row[COL_THRESHOLD];

        // 16-bit range check applied to EVERY row (same soundness fix as the single postcard):
        // high 16 bits zero, low 16 boolean, reconstructed == repid - threshold - 1.
        for i in 0..16 {
            builder.assert_zero(row[i]);
        }
        let mut reconstructed = AB::Expr::ZERO;
        for i in 16..32 {
            let bit = row[i];
            builder.assert_bool(bit);
            reconstructed += AB::Expr::from_u32(1 << (31 - i)) * bit;
        }
        // Value-binding per row, on ALL rows (padding rows use repid=1,threshold=0 → 0==0).
        builder.assert_eq(reconstructed, repid.into() - threshold.into() - AB::Expr::ONE);
    }
}

/// One trace row for statement (repid, threshold): 32 big-endian bits of the gap, then repid, threshold.
fn batch_row<F: Field>(repid: u64, threshold: u64) -> Vec<F> {
    let gap = (repid - threshold - 1) as u32;
    let mut r = Vec::with_capacity(BATCH_WIDTH);
    for i in (0..32).rev() {
        r.push(if (gap & (1 << i)) != 0 { F::ONE } else { F::ZERO });
    }
    r.push(F::from_u32(repid as u32));
    r.push(F::from_u32(threshold as u32));
    r
}

#[derive(Debug, Clone)]
pub struct BatchProof {
    pub proof_bytes: Vec<u8>,
    pub root: u32,
    pub leaf_count: usize,
    pub padded_height: usize,
}

/// Prove the whole batch in ONE STARK: every (repid_i > threshold_i) via a value-bound 16-bit range
/// check, with the aggregation root over `leaves` bound into the transcript. `statements` and
/// `leaves` are index-aligned (leaves[i] is the postcard leaf of statements[i]). Pads to a power of
/// two with the trivial valid statement (repid=1, threshold=0).
pub fn prove_batch(statements: &[(u64, u64)], leaves: &[u32]) -> Result<BatchProof, String> {
    if statements.is_empty() {
        return Err("empty batch".into());
    }
    if statements.len() != leaves.len() {
        return Err(format!("statements/leaves length mismatch: {} vs {}", statements.len(), leaves.len()));
    }
    for (i, (repid, threshold)) in statements.iter().enumerate() {
        if repid <= threshold {
            return Err(format!("statement {} not positive: repid {} <= threshold {}", i, repid, threshold));
        }
        if *repid >= (1u64 << 31) || *threshold >= (1u64 << 31) {
            return Err(format!("statement {} out of field range", i));
        }
        // gap < 2^16 (the 16-bit soundness assumption) — fail-closed if a spread is too large.
        if repid - threshold - 1 >= (1u64 << 16) {
            return Err(format!("statement {} gap >= 2^16 (out of 16-bit range)", i));
        }
    }

    type Val = BabyBear;
    type Challenge = BinomialExtensionField<Val, 4>;
    type ByteHash = Keccak256Hash;
    type FieldHash = SerializingHasher<ByteHash>;
    type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
    type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 2, 32>;
    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    type Dft = RecursiveDft<Val>;
    type Pcs = p3_fri::TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(ByteHash {});
    let compress = MyCompress::new(byte_hash);
    let val_mmcs = ValMmcs::new(field_hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    // Build the padded trace (power-of-two height).
    let height = statements.len().next_power_of_two().max(2);
    let mut flat: Vec<Val> = Vec::with_capacity(height * BATCH_WIDTH);
    for (repid, threshold) in statements {
        flat.extend(batch_row::<Val>(*repid, *threshold));
    }
    for _ in statements.len()..height {
        flat.extend(batch_row::<Val>(1, 0)); // trivial valid pad: gap=0, 0 == 1-0-1
    }
    let trace = RowMajorMatrix::new(flat, BATCH_WIDTH);

    let fri_config = FriConfig {
        log_blowup: 2,
        num_queries: 28,
        log_final_poly_len: 0,
        max_log_arity: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 8,
        mmcs: challenge_mmcs,
    };
    let dft = Dft::new(trace.height() << fri_config.log_blowup);
    let pcs = Pcs::new(dft, val_mmcs, fri_config);
    let challenger = SerializingChallenger32::new(HashChallenger::<u8, ByteHash, 32>::new(vec![], byte_hash));
    let config = StarkConfig::new(pcs, challenger);

    let root = aggregate_root(leaves);
    let public_values = vec![Val::new(root), Val::new(leaves.len() as u32)];

    let air = RepIdBatchRangeCheckAir;
    let proof = prove(&config, &air, trace, &public_values);
    verify(&config, &air, &proof, &public_values).map_err(|e| format!("batch verify failed: {:?}", e))?;
    let proof_bytes = bincode::serialize(&proof).map_err(|e| format!("serialize: {}", e))?;

    Ok(BatchProof { proof_bytes, root, leaf_count: leaves.len(), padded_height: height })
}

/// Re-verify a batch proof against an independently supplied root + leaf count (the verifier path:
/// recompute root = aggregate_root(leaves) yourself, then this must pass only for that root).
pub fn verify_batch(proof_bytes: &[u8], root: u32, leaf_count: usize) -> Result<(), String> {
    type Val = BabyBear;
    type Challenge = BinomialExtensionField<Val, 4>;
    type ByteHash = Keccak256Hash;
    type FieldHash = SerializingHasher<ByteHash>;
    type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
    type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 2, 32>;
    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    type Dft = RecursiveDft<Val>;
    type Pcs = p3_fri::TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(ByteHash {});
    let compress = MyCompress::new(byte_hash);
    let val_mmcs = ValMmcs::new(field_hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_config = FriConfig {
        log_blowup: 2,
        num_queries: 28,
        log_final_poly_len: 0,
        max_log_arity: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 8,
        mmcs: challenge_mmcs,
    };
    // height-independent on the verify side (dft size doesn't affect verification correctness here
    // because the proof carries its own degree info); use a nominal dft.
    let dft = Dft::new(4);
    let pcs = Pcs::new(dft, val_mmcs, fri_config);
    let challenger = SerializingChallenger32::new(HashChallenger::<u8, ByteHash, 32>::new(vec![], byte_hash));
    let config = StarkConfig::new(pcs, challenger);

    let proof: p3_uni_stark::Proof<_> =
        bincode::deserialize(proof_bytes).map_err(|e| format!("deserialize: {}", e))?;
    let public_values = vec![Val::new(root), Val::new(leaf_count as u32)];
    let air = RepIdBatchRangeCheckAir;
    verify(&config, &air, &proof, &public_values).map_err(|e| format!("verify failed: {:?}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::poseidon2_postcard_leaf_felt;
    use crate::corpus;

    // Frozen golden aggregation root (P2 KAT). Folds the first three real corpus leaves
    // (MEDIATOR/SKEPTIC/NEWCOMER at their tightest threshold) → one root. If the Poseidon2
    // permutation, the leaf encoding, the fold order, or the pin drifts, this breaks the build —
    // the aggregation-root tripwire (a silent change would make every anchored PACKAGE root
    // unverifiable against the leaves it claims to commit).
    const GOLDEN_AGG_ROOT_3: &str = "0x5e8a02f1"; // aggregate_root(three_leaves), frozen

    fn three_leaves() -> Vec<u32> {
        vec![
            poseidon2_postcard_leaf_felt("394b6ee4-62e7-4c66-8445-29107b097b4c", 999, 2280), // MEDIATOR
            poseidon2_postcard_leaf_felt("2538b7ed-acdb-4423-b5bf-a9e18069ec99", 833, 834),  // SKEPTIC
            poseidon2_postcard_leaf_felt("d71b1e49-ce20-4e1c-b21f-3501dd852f6a", 59, 60),    // NEWCOMER
        ]
    }

    #[test]
    #[ignore]
    fn print_golden_agg_root() {
        eprintln!("GOLDEN_AGG_ROOT_3=0x{:08x}", aggregate_root(&three_leaves()));
    }

    #[test]
    fn agg_root_golden_kat() {
        // Frozen known-answer for the aggregation root over three real corpus leaves. Breaks the
        // build if the Poseidon2 permutation, leaf encoding, fold order, or pin drifts — so an
        // anchored PACKAGE root can never silently diverge from the leaves it claims to commit.
        assert_eq!(
            format!("0x{:08x}", aggregate_root(&three_leaves())),
            GOLDEN_AGG_ROOT_3,
            "aggregation root drifted — anchored roots would be unverifiable against their leaves"
        );
    }

    #[test]
    fn agg_root_deterministic_and_order_sensitive() {
        let l = three_leaves();
        assert_eq!(aggregate_root(&l), aggregate_root(&l), "root deterministic");
        let mut rev = l.clone();
        rev.reverse();
        assert_ne!(aggregate_root(&l), aggregate_root(&rev), "root is order-sensitive (fold structure)");
        assert_eq!(aggregate_root(&l[..1]), l[0], "single leaf folds to itself");
    }

    #[test]
    fn membership_paths_reproduce_root() {
        // Use a real spread of corpus leaves.
        let leaves: Vec<u32> = corpus::REAL_AGENTS
            .iter()
            .map(|(_, id, repid)| poseidon2_postcard_leaf_felt(id, 0, *repid))
            .collect();
        let root = aggregate_root(&leaves);
        for i in 0..leaves.len() {
            let mp = membership_proof(&leaves, i);
            assert_eq!(mp.root, root, "membership root matches aggregate root (leaf {})", i);
            assert!(verify_membership(&mp), "membership path verifies (leaf {})", i);
        }
        // A tampered leaf must fail membership.
        let mut bad = membership_proof(&leaves, 3);
        bad.leaf ^= 1;
        assert!(!verify_membership(&bad), "tampered leaf fails membership");
    }

    #[test]
    fn batch_proof_folds_real_corpus_and_verifies_e2e() {
        // Take a real spread (every agent at threshold 0 → gap = repid-1, all < 2^16 since repid<=2280).
        let stmts: Vec<(u64, u64)> = corpus::REAL_AGENTS.iter().map(|(_, _, r)| (*r, 0u64)).collect();
        let leaves: Vec<u32> = corpus::REAL_AGENTS
            .iter()
            .map(|(_, id, r)| poseidon2_postcard_leaf_felt(id, 0, *r))
            .collect();

        let bp = prove_batch(&stmts, &leaves).expect("batch proves");
        assert_eq!(bp.leaf_count, leaves.len());
        assert_eq!(bp.root, aggregate_root(&leaves), "batch root == independent fold");

        // e2e verify: the verifier recomputes the root from the leaves and checks the one proof.
        let recomputed = aggregate_root(&leaves);
        verify_batch(&bp.proof_bytes, recomputed, leaves.len()).expect("batch verifies under real root");

        // Binding: the proof must NOT verify under a different root (non-transferable across batches).
        assert!(verify_batch(&bp.proof_bytes, recomputed ^ 1, leaves.len()).is_err(), "wrong root rejected");
    }

    #[test]
    fn batch_rejects_non_positive_statement() {
        let stmts = vec![(100u64, 50u64), (40u64, 40u64)]; // second is repid==threshold
        let leaves = vec![1u32, 2u32];
        assert!(prove_batch(&stmts, &leaves).is_err(), "batch with a non-positive statement must not prove");
    }
}
