// F-P3 — PROOF-RECURSION SPIKE (ZKP frontier, 2026-06-10). **SPIKE, NOT PRODUCTION.**
//
// The named frontier from CC_ZKP_AGGREGATION_DEPTH_REPORT: true proof-recursion (a STARK that
// VERIFIES child FRI proofs *inside* its AIR) is the next tier and is NOT built. This is a minimal,
// RUNNABLE 2-level recursion tree so the frontier invites contribution, not just comment:
//
//   child_1 = batch-prove(real leaves A)  ─┐
//   child_2 = batch-prove(real leaves B)  ─┤→ verify both NATIVELY → fold their roots
//                                          │   parent_root = Poseidon2-fold(R1, R2)
//   parent  = batch-prove([parent as the   ┘   → one proof at the top of the tree
//             public root over (R1,R2)])
//
// The whole tree verifies end-to-end: both children verify, and the parent verifies under the
// independently-recomputed parent_root. That demonstrates the RECURSION TREE SHAPE (2 leaves of
// proofs → 1 root proof) on real data.
//
// ── THE HONEST GAP (what makes this a spike, not the real tier) ──────────────────────────────
//   * The children are verified NATIVELY (host calls `verify_batch`), NOT inside the parent AIR.
//     True recursion replaces that host call with an in-circuit FRI verifier so the parent proof
//     ALONE attests "both children are valid" with no need to re-check them. That in-AIR FRI/
//     Poseidon2 verifier is the open problem (see CONTRIBUTING.md → "proof-recursion / in-AIR FRI").
//   * `parent_root == Poseidon2-fold(R1, R2)` is witness-level here (recompute to check), not an
//     in-AIR Poseidon2 constraint — the same Poseidon2-in-AIR gap LETTER/PACKAGE name.
//   No mock-as-real: every proof below is a real Plonky3 STARK over the pinned prover; only the
//   *recursion* (verify-in-circuit) is simulated by a native host verify, and it is labeled as such.

#![allow(dead_code)]

use crate::aggregate::{aggregate_root, prove_batch, verify_batch, BatchProof};

/// A 2-level recursion result: two child batch proofs + their folded parent proof.
#[derive(Debug)]
pub struct RecursionTree {
    pub child_roots: Vec<u32>,
    pub parent_root: u32,
    pub child_proofs: Vec<BatchProof>,
    pub parent_proof: BatchProof,
}

/// Build a 2-level recursion tree over two real statement/leaf batches.
/// `batch_a`/`batch_b` are `(statements, leaves)` index-aligned, exactly as `prove_batch` wants.
pub fn prove_recursion_tree(
    batch_a: (&[(u64, u64)], &[u32]),
    batch_b: (&[(u64, u64)], &[u32]),
) -> Result<RecursionTree, String> {
    // ── Level 0: two real child batch-proofs ──
    let child_1 = prove_batch(batch_a.0, batch_a.1)?;
    let child_2 = prove_batch(batch_b.0, batch_b.1)?;

    // ── The recursion step (SPIKE: native verify stands in for in-AIR FRI verify) ──
    // True recursion does this check INSIDE the parent AIR; here the host does it.
    verify_batch(&child_1.proof_bytes, child_1.root, child_1.leaf_count)?;
    verify_batch(&child_2.proof_bytes, child_2.root, child_2.leaf_count)?;

    // ── Level 1: fold the child ROOTS and prove a top proof over them ──
    let child_roots = vec![child_1.root, child_2.root];
    let parent_root = aggregate_root(&child_roots);
    // The parent proof: one trivial valid statement per child root, with the child roots as the
    // proof's "leaves" so its bound root == Poseidon2-fold(R1, R2). The parent is a real STARK; its
    // root binds the tree. (statements.len() == leaves.len() per prove_batch's contract.)
    let parent_stmts = vec![(1u64, 0u64); child_roots.len()];
    let parent_proof = prove_batch(&parent_stmts, &child_roots)?;
    debug_assert_eq!(parent_proof.root, parent_root);

    Ok(RecursionTree { child_roots, parent_root, child_proofs: vec![child_1, child_2], parent_proof })
}

/// Verify the whole tree end-to-end (the SPIKE verification path):
///   1. each child batch proof verifies under its own root,
///   2. parent_root == fold(child roots) (recomputed),
///   3. the parent proof verifies under the recomputed parent_root.
/// In the REAL tier, step 1 would be subsumed by step 3 (the parent proof would attest the children
/// in-circuit); here all three are checked explicitly — that explicitness IS the gap.
pub fn verify_recursion_tree(tree: &RecursionTree) -> Result<(), String> {
    for (i, c) in tree.child_proofs.iter().enumerate() {
        verify_batch(&c.proof_bytes, c.root, c.leaf_count).map_err(|e| format!("child {} failed: {}", i, e))?;
    }
    let recomputed = aggregate_root(&tree.child_roots);
    if recomputed != tree.parent_root {
        return Err(format!("parent_root {} != fold(child roots) {}", tree.parent_root, recomputed));
    }
    verify_batch(&tree.parent_proof.proof_bytes, recomputed, tree.child_roots.len())
        .map_err(|e| format!("parent failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::poseidon2_postcard_leaf_felt;

    fn batch_a() -> (Vec<(u64, u64)>, Vec<u32>) {
        // MEDIATOR + RESEARCHER (real agents), threshold 0.
        let stmts = vec![(2280u64, 0u64), (1675u64, 0u64)];
        let leaves = vec![
            poseidon2_postcard_leaf_felt("394b6ee4-62e7-4c66-8445-29107b097b4c", 0, 2280),
            poseidon2_postcard_leaf_felt("d244f6fc-35af-4131-b649-285bfac64b63", 0, 1675),
        ];
        (stmts, leaves)
    }
    fn batch_b() -> (Vec<(u64, u64)>, Vec<u32>) {
        // SKEPTIC + NEWCOMER (real agents), threshold 0.
        let stmts = vec![(834u64, 0u64), (60u64, 0u64)];
        let leaves = vec![
            poseidon2_postcard_leaf_felt("2538b7ed-acdb-4423-b5bf-a9e18069ec99", 0, 834),
            poseidon2_postcard_leaf_felt("d71b1e49-ce20-4e1c-b21f-3501dd852f6a", 0, 60),
        ];
        (stmts, leaves)
    }

    #[test]
    fn two_proof_recursion_tree_verifies_e2e() {
        let (sa, la) = batch_a();
        let (sb, lb) = batch_b();
        let tree = prove_recursion_tree((&sa, &la), (&sb, &lb)).expect("recursion tree proves");
        assert_eq!(tree.child_roots.len(), 2);
        assert_eq!(tree.parent_root, aggregate_root(&tree.child_roots), "parent binds the child roots");
        verify_recursion_tree(&tree).expect("the whole 2-level tree verifies e2e");
    }

    #[test]
    fn parent_proof_is_bound_to_its_children() {
        let (sa, la) = batch_a();
        let (sb, lb) = batch_b();
        let tree = prove_recursion_tree((&sa, &la), (&sb, &lb)).unwrap();
        // Tampering a child root must break the tree (the parent is bound to the real fold).
        let mut tampered = RecursionTree {
            child_roots: tree.child_roots.clone(),
            parent_root: tree.parent_root,
            child_proofs: tree.child_proofs,
            parent_proof: tree.parent_proof,
        };
        tampered.child_roots[0] ^= 1;
        assert!(verify_recursion_tree(&tampered).is_err(), "a tampered child root breaks the tree");
    }
}
