// P4 — Epoch reconciliation (ZKP aggregation-depth sprint, 2026-06-10).
//
// Two epoch mechanisms exist and were diverging:
//   * CC (0.3.0, feat/cc-2026-06-09-epoch-binding): epoch as a PUBLIC INPUT inside the STARK
//     statement {agent_id, threshold, repid_score, epoch}, observed into Fiat-Shamir → a tampered
//     epoch fails the proof; epoch sourced from chain block height; freshness checked verifier-side.
//     This is the PROOF-PLANE: each proof is self-describing + tamper-evident, verifiable offline.
//   * XC (zkp-epoch-anchor.ts): epoch = UTC-day window from `created_at`; one keccak256 Merkle tree
//     per epoch → one root → one EAS attestation; replay-across-epoch fails because the leaf is not
//     in the other epoch's root. This is the ANCHOR-PLANE: which epoch's tree a proof belongs to.
//
// THE RECONCILIATION (one coherent 0.3.0 Sean co-signs once — see the decision doc):
//   1. ONE authoritative epoch integer, CHAIN-DERIVED: `epoch_of(block_height, EPOCH_BLOCKS)`.
//      DEFAULT_EPOCH_BLOCKS = 43200 (~1 day at Base Sepolia's ~2s blocks) so the chain epoch lands
//      on the same cadence as XC's UTC-day. created_at becomes a human LABEL, never the source of
//      truth (server clocks are mutable; block height is not).
//   2. The PROOF-PLANE binds it (CC): epoch is a public input → tamper-evident, offline-verifiable.
//   3. The ANCHOR-PLANE indexes it (XC): the per-epoch aggregation tree is built from the leaves
//      whose proofs are BOUND to that epoch — and folded with Poseidon2 (the B-2 leaf), resolving
//      XC's flagged Invariant-1 gap (its keccak256 layer was not aggregation-ready).
//   4. THE TIE (what unifies the planes): a proof bound to epoch E can only be selected into epoch
//      E's root (`per_epoch_root` filters by the bound epoch). So replay-across-epoch fails on BOTH
//      planes at once — the circuit rejects a wrong epoch (CC) AND the proof is absent from any other
//      epoch's anchored root (XC). One freshness rule: `epoch_fresh(proof_epoch, current_epoch,
//      window)`, current epoch chain-derived, never agent-supplied.
//
// SCOPE: this module is the EXECUTABLE SPEC of the reconciliation (derivation + per-epoch selection
// + freshness), with tests. The leaf stays epoch-free (frozen f64835f) — the tie is at SELECTION,
// not in the leaf; putting epoch IN the leaf is a documented future leaf-scheme bump (decision doc
// Option B), not taken now (it would break the frozen golden KAT + corpus for no present need).

#![allow(dead_code)]

use crate::aggregate::aggregate_root;

/// ~1 day at Base Sepolia ~2s blocks → aligns the chain epoch with XC's UTC-day cadence.
pub const DEFAULT_EPOCH_BLOCKS: u64 = 43_200;

/// The ONE authoritative epoch: floor(block_height / epoch_blocks). Chain-derived, tamper-resistant,
/// never agent-supplied. Both planes (proof public-input + anchor tree index) reduce to this integer.
pub fn epoch_of(block_height: u64, epoch_blocks: u64) -> u64 {
    let eb = if epoch_blocks == 0 { DEFAULT_EPOCH_BLOCKS } else { epoch_blocks };
    block_height / eb
}

/// Freshness — the single rule across both planes. A proof minted at `proof_epoch` is fresh iff it
/// is within `window` epochs of the current authoritative epoch, and not future-dated. Separate
/// from cryptographic verification: a stale proof still verifies cryptographically but is rejected
/// as STALE here. `current_epoch` MUST be chain-derived (never from the proof / the agent).
pub fn epoch_fresh(proof_epoch: u64, current_epoch: u64, window: u64) -> bool {
    if proof_epoch > current_epoch {
        return false; // future-dated → reject (clock/forgery)
    }
    current_epoch - proof_epoch <= window
}

/// THE TIE: build epoch `target_epoch`'s aggregation root from ONLY the leaves whose proofs are
/// bound to `target_epoch`. A leaf bound to any other epoch is excluded — so a proof cannot be
/// replayed into a foreign epoch's anchored root. `entries` = (proof's bound epoch, postcard leaf).
/// Folded with the same Poseidon2 fold as `aggregate_root` (aggregation-ready, Invariant 1).
pub fn per_epoch_root(entries: &[(u64, u32)], target_epoch: u64) -> u32 {
    let selected: Vec<u32> = entries
        .iter()
        .filter(|(e, _)| *e == target_epoch)
        .map(|(_, leaf)| *leaf)
        .collect();
    aggregate_root(&selected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::poseidon2_postcard_leaf_felt;

    #[test]
    fn one_chain_derived_epoch_integer() {
        // Both planes reduce to this integer; default ~1-day cadence.
        assert_eq!(epoch_of(0, DEFAULT_EPOCH_BLOCKS), 0);
        assert_eq!(epoch_of(43_199, DEFAULT_EPOCH_BLOCKS), 0);
        assert_eq!(epoch_of(43_200, DEFAULT_EPOCH_BLOCKS), 1);
        assert_eq!(epoch_of(86_400, DEFAULT_EPOCH_BLOCKS), 2);
        // A real Base Sepolia height (from STATE_OF_THE_SYSTEM on-chain anchors) maps deterministically.
        assert_eq!(epoch_of(42_467_884, DEFAULT_EPOCH_BLOCKS), 42_467_884 / 43_200);
        // epoch_blocks=0 falls back to the default (never divide-by-zero).
        assert_eq!(epoch_of(43_200, 0), 1);
    }

    #[test]
    fn freshness_accepts_recent_rejects_stale_and_future() {
        let cur = 100;
        assert!(epoch_fresh(100, cur, 3), "current epoch is fresh");
        assert!(epoch_fresh(98, cur, 3), "within window is fresh");
        assert!(epoch_fresh(97, cur, 3), "window boundary is fresh");
        assert!(!epoch_fresh(96, cur, 3), "beyond window is STALE");
        assert!(!epoch_fresh(101, cur, 3), "future-dated is rejected");
    }

    #[test]
    fn replay_across_epoch_fails_on_the_anchor_plane() {
        // Three real leaves, each a proof bound to a specific epoch.
        let a = poseidon2_postcard_leaf_felt("394b6ee4-62e7-4c66-8445-29107b097b4c", 0, 2280); // MEDIATOR
        let b = poseidon2_postcard_leaf_felt("2538b7ed-acdb-4423-b5bf-a9e18069ec99", 0, 834);  // SKEPTIC
        let c = poseidon2_postcard_leaf_felt("d71b1e49-ce20-4e1c-b21f-3501dd852f6a", 0, 60);   // NEWCOMER

        // a,b bound to epoch 10; c bound to epoch 11.
        let entries = vec![(10u64, a), (10u64, b), (11u64, c)];

        let root10 = per_epoch_root(&entries, 10);
        let root11 = per_epoch_root(&entries, 11);

        // Epoch 10's root folds exactly {a,b}; epoch 11's root folds exactly {c}.
        assert_eq!(root10, aggregate_root(&[a, b]), "epoch 10 root == fold of its members");
        assert_eq!(root11, aggregate_root(&[c]), "epoch 11 root == fold of its member");
        assert_ne!(root10, root11, "different epochs → different anchored roots");

        // THE TIE: c (bound to epoch 11) is NOT a member of epoch 10's root — it cannot be replayed
        // into epoch 10's anchored tree.
        let members_of_10: Vec<u32> = entries.iter().filter(|(e, _)| *e == 10).map(|(_, l)| *l).collect();
        assert!(!members_of_10.contains(&c), "a foreign-epoch leaf is excluded from the epoch root");

        // An empty epoch folds to 0 (no proofs that epoch).
        assert_eq!(per_epoch_root(&entries, 99), 0, "empty epoch → zero root");
    }

    #[test]
    fn proof_plane_and_anchor_plane_agree_on_the_same_integer() {
        // The proof's public-input epoch (CC) and the anchor tree's index (XC) are the SAME integer,
        // derived once from chain height. Demonstrate: a proof minted at height H is bound to
        // epoch_of(H), and that is exactly the tree it can be a member of.
        let height = 5_000_000u64;
        let e = epoch_of(height, DEFAULT_EPOCH_BLOCKS);
        let leaf = poseidon2_postcard_leaf_felt("394b6ee4-62e7-4c66-8445-29107b097b4c", 0, 2280);
        let entries = vec![(e, leaf)];
        assert_eq!(per_epoch_root(&entries, e), leaf, "the proof anchors in exactly its bound epoch");
        assert_eq!(per_epoch_root(&entries, e + 1), 0, "and in no other");
    }
}
