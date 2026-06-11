// PACKAGE tier — SCAFFOLD + interfaces only (Phase 3). ZKP_REVEAL_TIERS: postcard → envelope →
// letter → PACKAGE. A PACKAGE aggregates N member proofs (envelopes/letters) into ONE epoch root,
// anchored once per epoch (gas discipline), with the reveal GATED by staked authority.
//
// ⚠️ SCOPE (per CC_REBASE_ENVELOPE_PACKAGE Phase 3 — "do NOT ship untested aggregation circuit at
// tail"): this file ships only the parts that are REAL and tested today, plus typed interfaces for the
// parts that are deferred. Specifically:
//   * REAL + tested: `package_epoch_root` reuses the tested `aggregate::aggregate_root` (Poseidon2
//     merkle over member leaves) — the same primitive `aggregate.rs` golden-KATs. One root per epoch.
//   * REAL + tested: the staked-reveal GATE (`reveal_authority`, `gate_reveal`) — pure D-053 math.
//   * DEFERRED (interface only, NOT shipped): the recursive Plonky3 FOLD that proves, in-circuit, that
//     each member proof is individually valid before it enters the root. Today the root is a merkle
//     commitment to member LEAVES (binding, not a recursion proof). The runnable 2-level recursion
//     SPIKE lives in `recursion_spike.rs` (explicitly NOT production). Build-plan in BUILD-PLAN below.
//
// INVARIANTS: Inv-1 (Poseidon2 root via babybear-leaf), Inv-5 (one Plonky3 pin governs the future
// recursion circuit), Inv-6 (domain='package'). Stake tables are WIRED, not built (R10): the gate
// reads `repid_agent_stakes` / `stake_authority_snapshots` via the `StakeSource` trait — this file
// does not create or own that data.
//
// GOODHART FIX (the load-bearing design choice): reveal authority is RE-DERIVED AT THE REQUESTER from
// LIVE (repid, stake) at request time — it is NEVER read from a stored `authority` column. A stored
// authority is a metric that becomes a target (game the snapshot once, keep the power); recomputing
// `min(R, 100·√S)` per request means the gate always reflects current earned reputation + current
// stake, so there is nothing stale to game.

#![allow(dead_code)]

use crate::aggregate::aggregate_root;

/// Domain tag (Inv-3/6) for the package tier.
pub const DOMAIN_PACKAGE: u32 = 0x504b_4731; // "PKG1"

/// D-053 authority β: A = min(R, β·√S_usd), β = 100. Canonical (supersedes min(R,10S) and √S·log10 R).
pub const AUTHORITY_BETA: u64 = 100;

/// A member of a package — the public leaf of one envelope/letter proof (its root or commitment).
/// PACKAGE binds to these leaves; proving each member's *internal* validity in-circuit is the deferred
/// recursion fold (BUILD-PLAN below), not this scaffold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackageMember {
    /// The member proof's public leaf (envelope root / letter commitment) as a BabyBear felt.
    pub leaf: u32,
    /// Member kind for the manifest (audit only; does not affect the root).
    pub kind: MemberKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberKind {
    Envelope,
    Letter,
}

/// The public package: one epoch root over N member leaves, anchored once per epoch.
#[derive(Debug, Clone, PartialEq)]
pub struct Package {
    pub domain: u32,
    pub epoch: u64,
    pub epoch_root: u32,
    pub member_count: usize,
}

/// Compute the epoch root over the member leaves. REAL — reuses the tested Poseidon2 merkle
/// `aggregate_root` (Inv-1). Deterministic + order-sensitive (the aggregate.rs KATs cover the root fn).
pub fn package_epoch_root(members: &[PackageMember]) -> u32 {
    let leaves: Vec<u32> = members.iter().map(|m| m.leaf).collect();
    aggregate_root(&leaves)
}

/// Assemble a package for an epoch (one root, gas-amortized anchor — anchoring itself is the
/// epoch-anchor path, Sean-gated, not here).
pub fn assemble_package(epoch: u64, members: &[PackageMember]) -> Result<Package, String> {
    if members.is_empty() {
        return Err("package needs at least one member".into());
    }
    Ok(Package {
        domain: DOMAIN_PACKAGE,
        epoch,
        epoch_root: package_epoch_root(members),
        member_count: members.len(),
    })
}

// ───────────────────────────── STAKED REVEAL GATE (REAL, tested) ─────────────────────────────

/// Live reputation + stake for a requester, read at request time. The WIRING reads these from the
/// dormant `repid_agent_stakes` / `stake_authority_snapshots` (R10 — wire, don't build); the scaffold
/// only depends on the trait so the data source is swappable and never stored as a derived authority.
pub trait StakeSource {
    /// Current earned RepID (R) for the requester — the live value, not a snapshot.
    fn current_repid(&self, requester_id: &str) -> Option<u64>;
    /// Current backing stake in whole USD (S_usd) for the requester — the live value.
    fn current_stake_usd(&self, requester_id: &str) -> Option<u64>;
}

/// RE-DERIVE the reveal authority at the requester (Goodhart fix): A = min(R, 100·√S_usd), integer
/// isqrt, computed fresh from live (R, S). NEVER read a stored authority. Returns None if the requester
/// has no live repid/stake (cannot reveal).
pub fn reveal_authority<S: StakeSource>(src: &S, requester_id: &str) -> Option<u64> {
    let r = src.current_repid(requester_id)?;
    let s = src.current_stake_usd(requester_id)?;
    let sqrt_s = s.isqrt();
    let capital_bound = AUTHORITY_BETA.saturating_mul(sqrt_s);
    Some(r.min(capital_bound))
}

/// Gate a package reveal: the requester may reveal only if their RE-DERIVED authority meets the
/// package's required authority. Pure check over live-derived values.
pub fn gate_reveal<S: StakeSource>(
    src: &S,
    requester_id: &str,
    required_authority: u64,
) -> Result<u64, String> {
    let a = reveal_authority(src, requester_id)
        .ok_or_else(|| "requester has no live repid/stake — reveal denied".to_string())?;
    if a < required_authority {
        return Err(format!(
            "reveal denied: re-derived authority {a} < required {required_authority} (earn RepID or add stake)"
        ));
    }
    Ok(a)
}

// ──────────────────────────────────────── BUILD-PLAN ────────────────────────────────────────────
// The DEFERRED recursion fold (do NOT ship untested at tail). Sequenced:
//  1. Land the BabyBear leaf prover end-to-end (Track A: real plonky3 range-check proofs draining).
//  2. Promote `recursion_spike.rs`'s 2-level tree to an N-ary fold AIR that verifies each member
//     proof in-circuit, pinned to Plonky3 27d59f73 (Inv-5). Golden-KAT the fold root like aggregate.rs.
//  3. Replace `package_epoch_root` (merkle-of-leaves) with the recursion root ONLY once the fold AIR
//     has soundness fixtures (forge-a-member, swap-a-member, replay) all REJECTED — same bar as
//     envelope/letter. Until then PACKAGE binds member leaves (commitment) but does not PROVE their
//     internal validity in-circuit; the manifest documents this honestly.
//  4. Epoch anchor: one EAS attestation of `epoch_root` per epoch (gas discipline) — the epoch-anchor
//     path (Sean-gated key), not this module.

#[cfg(test)]
mod tests {
    use super::*;

    fn members() -> Vec<PackageMember> {
        vec![
            PackageMember { leaf: 0x1111_1111, kind: MemberKind::Envelope },
            PackageMember { leaf: 0x2222_2222, kind: MemberKind::Letter },
            PackageMember { leaf: 0x3333_3333, kind: MemberKind::Envelope },
        ]
    }

    #[test]
    fn epoch_root_is_deterministic_and_order_sensitive() {
        let m = members();
        let r1 = package_epoch_root(&m);
        let r2 = package_epoch_root(&m);
        assert_eq!(r1, r2, "same members → same epoch root (deterministic)");
        let mut swapped = m.clone();
        swapped.swap(0, 2);
        assert_ne!(package_epoch_root(&swapped), r1, "member order changes the root (binding)");
    }

    #[test]
    fn assemble_rejects_empty_and_stamps_domain() {
        assert!(assemble_package(7, &[]).is_err());
        let pkg = assemble_package(7, &members()).unwrap();
        assert_eq!(pkg.domain, DOMAIN_PACKAGE);
        assert_eq!(pkg.epoch, 7);
        assert_eq!(pkg.member_count, 3);
    }

    // Fake live source for the gate tests — models reading repid_agent_stakes / stake_authority_snapshots.
    struct FakeStake {
        repid: Option<u64>,
        stake_usd: Option<u64>,
    }
    impl StakeSource for FakeStake {
        fn current_repid(&self, _r: &str) -> Option<u64> {
            self.repid
        }
        fn current_stake_usd(&self, _r: &str) -> Option<u64> {
            self.stake_usd
        }
    }

    #[test]
    fn authority_is_min_repid_and_100_sqrt_stake() {
        // Capital-bound binds: R high, stake small → A = 100·√S.
        let s = FakeStake { repid: Some(9000), stake_usd: Some(100) }; // 100·10 = 1000
        assert_eq!(reveal_authority(&s, "x"), Some(1000), "capital-bound: min(9000, 1000)");
        // RepID binds: stake huge, R small → A = R (plutocrat can't exceed earned reputation).
        let s2 = FakeStake { repid: Some(500), stake_usd: Some(1_000_000) }; // 100·1000 = 100_000
        assert_eq!(reveal_authority(&s2, "x"), Some(500), "repid-bound: min(500, 100000)");
        // No live data → no authority.
        let s3 = FakeStake { repid: None, stake_usd: Some(100) };
        assert_eq!(reveal_authority(&s3, "x"), None);
    }

    #[test]
    fn gate_allows_sufficient_and_denies_insufficient() {
        let s = FakeStake { repid: Some(2280), stake_usd: Some(2500) }; // 100·50 = 5000 → A = min(2280,5000)=2280
        assert_eq!(gate_reveal(&s, "x", 1000).unwrap(), 2280, "sufficient authority reveals");
        assert!(gate_reveal(&s, "x", 3000).is_err(), "insufficient authority denied");
        // Goodhart: there is no stored authority to pass in — the gate ONLY accepts a live source.
        let broke = FakeStake { repid: None, stake_usd: None };
        assert!(gate_reveal(&broke, "x", 1).is_err(), "no live repid/stake → denied");
    }
}
