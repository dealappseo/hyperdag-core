// ENVELOPE tier — owner-controlled VARIABLE-field selective disclosure, sealed to ONE recipient.
// (ZKP_REVEAL_TIERS: postcard → ENVELOPE → letter → package.)
//
// POSTCARD reveals everything; LETTER hides one score behind a threshold. ENVELOPE is the
// user-controlled variable-reveal primitive: the owner holds a vector of fields, picks WHICH SUBSET
// to disclose, and seals the disclosure to ONE verified recipient. Commitment + validity are public;
// the disclosed field VALUES are sealed so only the recipient can read them; undisclosed fields stay
// hidden; the whole thing is bound to a scoped nullifier so it cannot be replayed or re-scoped.
//
// INVARIANTS HONORED (ZKP_ARCHITECTURE_INVARIANTS):
//   * Inv-1 ONE HASH: every commitment, nullifier, seal-key and keystream is Poseidon2 over BabyBear
//     via the canonical `babybear-leaf` (no second hash, no hand-rolled constants).
//   * Inv-2 SCOPED NULLIFIER: nullifier = Poseidon2(secret, recipient_id, DOMAIN_ENVELOPE). The
//     `secret` is the SAME identity secret as ownership/letter — NO second identity system. The scope
//     is a PARAMETER (recipient_id), never hardcoded.
//   * Inv-3 DOMAIN-PARAMETERIZED: `DOMAIN_ENVELOPE` is mixed into the nullifier + seal so the verifier
//     is domain-tagged, not envelope-specific — the same machinery re-instantiates for the health
//     vertical with a different domain.
//   * Inv-6 NAMESPACE: registered as `zkp_circuits.domain='envelope'`
//     (migrations/2026-06-10-zkp-circuits-envelope-domain.sql — STAGED, Sean applies).
//
// SOUNDNESS (the 5 negatives, enforced + tested below):
//   1. non-recipient open  → FAILS  (no pre-shared recipient_key ⇒ wrong seal-key ⇒ unmasked value
//                                     fails its commitment check)
//   2. tampered disclosed field → FAILS (commitment binding: a flipped sealed byte unmasks to a wrong
//                                     value whose commitment ≠ the committed leaf)
//   3. undisclosed field stays hidden  (only its salted Poseidon2 commitment is in the public root —
//                                     no sealed value exists for it; the commitment is one-way)
//   4. replay (reused nullifier) → REJECTED (one-time nullifier registry, mirrors prod
//                                     `nullifier_registry`)
//   5. wrong-scope → REJECTED (the envelope declares its recipient_id; a different scope's nullifier
//                                     differs and the binding check fails)
//
// WITNESS-LEVEL CAVEATS (documented, parallel to LETTER's in-AIR-Poseidon2 upgrade — NOT marketed as
// closed):
//   (a) Knowledge that the nullifier/commitments were derived from the SAME identity secret is
//       witness-level (the issuer computes honestly); proving it in-circuit needs a Poseidon2
//       permutation AIR (the recursion-tier upgrade). A malicious *owner* forging its own nullifier is
//       out of scope until then — this protects RECIPIENTS and replay, not against a dishonest issuer.
//   (b) "Sealed to recipient" uses a pre-shared symmetric `recipient_key`. Establishing it via a real
//       KEM/ECDH to the recipient's PUBLIC key (so a network eavesdropper can't read disclosed fields
//       and no pre-shared secret is needed) is the production upgrade. The PROTOCOL soundness above
//       (the 5 negatives) holds in the symmetric model; only eavesdropper-confidentiality awaits the KEM.

#![allow(dead_code)]

use std::collections::HashSet;

use crate::aggregate::{aggregate_root, membership_proof, verify_membership, MembershipProof};

/// Envelope domain tag (Inv-3 / Inv-6). A BabyBear-range constant ("ENV1").
pub const DOMAIN_ENVELOPE: u32 = 0x454e_5631;
/// Field values and salts live in the BabyBear range; we keep inputs < 2^31 so XOR masking stays
/// invertible AND the result is a valid field element for the commitment.
const FIELD_MAX: u32 = 1 << 31;

/// A single disclosable field. `label` names the field (e.g. a stable u32 id for "tier"/"region");
/// `value` is the secret content (< 2^31).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvelopeField {
    pub label: u32,
    pub value: u32,
}

/// The owner-selected disclosure for one field, sealed to the recipient.
#[derive(Debug, Clone, PartialEq)]
pub struct SealedDisclosure {
    pub index: usize,
    pub label: u32,
    /// Per-field salt — REVEALED so the recipient can re-bind the opened value to its commitment.
    pub salt: u32,
    /// `value XOR keystream` — only a holder of the recipient_key can recover the value.
    pub sealed_value: u32,
    /// Path proving this field's commitment is in the public envelope root.
    pub membership: MembershipProof,
}

/// The public envelope + the sealed selective disclosure. Everything here is safe to publish: the
/// root and nullifier leak nothing about field values; sealed_values need the recipient_key to open.
#[derive(Debug, Clone, PartialEq)]
pub struct Envelope {
    pub domain: u32,
    pub root: u32,
    pub field_count: usize,
    pub recipient_id: u32,
    pub nullifier: u32,
    pub disclosures: Vec<SealedDisclosure>,
}

#[inline]
fn p2() -> impl p3_symmetric::Permutation<[p3_baby_bear::BabyBear; babybear_leaf::WIDTH]> {
    babybear_leaf::poseidon2_16()
}

/// Per-field commitment = Poseidon2(value, salt, label). Binding (can't change value/label without
/// changing the commitment) + hiding (the salt makes it one-way over the small value space).
fn field_commit(
    p: &impl p3_symmetric::Permutation<[p3_baby_bear::BabyBear; babybear_leaf::WIDTH]>,
    f: &EnvelopeField,
    salt: u32,
) -> u32 {
    babybear_leaf::hash(p, &[f.value, salt, f.label])
}

/// Scoped nullifier (Inv-2): Poseidon2(secret, recipient_id, DOMAIN_ENVELOPE). One-time per recipient.
fn envelope_nullifier(
    p: &impl p3_symmetric::Permutation<[p3_baby_bear::BabyBear; babybear_leaf::WIDTH]>,
    secret: u32,
    recipient_id: u32,
) -> u32 {
    babybear_leaf::hash(p, &[secret, recipient_id, DOMAIN_ENVELOPE])
}

/// Recipient-scoped seal key = Poseidon2(recipient_key, recipient_id, DOMAIN_ENVELOPE). Both the owner
/// (sealing) and the recipient (opening) derive the SAME key from the pre-shared recipient_key; a party
/// without recipient_key cannot derive it (caveat (b): a KEM replaces the pre-shared key in production).
fn seal_key(
    p: &impl p3_symmetric::Permutation<[p3_baby_bear::BabyBear; babybear_leaf::WIDTH]>,
    recipient_key: u32,
    recipient_id: u32,
) -> u32 {
    babybear_leaf::hash(p, &[recipient_key, recipient_id, DOMAIN_ENVELOPE])
}

/// Per-field keystream = Poseidon2(seal_key, salt, index). A fresh mask per field (salt+index domain-
/// separate the streams) so identical values in different slots don't seal identically.
fn keystream(
    p: &impl p3_symmetric::Permutation<[p3_baby_bear::BabyBear; babybear_leaf::WIDTH]>,
    seal_key: u32,
    salt: u32,
    index: usize,
) -> u32 {
    // Mask < 2^31 so `value (< 2^31) XOR mask` stays < 2^31 and invertible.
    babybear_leaf::hash(p, &[seal_key, salt, index as u32]) % FIELD_MAX
}

/// Seal an envelope: commit every field, build the public root, derive the scoped nullifier, and seal
/// the owner-selected `disclose` subset to `recipient_id`/`recipient_key`. Undisclosed fields appear
/// only as commitments in the root.
pub fn seal_envelope(
    secret: u32,
    fields: &[EnvelopeField],
    salts: &[u32],
    recipient_id: u32,
    recipient_key: u32,
    disclose: &[usize],
) -> Result<Envelope, String> {
    if fields.is_empty() {
        return Err("envelope must have at least one field".into());
    }
    if fields.len() != salts.len() {
        return Err("fields/salts length mismatch".into());
    }
    for (i, f) in fields.iter().enumerate() {
        if f.value >= FIELD_MAX {
            return Err(format!("field {i} value out of range (>= 2^31)"));
        }
    }
    for &i in disclose {
        if i >= fields.len() {
            return Err(format!("disclose index {i} out of range"));
        }
    }

    let p = p2();
    let commits: Vec<u32> = fields
        .iter()
        .zip(salts.iter())
        .map(|(f, s)| field_commit(&p, f, *s))
        .collect();
    let root = aggregate_root(&commits);
    let nullifier = envelope_nullifier(&p, secret, recipient_id);
    let sk = seal_key(&p, recipient_key, recipient_id);

    let mut disclosures = Vec::with_capacity(disclose.len());
    for &i in disclose {
        let ks = keystream(&p, sk, salts[i], i);
        let sealed_value = fields[i].value ^ ks;
        disclosures.push(SealedDisclosure {
            index: i,
            label: fields[i].label,
            salt: salts[i],
            sealed_value,
            membership: membership_proof(&commits, i),
        });
    }

    Ok(Envelope {
        domain: DOMAIN_ENVELOPE,
        root,
        field_count: fields.len(),
        recipient_id,
        nullifier,
        disclosures,
    })
}

/// Open an envelope as the intended recipient. Returns the disclosed `(index, label, value)` triples.
/// FAILS if the caller is not the recipient (wrong id OR wrong key), if any disclosed field was
/// tampered, or if a membership path doesn't reproduce the root. Undisclosed fields are never returned.
pub fn open_envelope(
    env: &Envelope,
    my_recipient_id: u32,
    my_recipient_key: u32,
) -> Result<Vec<(usize, u32, u32)>, String> {
    if env.domain != DOMAIN_ENVELOPE {
        return Err("wrong domain".into());
    }
    // Scope binding: an envelope sealed to another recipient is not openable here (negatives 1 & 5).
    if env.recipient_id != my_recipient_id {
        return Err("envelope not addressed to this recipient (wrong scope)".into());
    }

    let p = p2();
    let sk = seal_key(&p, my_recipient_key, my_recipient_id);

    let mut out = Vec::with_capacity(env.disclosures.len());
    for d in &env.disclosures {
        // Unmask with the recipient-scoped keystream. A wrong key (non-recipient, negative 1) or a
        // tampered sealed_value (negative 2) yields a wrong value whose commitment will not match.
        let ks = keystream(&p, sk, d.salt, d.index);
        let value = d.sealed_value ^ ks;

        // Bind the opened value to the committed leaf (binding) …
        let recomputed = babybear_leaf::hash(&p, &[value, d.salt, d.label]);
        if recomputed != d.membership.leaf {
            return Err(format!(
                "disclosure {} failed commitment check (wrong recipient key or tampered field)",
                d.index
            ));
        }
        // … and prove that leaf is in the public root (no swapped-in foreign field).
        if !verify_membership(&d.membership) || d.membership.root != env.root {
            return Err(format!("disclosure {} membership does not reproduce the root", d.index));
        }
        out.push((d.index, d.label, value));
    }
    Ok(out)
}

/// Scope check (negative 5): assert the envelope is bound to `expected_recipient_id`.
pub fn verify_scope(env: &Envelope, expected_recipient_id: u32) -> Result<(), String> {
    if env.recipient_id != expected_recipient_id {
        return Err("wrong scope: envelope bound to a different recipient".into());
    }
    Ok(())
}

/// One-time nullifier acceptance (negative 4) — mirrors the prod `nullifier_registry` UNIQUE(context,
/// nullifier). Returns Err on replay.
pub fn accept_nullifier(seen: &mut HashSet<u32>, env: &Envelope) -> Result<(), String> {
    if !seen.insert(env.nullifier) {
        return Err("nullifier already used (replay rejected)".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // A 4-field envelope: e.g. [tier, region, repid, kyc_level]. Owner discloses {0,2} to the recipient.
    const SECRET: u32 = 0x0BAD_C0DE & (FIELD_MAX - 1);
    const RECIPIENT_ID: u32 = 7_777;
    const RECIPIENT_KEY: u32 = 0x5EA1_5EA1 & (FIELD_MAX - 1);

    fn sample() -> (Vec<EnvelopeField>, Vec<u32>) {
        let fields = vec![
            EnvelopeField { label: 100, value: 3 },          // tier
            EnvelopeField { label: 200, value: 42 },         // region (undisclosed)
            EnvelopeField { label: 300, value: 2280 },       // repid
            EnvelopeField { label: 400, value: 1 },          // kyc_level (undisclosed)
        ];
        let salts = vec![0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444];
        (fields, salts)
    }

    // ── POSITIVE GATE: a real envelope — recipient opens the selected fields + independently verifies ──
    #[test]
    fn envelope_recipient_opens_selected_fields_and_verifies() {
        let (fields, salts) = sample();
        let env = seal_envelope(SECRET, &fields, &salts, RECIPIENT_ID, RECIPIENT_KEY, &[0, 2]).unwrap();
        // Public surface is well-formed.
        assert_eq!(env.domain, DOMAIN_ENVELOPE);
        assert_eq!(env.field_count, 4);
        assert_eq!(env.disclosures.len(), 2);

        // Recipient opens — gets EXACTLY the disclosed fields, with correct values, membership-verified.
        let opened = open_envelope(&env, RECIPIENT_ID, RECIPIENT_KEY).unwrap();
        assert_eq!(opened, vec![(0, 100, 3), (2, 300, 2280)]);
        // Independent membership re-verification (the "+ independently verifies" half of the gate).
        for d in &env.disclosures {
            assert!(verify_membership(&d.membership) && d.membership.root == env.root);
        }
        // Nullifier accepts once.
        let mut seen = HashSet::new();
        assert!(accept_nullifier(&mut seen, &env).is_ok());
    }

    // ── NEGATIVE 1: non-recipient open → FAILS ──
    #[test]
    fn neg1_non_recipient_cannot_open() {
        let (fields, salts) = sample();
        let env = seal_envelope(SECRET, &fields, &salts, RECIPIENT_ID, RECIPIENT_KEY, &[0, 2]).unwrap();
        // Impostor knows the recipient_id but NOT the pre-shared recipient_key.
        let wrong_key = RECIPIENT_KEY ^ 0x55;
        assert!(
            open_envelope(&env, RECIPIENT_ID, wrong_key).is_err(),
            "a party without the recipient_key must not open the disclosed fields"
        );
    }

    // ── NEGATIVE 2: tampered disclosed field → FAILS ──
    #[test]
    fn neg2_tampered_disclosure_rejected() {
        let (fields, salts) = sample();
        let mut env = seal_envelope(SECRET, &fields, &salts, RECIPIENT_ID, RECIPIENT_KEY, &[0, 2]).unwrap();
        // Flip a bit of the first disclosed sealed value.
        env.disclosures[0].sealed_value ^= 1;
        assert!(
            open_envelope(&env, RECIPIENT_ID, RECIPIENT_KEY).is_err(),
            "a tampered sealed field must fail its commitment check"
        );
        // Tampering the revealed salt must also fail (it re-binds to a different commitment).
        let mut env2 = seal_envelope(SECRET, &fields, &salts, RECIPIENT_ID, RECIPIENT_KEY, &[0, 2]).unwrap();
        env2.disclosures[1].salt ^= 0xFF;
        assert!(open_envelope(&env2, RECIPIENT_ID, RECIPIENT_KEY).is_err(), "tampered salt rejected");
    }

    // ── NEGATIVE 3: undisclosed field stays hidden (no leak) ──
    #[test]
    fn neg3_undisclosed_field_stays_hidden() {
        let (fields, salts) = sample();
        let env = seal_envelope(SECRET, &fields, &salts, RECIPIENT_ID, RECIPIENT_KEY, &[0, 2]).unwrap();
        // The undisclosed indices (1, 3) are NOT in the disclosure set …
        let disclosed: Vec<usize> = env.disclosures.iter().map(|d| d.index).collect();
        assert_eq!(disclosed, vec![0, 2]);
        assert!(!disclosed.contains(&1) && !disclosed.contains(&3));
        // … even the legitimate recipient learns nothing about field 1/3 (open returns only 0 & 2) …
        let opened = open_envelope(&env, RECIPIENT_ID, RECIPIENT_KEY).unwrap();
        assert!(opened.iter().all(|(i, _, _)| *i == 0 || *i == 2));
        // … and field 1's value (42) is not recoverable by brute force against the public root without
        // its secret salt (the commitment is one-way; only the committer's salt opens it).
        let p = p2();
        let target_leaf = field_commit(&p, &fields[1], salts[1]);
        let mut leaked = false;
        for guess in 0..=10_000u32 {
            if babybear_leaf::hash(&p, &[guess, /*wrong salt*/ 0, fields[1].label]) == target_leaf {
                leaked = true;
                break;
            }
        }
        assert!(!leaked, "undisclosed value must not be brute-forceable without the salt");
    }

    // ── NEGATIVE 4: replay (reused nullifier) → REJECTED ──
    #[test]
    fn neg4_replay_rejected() {
        let (fields, salts) = sample();
        let env = seal_envelope(SECRET, &fields, &salts, RECIPIENT_ID, RECIPIENT_KEY, &[0, 2]).unwrap();
        let mut seen = HashSet::new();
        assert!(accept_nullifier(&mut seen, &env).is_ok(), "first use accepted");
        assert!(accept_nullifier(&mut seen, &env).is_err(), "second use (replay) rejected");
    }

    // ── NEGATIVE 5: wrong-scope → REJECTED ──
    #[test]
    fn neg5_wrong_scope_rejected() {
        let (fields, salts) = sample();
        let env = seal_envelope(SECRET, &fields, &salts, RECIPIENT_ID, RECIPIENT_KEY, &[0, 2]).unwrap();
        // Presenting recipient A's envelope under a different scope (B) is rejected …
        let other_id = RECIPIENT_ID + 1;
        assert!(verify_scope(&env, other_id).is_err(), "scope mismatch rejected");
        assert!(open_envelope(&env, other_id, RECIPIENT_KEY).is_err(), "open under wrong scope rejected");
        // … and the scoped nullifier itself differs across recipients (Inv-2), so A's envelope cannot
        // masquerade as a fresh envelope to B.
        let env_b = seal_envelope(SECRET, &fields, &salts, other_id, RECIPIENT_KEY, &[0, 2]).unwrap();
        assert_ne!(env.nullifier, env_b.nullifier, "different recipient scope ⇒ different nullifier");
    }
}
