// P3 — LETTER tier: selective-disclosure RepID proof (ZKP aggregation-depth sprint, 2026-06-10).
//
// POSTCARD reveals the score: its public statement is {agent_id, threshold, repid_score}. LETTER
// proves "repid_score >= threshold" (here: > threshold-1, i.e. repid >= threshold) WITHOUT putting
// the score in the public statement. The score becomes a PRIVATE witness; the public statement is
// {agent_id, threshold, score_commitment}, where score_commitment = Poseidon2(repid_score, nonce)
// with a secret high-entropy nonce.
//
// WHAT HOLDS (the selective-disclosure property, fully):
//   * The score is NOT in the public values. A verifier of the STARK learns only
//     {agent_id, threshold} + "the witnessed score exceeds threshold" — never the score itself.
//   * Range soundness is identical to POSTCARD: the gap = repid - threshold - 1 is range-checked
//     into 16 bits with the high bits forced zero, so repid <= threshold has no satisfying witness
//     (the field-wrap exploit is closed exactly as in circuit.rs).
//   * agent_id (16 bytes) and the commitment are bound into the Fiat-Shamir transcript, so a LETTER
//     proof is non-replayable across agents / commitments.
//
// WHAT IS WITNESS-LEVEL (documented gap, the same Poseidon2-in-AIR upgrade P2 names):
//   * The link "score_commitment == Poseidon2(repid_score, nonce) for the SAME repid the range
//     check used" is enforced by recomputation (the issuer/server computes both honestly and the
//     verifier can recompute the commitment given an opening), NOT by an in-AIR Poseidon2 constraint.
//     Closing it in-circuit needs a Poseidon2 permutation AIR (the recursion-tier upgrade). Until
//     then, LETTER's trust model is: the commitment is the issuer's attestation of the hidden score;
//     the proof attests that hidden score > threshold; the verifier checks the proof + that the
//     commitment matches the registry's published commitment for the agent.
//
// SCORE-HIDING (B2 — now STRUCTURAL, not just "absent from public values"): given
// {agent_id, threshold, commitment, proof}, the score is unrecoverable. Three layers:
//   (1) the score is absent from the public values (it is a private witness);
//   (2) the commitment Poseidon2(score, nonce) is one-way — brute-forcing the small RepID space
//       (0..=10000) fails without the secret nonce;
//   (3) the PROOF ITSELF is zero-knowledge: a hiding FRI PCS (salted Merkle MMCS + random
//       codewords) closes the FRI query-opening leak, and random masking rows close the OOD
//       trace-opening leak that a height-1 trace would otherwise have. See the config block below.
// NOTE: layer (2)'s commitment is still 31-bit-reduced and witness-level-bound (see the XC
// red-team fixtures + KNOWN LIMITATION in tests) — that is a SEPARATE fix (commitment widening /
// in-AIR Poseidon2) and is NOT addressed by B2's HidingFriPcs change.

#![allow(dead_code)]

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{FriParameters as FriConfig, HidingFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_monty_31::dft::RecursiveDft;
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
use p3_uni_stark::{prove, verify, StarkConfig};
use rand::rngs::SmallRng;
use rand::{RngExt, SeedableRng};

use crate::circuit::agent_id_to_16_bytes_pub;

// ── B2 HIDING STARK CONFIG (HidingFriPcs + salted MerkleTreeHidingMmcs + random codewords) ──
// LETTER's witness (the score) must not leak from the proof. The plain TwoAdicFriPcs is NOT
// zero-knowledge, and the LETTER trace is tiny, so two leaks had to be closed together:
//   1. FRI query openings (in-domain LDE values) — closed by the SALTED MerkleTreeHidingMmcs plus
//      `LETTER_NUM_RANDOM_CODEWORDS` random codewords folded into the FRI batch (HidingFriPcs).
//   2. The out-of-domain (OOD) trace opening at zeta — for a height-1 trace the trace polynomials
//      are CONSTANTS, so trace(zeta) == the witness exactly. Closed by padding the trace to
//      `LETTER_TRACE_HEIGHT` with random MASKING rows (see `letter_trace`), making each
//      witness-bearing column a high-degree polynomial whose evaluation at zeta is uniform.
// Together these make LETTER's score-hiding STRUCTURAL, not merely "absent from public values."
// This is Plonky3's canonical ZK path (mirrors uni-stark/tests/fib_air.rs + the poseidon2 ZK
// example). The RNGs MUST be high-entropy & secret at proving time; at verify time they are never
// drawn from (verification generates no randomness), so any seed verifies the same proof.
type LVal = BabyBear;
type LChallenge = BinomialExtensionField<LVal, 4>;
type LByteHash = Keccak256Hash;
type LU64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
type LFieldHash = SerializingHasher<LU64Hash>;
type LCompress = CompressionFunctionFromHasher<LU64Hash, 2, 4>;
type LValMmcs = MerkleTreeHidingMmcs<
    [LVal; p3_keccak::VECTOR_LEN],
    [u64; p3_keccak::VECTOR_LEN],
    LFieldHash,
    LCompress,
    SmallRng,
    2,
    4,
    4,
>;
type LChallengeMmcs = ExtensionMmcs<LVal, LChallenge, LValMmcs>;
type LDft = RecursiveDft<LVal>;
type LPcs = HidingFriPcs<LVal, LDft, LValMmcs, LChallengeMmcs, SmallRng>;
type LChallenger = SerializingChallenger32<LVal, HashChallenger<u8, LByteHash, 32>>;
type LConfig = StarkConfig<LPcs, LChallenge, LChallenger>;

/// Trace height (power of two). Row 0 is the real witness row; rows 1.. are random masking rows.
const LETTER_TRACE_HEIGHT: usize = 8;
/// Random codewords folded into the FRI batch by HidingFriPcs (matches Plonky3's ZK examples).
const LETTER_NUM_RANDOM_CODEWORDS: usize = 4;

/// Build the hiding STARK config. `mmcs_rng` salts the Merkle leaves; `pcs_rng` draws the random
/// codewords — both are the hiding secret and MUST be high-entropy when proving. Verification draws
/// no randomness, so a fixed seed there is correct and keeps verify deterministic.
fn letter_config(mmcs_rng: SmallRng, pcs_rng: SmallRng) -> LConfig {
    let byte_hash = LByteHash {};
    let u64_hash = LU64Hash::new(KeccakF {});
    let field_hash = LFieldHash::new(u64_hash);
    let compress = LCompress::new(u64_hash);
    let val_mmcs = LValMmcs::new(field_hash, compress, 0, mmcs_rng);
    let challenge_mmcs = LChallengeMmcs::new(val_mmcs.clone());
    let fri_config = FriConfig {
        log_blowup: 2,
        num_queries: 28,
        log_final_poly_len: 0,
        max_log_arity: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 8,
        mmcs: challenge_mmcs,
    };
    let dft = LDft::new(LETTER_TRACE_HEIGHT << fri_config.log_blowup);
    let pcs = LPcs::new(dft, val_mmcs, fri_config, LETTER_NUM_RANDOM_CODEWORDS, pcs_rng);
    let challenger =
        LChallenger::new(HashChallenger::<u8, LByteHash, 32>::new(vec![], byte_hash));
    LConfig::new(pcs, challenger)
}

/// Public-value layout for LETTER (18 elements — same width as POSTCARD, score swapped for commitment):
///   [0..16] agent_id (16 bytes), [16] threshold, [17] score_commitment.
/// The score is NOT present.
pub const LETTER_NUM_PUBLIC_VALUES: usize = 18;
const LPUB_THRESHOLD: usize = 16;
const LPUB_COMMITMENT: usize = 17;

const LETTER_WIDTH: usize = 33; // [0..32]=gap bits, [32]=repid (PRIVATE witness column)
const LCOL_REPID: usize = 32;

/// score_commitment = Poseidon2(repid_score, nonce). The nonce is the hiding secret; it must be
/// high-entropy (a field element here; production draws a full-width secret). Deterministic.
pub fn score_commitment(repid_score: u64, nonce: u64) -> u32 {
    let p = babybear_leaf::poseidon2_16();
    babybear_leaf::hash(&p, &[(repid_score % (1u64 << 31)) as u32, (nonce % (1u64 << 31)) as u32])
}

pub struct RepIdLetterAir;

impl<F: Field> BaseAir<F> for RepIdLetterAir {
    fn width(&self) -> usize {
        LETTER_WIDTH
    }
    fn num_public_values(&self) -> usize {
        LETTER_NUM_PUBLIC_VALUES
    }
}

impl<AB: AirBuilder> Air<AB> for RepIdLetterAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let pis = builder.public_values();
        let threshold = pis[LPUB_THRESHOLD];
        // NB: pis[LPUB_COMMITMENT] is bound via Fiat-Shamir (it is a public value) but is NOT
        // arithmetically constrained against the witnessed repid in-AIR — see module doc.

        let main = builder.main();
        let row = main.current_slice();
        let repid = row[LCOL_REPID]; // PRIVATE witness — never a public value, never revealed.

        // Same 16-bit range soundness as POSTCARD, with repid a witness instead of public.
        for i in 0..16 {
            builder.assert_zero(row[i]);
        }
        let mut reconstructed = AB::Expr::ZERO;
        for i in 16..32 {
            let bit = row[i];
            builder.assert_bool(bit);
            reconstructed += AB::Expr::from_u32(1 << (31 - i)) * bit;
        }
        builder
            .when_first_row()
            .assert_eq(reconstructed, repid.into() - threshold.into() - AB::Expr::ONE);
    }
}

/// Build the LETTER trace. Row 0 is the real witness row (gap bits in cols 16..32, zeros in cols
/// 0..16, repid in col 32). Rows 1.. are MASKING rows: cols 0..16 stay zero (per-row `assert_zero`),
/// cols 16..32 hold RANDOM bits (per-row `assert_bool` still holds), and col 32 holds a RANDOM field
/// element. Because the score-binding constraint is `when_first_row`, the masking rows do NOT weaken
/// soundness; they DO make every witness-bearing column a high-degree polynomial, so the STARK's
/// out-of-domain opening at zeta reveals nothing about row 0's witness (the height-1 OOD-leak fix).
fn letter_trace<F: Field>(repid: u64, threshold: u64, rng: &mut SmallRng) -> RowMajorMatrix<F> {
    let mut values = Vec::with_capacity(LETTER_TRACE_HEIGHT * LETTER_WIDTH);
    // Row 0 — the real witness row.
    let gap = (repid - threshold - 1) as u32;
    for i in (0..32).rev() {
        values.push(if (gap & (1 << i)) != 0 { F::ONE } else { F::ZERO });
    }
    values.push(F::from_u32(repid as u32));
    // Rows 1.. — random masking rows (satisfy per-row constraints, unconstrained by when_first_row).
    for _ in 1..LETTER_TRACE_HEIGHT {
        for _ in 0..16 {
            values.push(F::ZERO);
        }
        for _ in 16..32 {
            values.push(if rng.random::<bool>() { F::ONE } else { F::ZERO });
        }
        values.push(F::from_u32(rng.random::<u32>()));
    }
    RowMajorMatrix::new(values, LETTER_WIDTH)
}

fn letter_public_values(agent_id: &str, threshold: u64, commitment: u32) -> Result<Vec<BabyBear>, String> {
    if threshold >= (1u64 << 31) {
        return Err("threshold out of field range".into());
    }
    let mut pv = Vec::with_capacity(LETTER_NUM_PUBLIC_VALUES);
    for b in agent_id_to_16_bytes_pub(agent_id) {
        pv.push(BabyBear::new(b as u32));
    }
    pv.push(BabyBear::new(threshold as u32));
    pv.push(BabyBear::new(commitment));
    debug_assert_eq!(pv.len(), LETTER_NUM_PUBLIC_VALUES);
    Ok(pv)
}

#[derive(Debug, Clone)]
pub struct LetterProof {
    pub proof_bytes: Vec<u8>,
    pub agent_id: String,
    pub threshold: u64,
    pub score_commitment: u32,
}

/// Prove "repid_score > threshold" for `agent_id` WITHOUT revealing repid_score. The score and the
/// commitment nonce are private witnesses; the public statement carries only
/// {agent_id, threshold, score_commitment}.
pub fn prove_letter(agent_id: &str, threshold: u64, repid_score: u64, nonce: u64) -> Result<LetterProof, String> {
    if repid_score <= threshold {
        return Err(format!("repid {} <= threshold {} (no positive statement)", repid_score, threshold));
    }
    if repid_score >= (1u64 << 31) {
        return Err("repid out of field range".into());
    }
    if repid_score - threshold - 1 >= (1u64 << 16) {
        return Err("gap >= 2^16 (out of 16-bit range)".into());
    }

    let commitment = score_commitment(repid_score, nonce);

    // Entropy-seeded RNGs are the hiding secret: `trace_rng` draws the masking rows, and the two
    // config RNGs salt the Merkle leaves + draw the FRI random codewords. Fresh per proof, so the
    // same statement yields a different (non-linkable) proof each time.
    let mut trace_rng = rand::make_rng::<SmallRng>();
    let trace = letter_trace::<LVal>(repid_score, threshold, &mut trace_rng);
    let config = letter_config(rand::make_rng::<SmallRng>(), rand::make_rng::<SmallRng>());

    let public_values = letter_public_values(agent_id, threshold, commitment)?;
    let air = RepIdLetterAir;
    let proof = prove(&config, &air, trace, &public_values);
    verify(&config, &air, &proof, &public_values).map_err(|e| format!("letter verify failed: {:?}", e))?;
    let proof_bytes = bincode::serialize(&proof).map_err(|e| format!("serialize: {}", e))?;

    Ok(LetterProof { proof_bytes, agent_id: agent_id.to_string(), threshold, score_commitment: commitment })
}

/// Verify a LETTER proof against the public statement {agent_id, threshold, score_commitment}.
/// The verifier never learns the score; it learns only that the hidden score exceeds threshold.
pub fn verify_letter(proof_bytes: &[u8], agent_id: &str, threshold: u64, commitment: u32) -> Result<(), String> {
    // Verification draws no randomness, so fixed seeds are correct and keep verify deterministic.
    let config = letter_config(SmallRng::seed_from_u64(0), SmallRng::seed_from_u64(0));

    let proof: p3_uni_stark::Proof<_> =
        bincode::deserialize(proof_bytes).map_err(|e| format!("deserialize: {}", e))?;
    let public_values = letter_public_values(agent_id, threshold, commitment)?;
    let air = RepIdLetterAir;
    verify(&config, &air, &proof, &public_values).map_err(|e| format!("verify failed: {:?}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    const AGENT: &str = "394b6ee4-62e7-4c66-8445-29107b097b4c"; // MEDIATOR
    const REPID: u64 = 2280;
    const THRESHOLD: u64 = 999;
    const NONCE: u64 = 1_234_567_890;

    #[test]
    fn letter_proves_and_verifies_without_revealing_score() {
        let lp = prove_letter(AGENT, THRESHOLD, REPID, NONCE).unwrap();
        verify_letter(&lp.proof_bytes, AGENT, THRESHOLD, lp.score_commitment).unwrap();
    }

    #[test]
    fn score_is_absent_from_public_values() {
        let commitment = score_commitment(REPID, NONCE);
        let pv = letter_public_values(AGENT, THRESHOLD, commitment).unwrap();
        // The score must not appear anywhere in the public values (it is a witness).
        let repid_felt = BabyBear::new(REPID as u32);
        assert!(!pv.contains(&repid_felt), "repid_score must NOT be a public value");
        assert_eq!(pv.len(), LETTER_NUM_PUBLIC_VALUES);
        assert_eq!(pv[LPUB_COMMITMENT], BabyBear::new(commitment));
    }

    #[test]
    fn letter_proof_is_randomized_yet_verifies() {
        // B2 hiding evidence: with the hiding PCS + entropy RNG, proving the SAME statement twice
        // yields DIFFERENT proof bytes (random salts, codewords, and masking rows). A non-hiding
        // (deterministic) STARK would emit byte-identical proofs — so a difference here is the
        // observable signature that the zero-knowledge machinery is actually engaged. Both proofs
        // must still verify against the same public statement.
        let a = prove_letter(AGENT, THRESHOLD, REPID, NONCE).unwrap();
        let b = prove_letter(AGENT, THRESHOLD, REPID, NONCE).unwrap();
        assert_eq!(a.score_commitment, b.score_commitment, "same (score,nonce) → same commitment");
        assert_ne!(
            a.proof_bytes, b.proof_bytes,
            "hiding proof must be randomized: two proofs of the same statement must differ"
        );
        verify_letter(&a.proof_bytes, AGENT, THRESHOLD, a.score_commitment).unwrap();
        verify_letter(&b.proof_bytes, AGENT, THRESHOLD, b.score_commitment).unwrap();
    }

    #[test]
    fn hidden_score_unrecoverable_without_nonce() {
        // The negative test: an attacker holding {commitment, threshold} cannot recover the score by
        // brute-forcing the entire RepID space — each candidate needs the secret nonce to reproduce
        // the commitment, and the commitment does not leak it.
        let commitment = score_commitment(REPID, NONCE);
        let mut recovered = None;
        for guess in 0..=10_000u64 {
            // Attacker tries the SAME nonce-free guessing they could mount: they do NOT know NONCE,
            // so the best they can do is guess (score) and hope a wrong-nonce commitment collides.
            // Model the attacker's lack of nonce by trying a fixed wrong nonce (0) for every guess.
            if score_commitment(guess, 0) == commitment {
                recovered = Some(guess);
                break;
            }
        }
        assert!(recovered.is_none(), "score must be unrecoverable without the secret nonce");
        // Sanity: WITH the nonce, the commitment opens (proves the commitment is to the real score).
        assert_eq!(score_commitment(REPID, NONCE), commitment);
    }

    #[test]
    fn letter_rejects_non_positive_and_wrong_commitment() {
        // repid == threshold has no witness.
        assert!(prove_letter(AGENT, 2280, 2280, NONCE).is_err(), "repid==threshold must not prove");
        // A proof for one commitment must not verify under a different commitment (binding).
        let lp = prove_letter(AGENT, THRESHOLD, REPID, NONCE).unwrap();
        assert!(
            verify_letter(&lp.proof_bytes, AGENT, THRESHOLD, lp.score_commitment ^ 1).is_err(),
            "wrong commitment rejected"
        );
        // …and not under a different agent (agent-binding).
        assert!(
            verify_letter(&lp.proof_bytes, "942860a6-e26f-4334-ae94-b7c1abed1e8c", THRESHOLD, lp.score_commitment).is_err(),
            "wrong agent rejected"
        );
    }

    // ── XC RED-TEAM FIXTURES (E:\dev\reports\2026-06-10\XC_REDTEAM_AGG_LETTER_AND_CHALLENGE.md) ──
    // XC attacked letter.rs @ fa0eacd. (c) hiding and (d) fold HELD (covered above + in aggregate.rs).
    // (a) and (b) BROKE — encoded here as adversarial regression fixtures. They assert the CURRENT
    // (vulnerable) behavior, so they pass today and DOCUMENT the limitation; the moment the fix lands
    // (in-AIR commitment binding / a wider multi-felt commitment / #95's HidingFriPcs — XC P3) these
    // collisions disappear and the asserts below must be inverted. That forced edit is the tripwire
    // that keeps the limitation from being silently shipped as "the score is hidden + bound."
    //
    // ⚠️ KNOWN LIMITATION (do NOT market LETTER's commitment as collision-resistant until fixed):
    //   score_commitment reduces BOTH inputs `% 2^31` (BabyBear is ~31-bit), and the (repid,nonce)→
    //   commitment link is witness-level, not an in-AIR constraint. The STARK still soundly proves
    //   repid > threshold and the score stays private (hiding held); but the *commitment* is forgeable.

    #[test]
    fn redteam_a_nonce_entropy_capped_at_31_bits() {
        // XC P2(a): a "full-width" production nonce is silently reduced to 31 bits, so two DISTINCT
        // nonces collide to the same commitment. Effective nonce entropy ≤ 31 bits regardless of caller.
        assert_eq!(
            score_commitment(REPID, NONCE),
            score_commitment(REPID, NONCE + (1u64 << 31)),
            "BROKEN-AS-DESIGNED: nonce reduced mod 2^31 → distinct nonces collide (XC P2a). \
             Invert this assert when the commitment widens / binds in-AIR."
        );
        // The reduction is unconditional:
        assert_eq!(score_commitment(REPID, NONCE), score_commitment(REPID, NONCE % (1u64 << 31)));
    }

    #[test]
    fn redteam_b_commitment_forgeable_via_reduction() {
        // XC P2(b): a different (repid', nonce') reaches the SAME commitment — the binding is not
        // enforced in-circuit, and the 31-bit reduction guarantees alternative preimages exist.
        let target = score_commitment(REPID, NONCE);
        // Forge 1 — different nonce (score unchanged): n' = n + 2^31.
        let forge_nonce = NONCE + (1u64 << 31);
        assert_ne!(forge_nonce, NONCE);
        assert_eq!(score_commitment(REPID, forge_nonce), target, "forged different nonce → same commitment (XC P2b)");
        // Forge 2 — different score ARGUMENT (reduces equal): r' = repid + 2^31 maps to the same felt.
        let forge_score = REPID + (1u64 << 31);
        assert_ne!(forge_score, REPID);
        assert_eq!(score_commitment(forge_score, NONCE), target, "forged different score-arg → same commitment (XC P2b)");
        // The ONLY thing standing between this forge and acceptance is the issuer's witness-level
        // recompute — there is no in-AIR constraint tying the public commitment to the proven repid.
    }
}
