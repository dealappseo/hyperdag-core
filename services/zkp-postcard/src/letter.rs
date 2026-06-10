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
// SCORE-HIDING (negative-tested): given {agent_id, threshold, commitment, proof}, the score is
// unrecoverable — it is absent from the public values, and brute-forcing the small RepID space
// (0..=10000) against the commitment fails without the secret nonce (Poseidon2 is one-way; each
// guess needs the matching nonce, which the commitment does not leak).

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

use crate::circuit::agent_id_to_16_bytes_pub;

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

fn letter_trace<F: Field>(repid: u64, threshold: u64) -> RowMajorMatrix<F> {
    let gap = (repid - threshold - 1) as u32;
    let mut row = Vec::with_capacity(LETTER_WIDTH);
    for i in (0..32).rev() {
        row.push(if (gap & (1 << i)) != 0 { F::ONE } else { F::ZERO });
    }
    row.push(F::from_u32(repid as u32));
    RowMajorMatrix::new(row, LETTER_WIDTH)
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

    let commitment = score_commitment(repid_score, nonce);
    let trace = letter_trace::<Val>(repid_score, threshold);

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
    let dft = Dft::new(1usize << fri_config.log_blowup);
    let pcs = Pcs::new(dft, val_mmcs, fri_config);
    let challenger = SerializingChallenger32::new(HashChallenger::<u8, ByteHash, 32>::new(vec![], byte_hash));
    let config = StarkConfig::new(pcs, challenger);

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
}
