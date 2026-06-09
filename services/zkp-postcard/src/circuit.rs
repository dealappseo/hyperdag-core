use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_air::WindowAccess;
// Plonky3 STARK Range-Check Circuit for RepID Verification (agent-bound)
//
// Proves "RepID > threshold" for a SPECIFIC agent:
//   gap = repid_score - threshold - 1
//   prove(gap fits in u32)  =>  repid_score > threshold
//
// Soundness (A1, the keystone):
//   The statement is the public tuple {agent_id, threshold, repid_score}, exposed as
//   circuit public values. Two binding properties hold:
//     1. agent-binding  — agent_id (16 bytes) is in public_values, observed into the
//        Fiat-Shamir transcript by both prover and verifier. A proof made for agent A
//        FAILS verification under agent B's public values (different transcript). This
//        is what makes a RepID proof non-replayable across agents.
//     2. value-binding  — an AIR boundary constraint asserts the range-checked gap equals
//        (repid_score - threshold - 1) drawn from public_values, so the proof actually
//        attests "THIS agent's score exceeds THIS threshold," not merely "some 32-bit
//        value exists."
//
// Field: BabyBear (p = 2^31 - 2^27 + 1)
// Hash: Keccak256
// FRI: log_blowup=2, 28 queries, 8-bit PoW

use p3_air::{Air, AirBuilder, BaseAir};
use p3_baby_bear::BabyBear;
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
use p3_uni_stark::{prove, verify, StarkConfig, Proof};
use sha2::{Digest, Sha256};

/// Canonical public-input layout (BabyBear field elements) — the RepID statement.
///   [0..16]  agent_id : the 16 bytes of the agent UUID, one byte per element
///   [16]     threshold
///   [17]     repid_score
///   [18]     epoch     : an AUTHORITATIVE freshness epoch (block-height-derived, NEVER agent-supplied).
/// Binding `epoch` into the public values (observed into the Fiat-Shamir transcript) ties each proof
/// to the epoch it was minted in. A freshness check (verifier-side, against the current authoritative
/// epoch) then rejects a stale proof — defeating replay-across-time (a proof minted when RepID was
/// high being re-presented later). 0.3.0. The WASM verifier + `@hyperdag/trustshell` MUST reproduce
/// this exact encoding.
pub const NUM_PUBLIC_VALUES: usize = 19;
const PUB_THRESHOLD: usize = 16;
const PUB_REPID: usize = 17;
const PUB_EPOCH: usize = 18;

/// AIR for range-checking the gap (repid - threshold - 1) and binding it to the
/// public statement {agent_id, threshold, repid_score}.
pub struct RepIdRangeCheckAir {
    /// The gap = repid_score - threshold - 1 (the value range-checked into 32 bits).
    pub value: u32,
}

impl<F: Field> BaseAir<F> for RepIdRangeCheckAir {
    fn width(&self) -> usize {
        32
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }
}

impl<AB: AirBuilder> Air<AB> for RepIdRangeCheckAir where AB::F: Field {
    fn eval(&self, builder: &mut AB) {
        // Copy the public statement scalars out before taking a mutable borrow of the builder.
        let pis = builder.public_values();
        let threshold = pis[PUB_THRESHOLD];
        let repid = pis[PUB_REPID];

        let main = builder.main();
        let row = main.current_slice();

        // 16-bit range check (soundness fix, 2026-06-08). The gap must be < 2^16. The high
        // 16 bits (row[0..16] = the 2^16..2^31 places, big-endian) are forced to ZERO, so a
        // "negative" gap (repid <= threshold), which is (repid-threshold-1) mod p ~= 2^31 with
        // high bits set, cannot be represented and verification fails. A 31-bit range over
        // BabyBear (p = 2^31 - 2^27 + 1) was unsound: ~the whole field is representable, so a
        // wrapped negative gap (e.g. -1 == p-1 == 2013265920 < 2^31) satisfied the equality.
        // ASSUMPTION: repid - threshold < 65536. True for RepID (repid <= 10000, threshold >= 0
        // => gap <= 9999). A larger spread would be rejected as out of range (fail-closed).
        for i in 0..16 {
            builder.assert_zero(row[i]);
        }

        // Reconstruct the gap from its low 16 bits (row[16..32] = 2^15..2^0); assert boolean.
        let mut reconstructed = AB::Expr::ZERO;
        for i in 16..32 {
            let bit = row[i];
            builder.assert_bool(bit);
            reconstructed += AB::Expr::from_u32(1 << (31 - i)) * bit;
        }

        // value-binding: the range-checked gap == repid_score - threshold - 1 (public).
        // With the gap proven < 2^16 << p, this equality holds over the integers only when
        // repid > threshold — a wrapped (negative) gap would be >= 2^16 and is rejected above.
        builder
            .when_first_row()
            .assert_eq(reconstructed, repid.into() - threshold.into() - AB::Expr::ONE);
    }
}

/// Generate the execution trace: decompose value into 32 bits (big-endian)
fn generate_trace<F: Field>(value: u32) -> RowMajorMatrix<F> {
    let mut bits = Vec::with_capacity(32);
    for i in (0..32).rev() {
        if (value & (1 << i)) != 0 {
            bits.push(F::ONE);
        } else {
            bits.push(F::ZERO);
        }
    }
    RowMajorMatrix::new(bits, 32)
}

/// Map an agent identifier to 16 bytes. A canonical UUID (with or without hyphens)
/// maps to its 16 raw bytes; any other identifier is bound via sha256(id)[..16] so
/// legacy/numeric agent ids still produce a deterministic, collision-resistant binding.
fn agent_id_to_16_bytes(agent_id: &str) -> [u8; 16] {
    let cleaned: String = agent_id.chars().filter(|c| *c != '-').collect();
    if cleaned.len() == 32 && cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        if let Ok(bytes) = hex::decode(&cleaned) {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&bytes);
            return arr;
        }
    }
    let digest = Sha256::digest(agent_id.as_bytes());
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&digest[..16]);
    arr
}

/// Build the canonical 19-element public-values vector for the statement
/// {agent_id, threshold, repid_score, epoch}. threshold, repid_score, and epoch must each be < 2^31.
/// `epoch` is an AUTHORITATIVE freshness epoch (block-height-derived) — the prover MUST source it
/// from chain/EAS, NEVER from agent input, or replay-across-time is not defeated.
pub fn build_public_values(
    agent_id: &str,
    threshold: u64,
    repid_score: u64,
    epoch: u64,
) -> Result<Vec<BabyBear>, String> {
    if threshold >= (1u64 << 31) || repid_score >= (1u64 << 31) || epoch >= (1u64 << 31) {
        return Err(format!(
            "threshold/repid_score/epoch must be < 2^31 (got threshold={}, repid_score={}, epoch={})",
            threshold, repid_score, epoch
        ));
    }
    let mut pv = Vec::with_capacity(NUM_PUBLIC_VALUES);
    for b in agent_id_to_16_bytes(agent_id) {
        pv.push(BabyBear::new(b as u32));
    }
    pv.push(BabyBear::new(threshold as u32));
    pv.push(BabyBear::new(repid_score as u32));
    pv.push(BabyBear::new(epoch as u32));
    debug_assert_eq!(pv.len(), NUM_PUBLIC_VALUES);
    Ok(pv)
}

/// Prove "repid_score > threshold" for `agent_id` at `epoch`, using a Plonky3 STARK (BabyBear).
/// `value` is the gap = repid_score - threshold - 1 (caller computes it). `epoch` MUST be the
/// authoritative current epoch (block-height-derived) — never agent-supplied.
/// The proof is bound to the public statement {agent_id, threshold, repid_score, epoch}.
pub fn prove_range_check(
    value: u32,
    agent_id: &str,
    threshold: u64,
    repid_score: u64,
    epoch: u64,
) -> Result<Vec<u8>, String> {
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

    let air = RepIdRangeCheckAir { value };
    let trace = generate_trace::<Val>(value);

    let fri_config = FriConfig {
        log_blowup: 2,
        num_queries: 28,
        log_final_poly_len: 0, max_log_arity: 1, commit_proof_of_work_bits: 0, query_proof_of_work_bits: 8,
        mmcs: challenge_mmcs,
    };

    let dft = Dft::new(trace.height() << fri_config.log_blowup);
    let pcs = Pcs::new(dft, val_mmcs, fri_config);
    let mut challenger = SerializingChallenger32::new(HashChallenger::<u8, ByteHash, 32>::new(vec![], byte_hash.clone()));
    let config = StarkConfig::new(pcs, challenger);

    let public_values = build_public_values(agent_id, threshold, repid_score, epoch)?;

    // New API: no challenger arg, returns Proof directly
    let proof = prove(&config, &air, trace, &public_values);

    // Verify immediately (prover-side sanity check)
    verify(&config, &air, &proof, &public_values)
        .map_err(|e| format!("Verify failed: {:?}", e))?;

    // Return the real serialized proof bytes
    let proof_bytes = bincode::serialize(&proof)
        .map_err(|e| format!("Plonky3 proof serialization failed: {}", e))?;

    Ok(proof_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shared StarkConfig builder for tests (mirrors prove_range_check).
    macro_rules! test_config {
        () => {{
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
                log_final_poly_len: 0, max_log_arity: 1, commit_proof_of_work_bits: 0, query_proof_of_work_bits: 8,
                mmcs: challenge_mmcs,
            };
            let trace_height = 32usize; // single 32-wide row; height() == 1
            let _ = trace_height;
            let dft = Dft::new(1usize << fri_config.log_blowup);
            let pcs = Pcs::new(dft, val_mmcs, fri_config);
            let challenger = SerializingChallenger32::new(HashChallenger::<u8, ByteHash, 32>::new(vec![], byte_hash.clone()));
            StarkConfig::new(pcs, challenger)
        }};
    }

    const AGENT_A: &str = "394b6ee4-62e7-4c66-8445-29107b097b4c";
    const AGENT_B: &str = "942860a6-e26f-4334-ae94-b7c1abed1e8c";
    const EPOCH: u64 = 1_000;

    #[test]
    fn test_agent_bound_proof_round_trip() {
        let repid = 2280u64;
        let threshold = 999u64;
        let gap = (repid - threshold - 1) as u32;
        let config = test_config!();
        let air = RepIdRangeCheckAir { value: gap };
        let trace = generate_trace::<BabyBear>(gap);
        let pv = build_public_values(AGENT_A, threshold, repid, EPOCH).unwrap();

        let proof = prove(&config, &air, trace, &pv);
        let encoded = bincode::serialize(&proof).expect("serialize");
        let decoded: Proof<_> = bincode::deserialize(&encoded).expect("deserialize");
        verify(&config, &air, &decoded, &pv).expect("agent-bound proof must verify");
    }

    #[test]
    fn test_wrong_agent_id_fails_verification() {
        // Soundness: a proof made for AGENT_A must NOT verify under AGENT_B's public values.
        let repid = 2280u64;
        let threshold = 999u64;
        let gap = (repid - threshold - 1) as u32;
        let config = test_config!();
        let air = RepIdRangeCheckAir { value: gap };
        let trace = generate_trace::<BabyBear>(gap);

        let pv_a = build_public_values(AGENT_A, threshold, repid, EPOCH).unwrap();
        let proof = prove(&config, &air, trace, &pv_a);

        let pv_b = build_public_values(AGENT_B, threshold, repid, EPOCH).unwrap();
        let res = verify(&config, &air, &proof, &pv_b);
        assert!(res.is_err(), "verification with wrong agent_id MUST fail");
    }

    #[test]
    fn test_wrong_score_fails_verification() {
        // value-binding: a proof for repid=2280 must NOT verify against a claimed repid=9999.
        let repid = 2280u64;
        let threshold = 999u64;
        let gap = (repid - threshold - 1) as u32;
        let config = test_config!();
        let air = RepIdRangeCheckAir { value: gap };
        let trace = generate_trace::<BabyBear>(gap);

        let pv_real = build_public_values(AGENT_A, threshold, repid, EPOCH).unwrap();
        let proof = prove(&config, &air, trace, &pv_real);

        let pv_lie = build_public_values(AGENT_A, threshold, 9999, EPOCH).unwrap();
        let res = verify(&config, &air, &proof, &pv_lie);
        assert!(res.is_err(), "verification with inflated repid_score MUST fail");
    }

    #[test]
    fn test_wrong_epoch_fails_verification() {
        // freshness-binding (0.3.0): a proof minted at EPOCH must NOT verify under a different epoch.
        // This is what makes a stale proof detectable — the epoch is bound into the transcript.
        let repid = 2280u64;
        let threshold = 999u64;
        let gap = (repid - threshold - 1) as u32;
        let config = test_config!();
        let air = RepIdRangeCheckAir { value: gap };
        let trace = generate_trace::<BabyBear>(gap);

        let pv_now = build_public_values(AGENT_A, threshold, repid, EPOCH).unwrap();
        let proof = prove(&config, &air, trace, &pv_now);

        let pv_other_epoch = build_public_values(AGENT_A, threshold, repid, EPOCH + 1).unwrap();
        let res = verify(&config, &air, &proof, &pv_other_epoch);
        assert!(res.is_err(), "verification under a different epoch MUST fail (freshness binding)");
    }

    // BabyBear prime p = 2^31 - 2^27 + 1. A "negative" gap (repid <= threshold) is
    // (repid - threshold - 1) mod p, i.e. ~p (high bits set). The 16-bit range check rejects it.
    const BABYBEAR_P: u64 = (1u64 << 31) - (1u64 << 27) + 1;

    /// Attempt to forge a proof for `repid`/`threshold` using a (possibly wrapped) gap value.
    /// Returns true iff the forgery FAILS — either the prover cannot build it (constraints
    /// unsatisfiable → panic under debug_assertions) or the verifier rejects it.
    fn forgery_fails(agent: &str, threshold: u64, repid: u64, malicious_gap: u32) -> bool {
        use std::panic;
        let prev = panic::take_hook();
        panic::set_hook(Box::new(|_| {})); // silence the expected unsatisfiable-constraint panic
        let out = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            let config = test_config!();
            let air = RepIdRangeCheckAir { value: malicious_gap };
            let trace = generate_trace::<BabyBear>(malicious_gap);
            let pv = build_public_values(agent, threshold, repid, EPOCH).unwrap();
            let proof = prove(&config, &air, trace, &pv);
            verify(&config, &air, &proof, &pv)
        }));
        panic::set_hook(prev);
        match out {
            Err(_) => true,       // prover could not satisfy constraints
            Ok(Err(_)) => true,   // verifier rejected
            Ok(Ok(())) => false,  // FORGERY ACCEPTED — soundness broken
        }
    }

    #[test]
    fn test_boundary_repid_eq_threshold_plus_one_passes() {
        // gap = 0 is the smallest honest gap: repid = threshold + 1.
        let threshold = 1000u64;
        let repid = 1001u64;
        let gap = (repid - threshold - 1) as u32; // 0
        let config = test_config!();
        let air = RepIdRangeCheckAir { value: gap };
        let trace = generate_trace::<BabyBear>(gap);
        let pv = build_public_values(AGENT_A, threshold, repid, EPOCH).unwrap();
        let proof = prove(&config, &air, trace, &pv);
        verify(&config, &air, &proof, &pv).expect("repid == threshold + 1 must verify (gap 0)");
    }

    #[test]
    fn test_boundary_repid_eq_threshold_fails() {
        // repid == threshold → honest gap would be -1 == p-1 (wrapped). Must be unforgeable.
        assert!(
            forgery_fails(AGENT_A, 1000, 1000, (BABYBEAR_P - 1) as u32),
            "repid == threshold (wrapped gap p-1) MUST fail"
        );
    }

    #[test]
    fn test_wrapped_gap_p_minus_1_fails() {
        // Explicit: gap field-element p-1 (== -1) with any equal repid/threshold is rejected
        // because p-1 has high bits set (fails the 16-bit range check).
        assert!(
            forgery_fails(AGENT_A, 5000, 5000, (BABYBEAR_P - 1) as u32),
            "wrapped gap = p-1 MUST fail the 16-bit range check"
        );
    }

    #[test]
    fn test_repid_below_threshold_fails() {
        // repid < threshold by 500 → gap_real = -501 → wrapped = p-501 (high bits set).
        let threshold = 1000u64;
        let repid = 500u64;
        let wrapped = (BABYBEAR_P - 501) as u32; // (repid - threshold - 1) mod p
        assert!(
            forgery_fails(AGENT_A, threshold, repid, wrapped),
            "repid < threshold MUST fail"
        );
    }
}
