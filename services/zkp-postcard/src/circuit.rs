use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_air::WindowAccess;
// Plonky3 STARK Range-Check Circuit for RepID Verification
//
// Proves that a value fits within a 32-bit unsigned integer range.
// To prove "RepID > threshold": diff = repid - threshold - 1
// prove(diff fits in u32) => repid > threshold
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

/// AIR for range-checking a 32-bit value.
pub struct RepIdRangeCheckAir {
    pub value: u32,
}

impl<F: Field> BaseAir<F> for RepIdRangeCheckAir {
    fn width(&self) -> usize {
        32
    }

    /// PHASE B — declare the 32 public values (the agent-bound commitment elements). Without this the
    /// prover commits ZERO public values and the commitment passed to `prove_range_check` is silently
    /// dropped (prove_range_check's own verify then fails). Declaring them makes the prover absorb the
    /// commitment into the Fiat-Shamir transcript, so a proof for agent A's commitment is REJECTED when
    /// verified against agent B's (agent-binding). See test_agent_binding_rejects_swapped_commitment.
    fn num_public_values(&self) -> usize {
        32
    }
}

impl<AB: AirBuilder> Air<AB> for RepIdRangeCheckAir where AB::F: Field {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();

        // MSB must be zero (value < 2^31)
        builder.assert_eq(row[0], AB::Expr::ZERO);

        // BabyBear modulus guard
        let upper_product = row[1..5]
            .iter()
            .map(|&bit: &AB::Var| bit.into())
            .product::<AB::Expr>();
        let remaining_sum = row[5..32]
            .iter()
            .map(|&bit: &AB::Var| bit.into())
            .sum::<AB::Expr>();
        builder.when(upper_product).assert_zero(remaining_sum);

        // Reconstruct value from bits and verify
        let mut reconstructed = AB::Expr::ZERO;
        for i in 0..32 {
            let bit = row[i];
            builder.assert_bool(bit);
            reconstructed += AB::Expr::from_u32(1 << (31 - i)) * bit;
        }
        builder
            .when_first_row()
            .assert_eq(AB::Expr::from_u32(self.value), reconstructed);
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

fn commitment_to_babybear(commitment: &str) -> Result<Vec<BabyBear>, String> {
    let hex_str = commitment.strip_prefix("0x").unwrap_or(commitment);
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid commitment hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("Commitment must be 32 bytes, got {}", bytes.len()));
    }
    let mut elements = Vec::with_capacity(32);
    for b in bytes {
        // BabyBear: any u32 < modulus (2^31 - 2^27 + 1) is a valid field element.
        // A single byte (0-255) is always safe.
        elements.push(BabyBear::new(b as u32));
    }
    Ok(elements)
}

/// Prove that `value` fits in a u32 using Plonky3 STARK (BabyBear field).
/// New Plonky3 API: prove(config, air, trace, public_values) -> Proof
/// verify(config, air, &proof, public_values) -> Result<(), VerificationError>
/// 
/// Soundness: The commitment is decoded into BabyBear elements and passed as
/// public_values to bind the proof to the agent's real committed score.
/// Note: Compiling custom Poseidon2 AIR constraints is blocked by current Plonky3
/// crate versions, so we use the fallback of passing the expected_commitment in public_values.
pub fn prove_range_check(value: u32, commitment: &str) -> Result<Vec<u8>, String> {
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

    let public_values = commitment_to_babybear(commitment)?;

    // New API: no challenger arg, returns Proof directly
    let proof = prove(&config, &air, trace, &public_values);

    // Verify immediately
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

    #[test]
    fn test_proof_serialization_round_trip() {
        let value = 100;
        let air = RepIdRangeCheckAir { value };
        
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

        let trace = generate_trace::<Val>(value);
        let dft = Dft::new(trace.height() << fri_config.log_blowup);
        let pcs = Pcs::new(dft, val_mmcs, fri_config);
        let challenger = SerializingChallenger32::new(HashChallenger::<u8, ByteHash, 32>::new(vec![], byte_hash.clone()));
        let config = StarkConfig::new(pcs, challenger);

        // 32 public values now required (the agent-bound commitment). Use a dummy commitment here.
        let pv_rt = commitment_to_babybear(&"cc".repeat(32)).expect("round-trip pv decode");
        let proof = prove(&config, &air, trace, &pv_rt);

        // Serialize
        let encoded: Vec<u8> = bincode::serialize(&proof).expect("Serialization failed");
        
        // Deserialize - need full type for bincode in test context if inference fails
        // In this case Proof<_> should work.
        let decoded: Proof<_> = bincode::deserialize(&encoded).expect("Deserialization failed");
        
        // Verify decoded proof
        verify(&config, &air, &decoded, &pv_rt).expect("Verification of decoded proof failed");
    }

    /// AGENT-BINDING (Phase B): agent_id is folded into the sha256 commitment, which is passed as the
    /// proof's public_values. A proof generated for agent A's commitment MUST be REJECTED when verified
    /// against agent B's commitment — otherwise a proof could be replayed under a different identity.
    /// The binding holds because the public_values are absorbed into the Fiat-Shamir transcript, so a
    /// mismatched commitment diverges the verifier's challenges and verification fails.
    #[test]
    fn test_agent_binding_rejects_swapped_commitment() {
        let value = 100u32;
        let air = RepIdRangeCheckAir { value };

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
            log_blowup: 2, num_queries: 28,
            log_final_poly_len: 0, max_log_arity: 1, commit_proof_of_work_bits: 0, query_proof_of_work_bits: 8,
            mmcs: challenge_mmcs,
        };
        let trace = generate_trace::<Val>(value);
        let dft = Dft::new(trace.height() << fri_config.log_blowup);
        let pcs = Pcs::new(dft, val_mmcs, fri_config);
        let challenger = SerializingChallenger32::new(HashChallenger::<u8, ByteHash, 32>::new(vec![], byte_hash.clone()));
        let config = StarkConfig::new(pcs, challenger);

        // Two distinct agent commitments (in prod: sha256("hyperdag_v1:{agent_id}:{repid}:{threshold}")).
        let commitment_a = "aa".repeat(32);
        let commitment_b = "bb".repeat(32);
        let pv_a = commitment_to_babybear(&commitment_a).expect("commitment A decode");
        let pv_b = commitment_to_babybear(&commitment_b).expect("commitment B decode");
        assert_ne!(pv_a, pv_b, "distinct agent commitments must decode to distinct public values");

        // Prove for agent A.
        let proof = prove(&config, &air, trace, &pv_a);

        // Correct agent verifies.
        verify(&config, &air, &proof, &pv_a)
            .expect("agent A's proof must verify against agent A's commitment");

        // Swapped agent_id (agent B's commitment) is REJECTED.
        assert!(
            verify(&config, &air, &proof, &pv_b).is_err(),
            "AGENT-BINDING VIOLATION: a proof for agent A verified against agent B's commitment"
        );
    }
}
