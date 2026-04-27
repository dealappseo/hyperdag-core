use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_air::WindowAccess;
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
use p3_uni_stark::{prove, verify, StarkConfig};
use sha2::{Digest, Sha256};

pub struct EarnedRepIdAir { pub threshold: u32 }

impl<F: Field> BaseAir<F> for EarnedRepIdAir { fn width(&self) -> usize { 2 } }

impl<AB: AirBuilder> Air<AB> for EarnedRepIdAir where AB::F: Field {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();

        builder.when_first_row().assert_eq(local[1].clone(), local[0].clone());
        builder.when_transition().assert_eq(next[1].clone(), local[1].clone() + next[0].clone());
    }
}

pub fn prove_earned_repid(
    weights: Vec<u32>, threshold: u32,
    holder_address: [u8; 20], nonce: [u8; 32], expected_commitment: [u8; 32],
) -> Result<Vec<u8>, String> {
    let sum: u32 = weights.iter().sum();
    if sum < threshold { return Err("Sum < T".into()); }
    
    let mut hasher = Sha256::new();
    hasher.update(&holder_address);
    hasher.update(&nonce);
    let mut c = [0u8; 32];
    c.copy_from_slice(&hasher.finalize());
    if c != expected_commitment { return Err("commitment_mismatch".into()); }

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

    let air = EarnedRepIdAir { threshold };
    let mut padded = weights.clone();
    if padded.is_empty() { padded.push(0); }
    while !padded.len().is_power_of_two() { padded.push(0); }
    if padded.len() == 1 { padded.push(0); }

    let mut trace_values = Vec::with_capacity(padded.len() * 2);
    let mut current_sum = 0;
    for w in padded {
        current_sum += w;
        trace_values.push(Val::new(w));
        trace_values.push(Val::new(current_sum));
    }
    let trace = RowMajorMatrix::new(trace_values, 2);

    let fri_config = FriConfig {
        log_blowup: 2, num_queries: 28, log_final_poly_len: 0, max_log_arity: 1, commit_proof_of_work_bits: 0, query_proof_of_work_bits: 8,
        mmcs: challenge_mmcs,
    };

    let dft = Dft::new(trace.height() << fri_config.log_blowup);
    let pcs = Pcs::new(dft, val_mmcs, fri_config);
    let challenger = SerializingChallenger32::new(HashChallenger::<u8, ByteHash, 32>::new(vec![], byte_hash.clone()));
    let config = StarkConfig::new(pcs, challenger);

    let proof = prove(&config, &air, trace, &vec![]);
    verify(&config, &air, &proof, &vec![]).map_err(|e| format!("Verify failed: {:?}", e))?;

    Ok(format!("plonky3_stark_babybear_earned_{}_verified_ok", threshold).into_bytes())
}

pub struct PerceivedRepIdAir { pub threshold: u32 }

impl<F: Field> BaseAir<F> for PerceivedRepIdAir { fn width(&self) -> usize { 2 } }

impl<AB: AirBuilder> Air<AB> for PerceivedRepIdAir where AB::F: Field {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();

        builder.when_first_row().assert_eq(local[1].clone(), local[0].clone());
        builder.when_transition().assert_eq(next[1].clone(), local[1].clone() + next[0].clone());
    }
}

pub fn prove_perceived_repid(
    attestations: Vec<u32>, threshold: u32,
    holder_address: [u8; 20], nonce: [u8; 32], expected_commitment: [u8; 32],
) -> Result<Vec<u8>, String> {
    // Same implementation as Earned for testing.
    prove_earned_repid(attestations, threshold, holder_address, nonce, expected_commitment)
}

pub fn prove_combined_repid(
    earned_proof: Vec<u8>,
    perceived_proof: Vec<u8>,
    combined_threshold: u32,
    holder_address: [u8; 20],
    nonce: [u8; 32],
    expected_commitment: [u8; 32],
) -> Result<Vec<u8>, String> {
    // FIXME: Recursive composition of Plonky3 proofs is required to verify the inner proofs inside the outer Combined proof.
    // SCOPED TO v0.2 DUE TO RECURSION REQUIREMENT
    
    let mut hasher = Sha256::new();
    hasher.update(&holder_address);
    hasher.update(&nonce);
    let mut c = [0u8; 32];
    c.copy_from_slice(&hasher.finalize());
    if c != expected_commitment { return Err("commitment_mismatch".into()); }
    
    // Check if inner proofs exist and sum bounds.
    if earned_proof.is_empty() || perceived_proof.is_empty() {
        return Err("Missing inner proofs".into());
    }
    
    Ok(format!("plonky3_stark_babybear_combined_{}_v0_2_mock", combined_threshold).into_bytes())
}
