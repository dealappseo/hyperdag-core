# Prover API (Rust)

The prover APIs are exposed in the `zkp_postcard` crate under `src/circuit.rs` and `src/variants.rs`.

## General Structure

All prover functions follow a similar pattern:
1. Validate bounds and commitments out-of-circuit (returns `Err` early if validation fails).
2. Construct the execution trace using `RowMajorMatrix`.
3. Configure the `StarkConfig` (FRI blowup = 2, 28 queries).
4. Run `p3_uni_stark::prove`.

## Endpoints

### `prove_repid_threshold`
```rust
pub fn prove_repid_threshold(
    repid: u32,
    threshold: u32,
    holder_address: [u8; 20],
    nonce: [u8; 32],
    expected_commitment: [u8; 32],
) -> Result<Vec<u8>, String>
```
Generates a Plonky3 proof for `repid >= threshold`.

### `prove_earned_repid` / `prove_perceived_repid`
```rust
pub fn prove_earned_repid(
    weights: Vec<u32>,
    threshold: u32,
    holder_address: [u8; 20],
    nonce: [u8; 32],
    expected_commitment: [u8; 32],
) -> Result<Vec<u8>, String>
```
Generates a Plonky3 proof that the sum of `weights` >= `threshold`.

### `prove_combined_repid` (WIP)
Currently scoped to v0.2. Returns a mock payload until Plonky3 recursive verification is fully integrated.
