# Verifier API (Rust)

Verification in the `zkp-postcard` service is performed immediately after proof generation using the `p3_uni_stark::verify` function.

## Local Verification
The prover internally calls the local verifier before returning the payload:
```rust
use p3_uni_stark::verify;

// Inside the prover function:
verify(&config, &air, &proof, &vec![])
    .map_err(|e| format!("Verify failed: {:?}", e))?;
```

## On-Chain Verification
The on-chain verifier interacts with the `Plonky3Verifier` smart contract deployed on Base Sepolia.

An integration test scaffolding is provided in `tests/onchain_verifier_test.rs`:
```rust
async fn verify_onchain_mock(proof: &[u8], threshold: u32, commitment: &[u8; 32]) -> bool
```
*Note: The actual Solidity ABI for `Plonky3Verifier` is currently missing from this repository, so the Rust integration test uses an RPC mock.*
