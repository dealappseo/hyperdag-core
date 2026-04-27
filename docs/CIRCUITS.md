# HyperDAG Trust Protocol v1 - Circuit Reference

This document outlines the zero-knowledge circuits used in the `zkp-postcard` service for RepID verification. The circuits are implemented using Plonky3 (BabyBear field).

## 1. `rep_id_threshold` (RepIdRangeCheckAir)
Proves that a holder's RepID meets a required threshold, without revealing the RepID.

- **Witness Shape:**
  - `repid` (u32): The actual RepID value.
  - `nonce` ([u8; 32]): The secret salt used when the SBT was minted.
  - `holder_address` ([u8; 20]): The owner's wallet address.
- **Public Inputs:**
  - `threshold` (u32): The required minimum RepID score.
  - `commitment` ([u8; 32]): The SHA-256 hash `H(holder_address || nonce)`.
- **Constraints:**
  - Range check: `0 <= R <= 10000`
  - Threshold check: `R >= T`
  - Commitment check: `C == H(holder_address || nonce)` *(Note: Currently checked out-of-circuit by the prover before witness generation due to missing Plonky3 Poseidon2/Keccak VM integration. Marked as FIXME in source).*

## 2. `earned_repid` (EarnedRepIdAir)
Proves that the sum of an agent's verified action weights meets the threshold.

- **Witness Shape:**
  - `weights` (Vec<u32>): The verified action weights.
  - `nonce`, `holder_address`
- **Public Inputs:**
  - `threshold` (u32): The required `T_e`.
  - `commitment` ([u8; 32]).
- **Constraints:**
  - `Sum(weights) >= T_e`

## 3. `perceived_repid` (PerceivedRepIdAir)
Proves that the sum of peer attestation weights meets the threshold.

- **Witness Shape:**
  - `attestations` (Vec<u32>): The weights of the attestations.
  - `nonce`, `holder_address`
- **Public Inputs:**
  - `threshold` (u32): The required `T_p`.
  - `commitment` ([u8; 32]).
- **Constraints:**
  - `Sum(attestations) >= T_p`

## 4. `combined_repid`
Proves `0.7 * Earned + 0.3 * Perceived >= T_combined`.
*(WIP: Scoped to v0.2. Requires recursive verification of the inner Earned and Perceived proofs.)*
