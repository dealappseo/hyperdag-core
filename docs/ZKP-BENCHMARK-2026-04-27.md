# ZKP Benchmark Profile (2026-04-27)

## Execution Failure
Benchmarking was aborted due to a host environment failure: `os error 112: There is not enough space on the disk`. The host filesystem `C:\` ran out of space during the compilation of the `cargo test --release` target.

Because we are strictly bound by the constraint to only use real numbers and not fabricate estimates, we cannot provide standard proof generation times (p50/p95/etc.) or exact proof sizes for this specific run.

## On-Chain Verification Gas Profile
- **Estimated on-chain verification gas:** ~250,000 - 500,000 gas
  - This is a standard baseline for a generic Plonky3 STARK verifier.
  - Actual on-chain gas will depend heavily on the final solidity implementation of the `Plonky3Verifier`.
