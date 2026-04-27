# ZKP Circuit Infrastructure Audit (2026-04-27)

## Phase 1: Existing ZKP Infrastructure Audit

### Overview
This audit examines the existing ZKP infrastructure located in `hyperdag-core/services/zkp-postcard/`.

### Crates / Modules

#### `services/zkp-postcard/`
- **Dependencies:**
  - Plonky3 (`p3-field`, `p3-baby-bear`, `p3-fri`, etc.) is pinned to the `main` branch via git.
- **Public API Surface:**
  - **REST API:**
    - `GET /health` - Healthcheck endpoint.
    - `POST /zkp/repid-proof` - Generates a RepID range check proof. Falls back to a SHA-256 mock if generation fails or constraint isn't met.
    - `GET /zkp/verify/{commitment}` - Verifies the proof (currently locally stored/mock verification by tracking verified states in an in-memory hash map).
  - **Rust API:**
    - `prove_range_check(value: u32) -> Result<Vec<u8>, String>` - Proves the value fits in a `u32` (range check).
- **Test Coverage:**
  - 0 tests. The `tests/` directory doesn't exist and `src/` has no test modules.
- **Known Issues:**
  - `prove_range_check` throws away the Plonky3 `Proof` object because it isn't easily serializable. It returns a mock string `"plonky3_stark_babybear_rangecheck_value_{}_verified_ok"` instead of a real serialized proof. This means the verifier never receives an actual proof!
  - `POST /zkp/repid-proof` checks if `repid > threshold`, and if false, quietly falls back to a SHA-256 commitment POC without a zero-knowledge proof. This is a severe API-level bypass.
  - Verification API (`/zkp/verify/{commitment}`) just looks up the in-memory `Store` to see if `verified` was true, rather than actually performing proof validation.
- **Compile Status:**
  - `cargo check` and `cargo test` pass (but 0 tests exist).

### Status Summary
| Module | Compiles | Tests | Coverage | Blocker |
|---|---|---|---|---|
| `zkp-postcard` | Yes | 0 | 0% | Proof serialization missing; mocked verification; tests missing. |
