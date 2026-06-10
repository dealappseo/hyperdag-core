# Contributing to HyperDAG core (ZKP tier)

This is a real cryptographic protocol with **honest edges**. We don't hide what isn't built yet — we
point at it. Everything below is a runnable frontier: the current state is in the tree, the gap is
named, and there's a test that tells you the moment you've closed it.

## Ground rules

- **Pinned prover, one pin.** All Plonky3 deps are pinned to `27d59f7350daf6b02d11b01c3a55af453554b515`
  (BabyBear). A mismatched pin cannot verify. Don't bump it in isolation — it moves in lockstep across
  `services/zkp-postcard` and `services/babybear-leaf` (CANON P-026).
- **Golden KATs are tripwires, not suggestions.** `poseidon2_postcard_leaf` (`0x32ed1341`/`0x669d7ab7`)
  and the aggregation root (`0x5e8a02f1`) are frozen. If your change moves a hash or an encoding, a
  golden KAT will break the build on purpose — that's the aggregation-compatibility guard. Re-freeze
  intentionally, never silently.
- **No mock-as-real.** If a relation is checked at the witness level (recompute) rather than in-circuit,
  say so in the doc-comment. Every place we do this is already labeled; keep it that way.
- **Reproduce before you change.** `cd services/zkp-postcard && cargo test --release`. The corpus
  (`test_vectors/corpus.json`, 188 real proofs) regenerates **byte-identically** —
  `cargo test --release -- --include-ignored` runs `verify_corpus_full`. That's your "I reproduced it"
  baseline; your PR must keep it green (or re-freeze with evidence).

## The frontiers — good first issues (hard)

Each is a genuine open cryptography problem with a clear finish line. Pick one.

### 1. Proof-recursion: an in-AIR FRI verifier
- **File:** `services/zkp-postcard/src/recursion_spike.rs`
- **Current state (runnable):** a 2-level recursion *tree* — two real child batch-proofs are verified
  **natively** (host calls `verify_batch`), their roots are Poseidon2-folded, and a parent STARK binds
  the folded root. `two_proof_recursion_tree_verifies_e2e` passes. It is explicitly a **spike**: the
  children are checked by the host, not inside the parent AIR.
- **Open problem:** replace the native `verify_batch` calls with an **in-circuit FRI verifier** so the
  parent proof *alone* attests "both children are valid" — true proof-recursion (recursion-over-proofs,
  not recursion-over-data). This is the keystone for the AGGREGATION tier (recurse many leaves → one
  anchored root) in `ZKP_ARCHITECTURE_INVARIANTS`.
- **Done when:** the parent proof verifies the child FRI proofs as part of its own constraint system
  (no host-side `verify_batch`), and a tampered child proof makes the **parent** proof unverifiable.

### 2. Poseidon2-in-AIR: constrain the commitment/leaf opening
- **Files:** `services/zkp-postcard/src/letter.rs` (LETTER), `src/aggregate.rs` (PACKAGE)
- **Current state:** LETTER proves `repid > threshold` with `repid` a private witness and publishes
  `score_commitment = Poseidon2(repid, nonce)` — but the link "the commitment opens to the SAME `repid`
  the range check used" is **witness-level** (recompute to check), not an in-AIR constraint. PACKAGE has
  the same gap binding the in-trace `(repid_i, threshold_i)` to the in-leaf values.
- **Open problem:** implement the **Poseidon2 permutation as an AIR** (round constraints over BabyBear)
  and add a constraint that `pis[commitment] == Poseidon2(repid_witness, nonce_witness)`. Then the proof
  *itself* binds the hidden score to the published commitment — no trust in the issuer's recomputation.
- **Done when:** `letter.rs` constrains the opening in-circuit (a proof with a commitment that does NOT
  open to the witnessed `repid` fails), and the same AIR is reused to bind PACKAGE leaves to the root.
- **Note:** this also unlocks #1 (the in-AIR FRI verifier needs an in-AIR hash) and #4.

### 3. Transcript-binding V2: domain-separated, context-bound proofs
- **File:** `services/zkp-postcard/src/circuit.rs` (the Fiat-Shamir transcript in `prove_range_check`)
- **Current state:** the transcript observes the public statement (`agent_id`, `threshold`, `repid` or
  `commitment`, `epoch`). A proof is bound to its statement but **not** to a verification *context* — the
  same proof is valid against any verifier in any domain.
- **Open problem:** add a **domain-separation tag** + an optional **verifier-supplied nonce** into the
  transcript (per `ZKP_ARCHITECTURE_INVARIANTS` Invariant 3 — domain-parameterized verifier) so a proof
  is bound to a specific domain/vertical (ownership vs the future health vertical) and can't be replayed
  across contexts. Must stay lockstep with the WASM verifier (`hyperdag-proof-verifier`).
- **Done when:** a proof minted for domain A fails verification under domain B, with byte-identical
  encoding in prover + WASM verifier, and a golden KAT freezing the new transcript layout.

### 4. agent_id as a single hashed public input
- **File:** `services/zkp-postcard/src/circuit.rs` (`agent_id_to_16_bytes`, `build_public_values`)
- **Current state:** `agent_id` is bound as **16 raw bytes → 16 public values**; non-UUID ids are
  `sha256(id)[..16]` (a 128-bit binding, and a hash the circuit does not itself compute).
- **Open problem:** bind `agent_id` as a **single BabyBear field element via a hash-to-field** computed
  **in-AIR** (Poseidon2, depends on #2), and define the canonical hash-to-field for arbitrary agent ids
  (full-width, not truncated). Shrinks the public-input vector and makes the agent binding circuit-checked
  rather than host-supplied.
- **Done when:** `NUM_PUBLIC_VALUES` drops the 16-byte agent block for a single hashed felt, the in-AIR
  hash matches a frozen KAT, and `test_wrong_agent_id_fails_verification` still holds.

## How to verify your contribution

```bash
cd services/zkp-postcard
cargo test --release                      # all tiers: postcard, PACKAGE, LETTER, epoch, recursion-spike
cargo test --release -- --include-ignored # + full 188-proof corpus reproducibility (byte-identical)
```
Pin parity: every `p3-*` dep in `services/zkp-postcard/Cargo.toml` and `services/babybear-leaf/Cargo.toml`
must read `rev = "27d59f7350daf6b02d11b01c3a55af453554b515"`. If you touch a circuit, update the WASM
verifier (`github.com/DealAppSeo/hyperdag-proof-verifier`) in the same change — they are byte-lockstep.

Open a PR with: the test that proves the gap is closed, the golden KAT you (re-)froze, and a one-line
note on anything still checked at the witness level. Honesty about edges is the contribution standard.

*Apache-2.0. Build · test · prove. Micah 6:8.*
