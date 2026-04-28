## HyperDAG Protocol — Ethical Trust Layer for the Agentic Economy

AI agents are entering the economy. They will make financial
recommendations, legal analyses, compliance assessments. The
infrastructure for agent IDENTITY is emerging. The infrastructure
for TRUST — verifiable behavioral reputation that cannot be
transferred or gamed — does not yet exist at scale.

This repository is our working attempt to build that layer.

We are not claiming to have the answers. We are publishing our
working methodology and asking the community to help improve it.
Ideas for or against our approach are equally welcome.
Contributions of any kind are always appreciated.

**What this is:**
A protocol and standard, not a product. Open source. Open methodology.
Grounded in mathematical constants (Pythagorean Comma), constitutional
ethics (Micah 6:8, Philippians 4:8, Golden Rule), and verifiable
on-chain reputation (ERC standards compatible).

**Current status:**
| Metric | Value |
|--------|-------|
| Production decisions scored | 316 |
| Total system vetoes | 361 |
| ZKP vetoes | 298 |
| CLAIM_REJECTED verdicts | 3 |
| Agent-layer catches | 60 |
| False positive vetoes | 0 |
| ERC-compatible agents on-chain | 4 |
| TruthfulQA F1 (baseline) | [run April 2026] |

**ZKP Circuit Status — read this section honestly:**

The trade authorization (`trade_auth`) and linked atomic settlement (`linked_bet`) circuits are implemented in Plonky3 Rust. They enforce quadratic stake math and one-way settlement valves at the constraint level. The Rust prover runs locally via an Axum HTTP bridge and produces real Plonky3 STARK proofs for both circuits.

What is **not** yet production-grade:

- **Production runtime falls back to an HMAC stub when the Plonky3 prover bridge is unavailable.** This is intentional during Reponomics rollout — a missing prover should not stop a demo round — but the fallback is **not** zero-knowledge. Every API response that contains a proof carries a `proof_source` field set to either `"plonky3"` or `"hmac_fallback"`, so callers can verify they got what they wanted. Do not treat an `hmac_fallback` proof as an attestation of anything.
- **In-circuit Poseidon2 commitment verification is blocked on Plonky3 upstream.** The `p3-uni-stark` single-table prover does not support the lookup arguments we need to verify a Poseidon2 commitment alongside the rest of the constraint set. The migration to `p3-multi-stark` (multi-table with cross-table lookups) is the unblocker. Until it lands, commitment verification is performed out-of-circuit by the trusted prover service.
- **CI benchmarks are deferred** due to runner disk-space constraints (`os error 112` on the Plonky3 build). Local proving works; CI does not yet exercise it.

What this means in practice: the cryptography in the demo is real when the prover is up; the API never lies about which one produced the proof; the proof you see is the proof we got.

**Links:**
[Read the methodology →](METHODOLOGY.md)
[View live benchmark →](https://trustrepid.dev/hal)
[Reproduce the benchmark →](docs/BENCHMARK_RESULTS.md)
[Custodian accountability →](docs/CUSTODIAN_ACCOUNTABILITY.md)
[Open an issue →](https://github.com/DealAppSeo/hyperdag-core/issues)

---

## Technical Stack

**Core infrastructure:**
- Rust — performance-critical services, ZKP proof generation
- Plonky3 — STARK-based zero-knowledge proofs (BabyBear field,
  Poseidon2 hash, no trusted setup required)
- TypeScript/Node.js — API layer, agent runtime
- Python — ANFIS training, signal processing (py-brain)

**Privacy architecture:**
ZKP (zero-knowledge proofs) are the cryptographic bridge
between human custodians and AI agents. A custodian's identity
is never publicly revealed — only a ZKP proof of their
accountability tier is on-chain. Identity is disclosed only
under defined conditions (see
[docs/CUSTODIAN_ACCOUNTABILITY.md](docs/CUSTODIAN_ACCOUNTABILITY.md)).

**Why Rust + Plonky3:**
Plonky3 STARKs provide post-quantum security with no trusted
setup. The proving system runs in Rust for the performance
required to generate proofs at production decision latency.
The zkp-postcard service (`hyperdag-core/services/zkp-postcard`)
implements this in production.

---

*Contributions, critiques, and alternative approaches are welcome.*
*This work is better with more perspectives, not fewer.*
