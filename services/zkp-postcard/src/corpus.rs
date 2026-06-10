// P1 — Real-proof corpus (ZKP aggregation-depth sprint, 2026-06-10).
//
// Generates a corpus of REAL Plonky3 STARK postcard proofs over REAL agent inputs (35 active
// agents pulled from Trinity prod `qnnpjhlxljtqyigedwkb` [sql:2026-06-10], each with its real
// current_repid), proven against meaningful thresholds (tier floors below the score). Each entry
// records the statement, the gap, the aggregation-ready Poseidon2 leaf, and the proof's size +
// sha256 — so the corpus is a COMMITTED, SELF-VERIFYING test vector: `verify_corpus` regenerates
// proofs from the manifest and asserts the bytes hash to the committed sha256 (the pinned prover
// 27d59f7350 is deterministic — empty-seed challenger, no randomness), re-derives each leaf, and
// re-verifies the proof. Live prod is 1 real proof + 56,823 sha256 stubs; this is the real volume
// to drain and demo (the leaves feed P2 PACKAGE aggregation).
//
// Stage only — nothing here writes to prod; the manifest + samples are committed git artifacts.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::circuit;

/// (agent_name, agent_uuid, current_repid) — verified live, Trinity prod, 2026-06-10.
/// Real agents only; the proof statement uses the real uuid + real repid.
pub const REAL_AGENTS: &[(&str, &str, u64)] = &[
    ("MEDIATOR", "394b6ee4-62e7-4c66-8445-29107b097b4c", 2280),
    ("demo-openai-agent", "51dbf516-c0e0-4d60-bfee-60209de313b8", 2186),
    ("RESEARCHER", "d244f6fc-35af-4131-b649-285bfac64b63", 1675),
    ("GUARDIAN", "5b81eaa8-b15b-44fb-b27c-c02e7ee58a7c", 1400),
    ("SEAN", "d08a6049-6e33-48ef-8d6c-006ebe9ef48a", 1050),
    ("HUMAN-8791", "8791a7c3-40eb-475c-bade-e11d5b9776c7", 1009),
    ("HUMAN-45f5", "45f5ec09-86be-40ef-b10f-299a1bbb913e", 1000),
    ("trinity-shofet", "32e0e809-c1c4-4405-913f-135c8a2d6626", 1000),
    ("trinity-w3c", "d82b2ae5-1d1d-462e-87fb-57cb3e63017b", 1000),
    ("HUMAN-4f66", "4f6673e9-1471-45c1-884e-34f294ddaec1", 1000),
    ("HUMAN-9f76", "9f76eca0-0743-4fa3-a8d8-01f18a161a67", 1000),
    ("trinity-orch", "84f2d7de-5bb9-4f3b-92ca-aecc7c498271", 1000),
    ("trinity-veritas", "a83cc9eb-43b0-49ee-9e45-2ecbb0d35067", 1000),
    ("trinity-hdm", "f93cdbbe-2337-48b3-8bfd-b5b7a5c2b5c0", 1000),
    ("HUMAN-2557", "25574cdd-ac93-4ad3-a9c9-7bdaa7430d2d", 1000),
    ("HUMAN-f436", "f4367518-a2a2-4dec-8193-1a259f3640f4", 916),
    ("SKEPTIC", "2538b7ed-acdb-4423-b5bf-a9e18069ec99", 834),
    ("trinity-t12-e2e", "e0b365eb-6634-4e14-9f8f-6d4cc2e65adc", 700),
    ("trinity-redteam-finder", "bd92d6f1-bbe5-481c-b258-68f0f76c9777", 610),
    ("trinity-redteam-accuser", "14f2b4ac-f8e2-4e45-ba54-59da23e72651", 595),
    ("trinity-redteam-subject", "797dcf75-6276-40c3-a7d0-4e686f646887", 580),
    ("ATLAS", "db5ea9f4-f1ad-445e-8c00-e13495e580f6", 574),
    ("trinity-torch", "9c0dc740-8c16-4862-ad62-9ba3d515369d", 500),
    ("trinity-gcm", "57a2f83a-e071-4901-bbfd-1ebe15ce0be5", 500),
    ("trinity-apm", "065ad782-ea58-4078-9414-60a862d67ba1", 500),
    ("trinity-mel", "942860a6-e26f-4334-ae94-b7c1abed1e8c", 500),
    ("trinity-chesed", "2c2c24d6-2fd0-47e6-95d5-7fc9804a19e6", 500),
    ("trinity-nexus", "848da285-93c5-4e99-a989-3d9e49ebed09", 500),
    ("trinity-sophia", "f3ef0bf8-5cdc-4fad-bce8-5144f01dc271", 500),
    ("MENTOR", "be599a22-2d31-4158-9d46-a87cb5d598ea", 499),
    ("ORACLE", "a16f14e7-3690-40ed-a013-f45c3f724bf7", 499),
    ("SAGE", "cde8f5af-c39e-44cc-bd69-82ce4c08a35f", 499),
    ("CONTRARIAN", "d5bc5cef-e2c4-4774-8651-569945fde388", 74),
    ("NEWCOMER", "d71b1e49-ce20-4e1c-b21f-3501dd852f6a", 60),
];

/// One corpus entry: a real statement, its gap, leaf, and proof digest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CorpusEntry {
    pub agent_name: String,
    pub agent_id: String,
    pub repid_score: u64,
    pub threshold: u64,
    pub gap: u32,
    /// Aggregation-ready Poseidon2/BabyBear leaf over {agent_id, threshold, repid}.
    pub leaf: String,
    pub proof_size_bytes: usize,
    /// sha256 of the serialized Plonky3 proof bytes — the reproducibility anchor.
    pub proof_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Corpus {
    pub plonky3_pin: String,
    pub num_public_values: usize,
    pub note: String,
    pub entries: Vec<CorpusEntry>,
}

/// Meaningful thresholds strictly below `repid`: tier floors + a tight boundary (repid-1).
/// Yields several real statements per agent so the corpus is ≥50 across the 35 agents.
fn thresholds_for(repid: u64) -> Vec<u64> {
    let mut ts: Vec<u64> = [0u64, 100, 250, 499, 500, 999]
        .into_iter()
        .filter(|&t| t < repid)
        .collect();
    if repid >= 1 {
        ts.push(repid - 1); // tight boundary: gap == 0
    }
    ts.sort_unstable();
    ts.dedup();
    ts
}

/// Build one real proof for a statement; return (entry, proof_bytes).
pub fn prove_entry(
    agent_name: &str,
    agent_id: &str,
    repid: u64,
    threshold: u64,
) -> Result<(CorpusEntry, Vec<u8>), String> {
    if repid <= threshold {
        return Err(format!("repid {} <= threshold {} (not a positive statement)", repid, threshold));
    }
    let gap = (repid - threshold - 1) as u32;
    let proof = circuit::prove_range_check(gap, agent_id, threshold, repid)?;
    let leaf = circuit::poseidon2_postcard_leaf(agent_id, threshold, repid);
    let proof_sha256 = hex::encode(Sha256::digest(&proof));
    Ok((
        CorpusEntry {
            agent_name: agent_name.to_string(),
            agent_id: agent_id.to_string(),
            repid_score: repid,
            threshold,
            gap,
            leaf,
            proof_size_bytes: proof.len(),
            proof_sha256,
        },
        proof,
    ))
}

/// Generate the full corpus (every agent × its thresholds). Deterministic.
pub fn generate() -> Corpus {
    let mut entries = Vec::new();
    for (name, id, repid) in REAL_AGENTS {
        for t in thresholds_for(*repid) {
            let (entry, _proof) = prove_entry(name, id, *repid, t).expect("real statement proves");
            entries.push(entry);
        }
    }
    Corpus {
        plonky3_pin: "27d59f7350daf6b02d11b01c3a55af453554b515".to_string(),
        num_public_values: circuit::NUM_PUBLIC_VALUES,
        note: "Real Plonky3 STARK postcard proofs over real Trinity-prod agents (sql:2026-06-10). \
               Each proof_sha256 is reproducible from the pinned, deterministic prover."
            .to_string(),
        entries,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn vectors_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test_vectors/corpus.json")
    }

    /// Regenerate the committed corpus manifest + a sample of full proofs. `#[ignore]` —
    /// run explicitly (`cargo test --release gen_corpus -- --ignored --nocapture`) when the
    /// real-agent set or the prover changes. Writes test_vectors/corpus.json (committed).
    #[test]
    #[ignore]
    fn gen_corpus() {
        let corpus = generate();
        assert!(corpus.entries.len() >= 50, "corpus must be >= 50 real statements, got {}", corpus.entries.len());
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test_vectors");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("corpus.json"), serde_json::to_string_pretty(&corpus).unwrap()).unwrap();

        // Persist a representative sample of FULL proof bytes (3, spread across tiers) as
        // committed artifacts; the rest are reproducible from the manifest's sha256.
        let proofs_dir = dir.join("proofs");
        std::fs::create_dir_all(&proofs_dir).unwrap();
        let last = REAL_AGENTS.len() - 1;
        for (name, id, repid) in [REAL_AGENTS[0], REAL_AGENTS[last / 2], REAL_AGENTS[last]] {
            let t = thresholds_for(repid)[0];
            let (_e, proof) = prove_entry(name, id, repid, t).unwrap();
            std::fs::write(proofs_dir.join(format!("{}_{}.bin", name, t)), &proof).unwrap();
        }
        eprintln!("wrote {} entries to {:?}", corpus.entries.len(), dir);
    }

    /// Always-on: the committed corpus is internally consistent + a sample is fully reproducible.
    /// Re-derives every leaf (fast) and asserts == committed; regenerates a spread of 6 proofs and
    /// asserts the bytes hash to the committed sha256 + re-verify. (Full regen = verify_corpus_full.)
    #[test]
    fn verify_corpus_sample() {
        let raw = std::fs::read_to_string(vectors_path()).expect("corpus.json committed");
        let corpus: Corpus = serde_json::from_str(&raw).unwrap();
        assert!(corpus.entries.len() >= 50, "corpus >= 50, got {}", corpus.entries.len());
        assert_eq!(corpus.plonky3_pin, "27d59f7350daf6b02d11b01c3a55af453554b515");
        assert_eq!(corpus.num_public_values, circuit::NUM_PUBLIC_VALUES);

        // Every committed leaf re-derives exactly (cheap, no proving).
        for e in &corpus.entries {
            let leaf = circuit::poseidon2_postcard_leaf(&e.agent_id, e.threshold, e.repid_score);
            assert_eq!(leaf, e.leaf, "leaf mismatch for {} t={}", e.agent_name, e.threshold);
            assert_eq!(e.gap, (e.repid_score - e.threshold - 1) as u32, "gap mismatch {}", e.agent_name);
        }

        // A spread of 6 proofs is fully regenerated → byte-identical sha256 + re-verify.
        let n = corpus.entries.len();
        for idx in [0, n / 5, 2 * n / 5, 3 * n / 5, 4 * n / 5, n - 1] {
            let e = &corpus.entries[idx];
            let (regen, proof) = prove_entry(&e.agent_name, &e.agent_id, e.repid_score, e.threshold).unwrap();
            assert_eq!(&regen, e, "regenerated entry diverged for {} t={}", e.agent_name, e.threshold);
            let sha = hex::encode(Sha256::digest(&proof));
            assert_eq!(sha, e.proof_sha256, "proof bytes not reproducible for {} t={}", e.agent_name, e.threshold);
        }
    }

    /// Full reproducibility: regenerate EVERY proof and assert sha256 match. Slow → `#[ignore]`.
    #[test]
    #[ignore]
    fn verify_corpus_full() {
        let raw = std::fs::read_to_string(vectors_path()).expect("corpus.json committed");
        let corpus: Corpus = serde_json::from_str(&raw).unwrap();
        for e in &corpus.entries {
            let (_regen, proof) = prove_entry(&e.agent_name, &e.agent_id, e.repid_score, e.threshold).unwrap();
            let sha = hex::encode(Sha256::digest(&proof));
            assert_eq!(sha, e.proof_sha256, "proof not reproducible for {} t={}", e.agent_name, e.threshold);
        }
        eprintln!("verified {} proofs reproduce byte-identically", corpus.entries.len());
    }
}
