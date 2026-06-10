-- B-2 / Invariant 6 — add a domain namespace to zkp_circuits so identity/ownership (postcard),
-- selective-disclosure (letter), aggregation (package), and the future health vertical coexist in
-- one registry with no collisions. DRAFT — apply is Tier-2 (XC), via the single writer. Backfills
-- existing rows to 'postcard'.
--
-- Verified by B0/B-2: zkp_circuits exists (3 rows) and has NO domain column today; repid_zkp_proofs
-- holds 56,823 sha256-stub rows (scheme NULL) + 1 plonky3 row. The leaf migration starts a CLEAN
-- Poseidon2 lineage — legacy rows are MARKED, never rewritten.

ALTER TABLE zkp_circuits ADD COLUMN IF NOT EXISTS domain text NOT NULL DEFAULT 'postcard';
COMMENT ON COLUMN zkp_circuits.domain IS 'Circuit namespace: postcard|letter|package|health (Inv-6 — shared substrate, isolated data planes).';

-- Declare each proof row's leaf-hash lineage so Poseidon2 (aggregation-ready) is distinguishable
-- from the legacy sha256 commitments WITHOUT touching the legacy proofs.
ALTER TABLE repid_zkp_proofs ADD COLUMN IF NOT EXISTS leaf_scheme text;  -- 'poseidon2_babybear' (new) | 'legacy_sha256'
COMMENT ON COLUMN repid_zkp_proofs.leaf_scheme IS 'Leaf hash lineage (B-2, Inv-1): poseidon2_babybear = aggregation-ready; legacy_sha256 = pre-migration, not aggregatable.';

-- Store the aggregation leaf value itself. It is deterministic-by-design over the statement
-- {agent_id, threshold, repid_score} (that determinism is exactly what lets a future PACKAGE-tier
-- Plonky3 fold it) — so it is NOT the row's unique id (zk_commitment stays nonce-bound for that).
-- A single BabyBear field element, hex (e.g. '0x1a2b3c4d'). NULL for legacy sha256 rows.
ALTER TABLE repid_zkp_proofs ADD COLUMN IF NOT EXISTS poseidon2_leaf text;
COMMENT ON COLUMN repid_zkp_proofs.poseidon2_leaf IS 'Aggregation-ready Poseidon2/BabyBear leaf (B-2, Inv-1) over {agent_id,threshold,repid_score}; single felt hex; the value a PACKAGE-tier proof aggregates. NULL for legacy_sha256 rows.';

-- Mark the legacy sha256 rows (no proof rewrite — clean Poseidon2 lineage starts fresh):
UPDATE repid_zkp_proofs SET leaf_scheme = 'legacy_sha256' WHERE scheme IS NULL AND leaf_scheme IS NULL;
