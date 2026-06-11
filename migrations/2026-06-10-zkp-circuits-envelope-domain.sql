-- ENVELOPE tier — register the selective-disclosure circuit under Invariant 6 (domain namespace).
-- DRAFT / STAGED — apply is Tier-2 (single writer, Sean co-sign). Additive + idempotent; safe to run
-- before OR after 2026-06-08-zkp-circuits-domain.sql (it re-asserts the domain column defensively).
--
-- Verified against live prod 2026-06-10 [sql]: zkp_circuits has NO `domain` column yet (the 06-08
-- migration is still staged) and 3 rows (base/stewardship/conservatorship). Required NOT-NULL cols:
-- circuit_name, circuit_type, approximate_gates, proof_gen_time_ms, inputs(jsonb), outputs(jsonb),
-- privacy_guarantee, plain_english. This inserts ONE 'envelope' row, guarded so re-runs are no-ops.
--
-- NOTE on gates: the ENVELOPE primitive shipped in zkp-postcard/src/envelope.rs is COMMITMENT-based
-- (Poseidon2 field commitments + scoped nullifier + symmetric seal), not yet an in-AIR STARK — the
-- in-circuit Poseidon2 knowledge proof is the documented recursion-tier upgrade (same as LETTER). The
-- gate estimate below is for that future in-AIR version; it is labelled so it is not read as shipped.

-- 1) Ensure the Inv-6 domain namespace exists (idempotent; mirrors 2026-06-08-zkp-circuits-domain.sql).
ALTER TABLE zkp_circuits ADD COLUMN IF NOT EXISTS domain text NOT NULL DEFAULT 'postcard';
COMMENT ON COLUMN zkp_circuits.domain IS
  'Circuit namespace: postcard|envelope|letter|package|health (Inv-6 — shared substrate, isolated data planes).';

-- 2) Register the ENVELOPE circuit (guard against duplicate inserts on re-run).
INSERT INTO zkp_circuits
  (circuit_name, circuit_type, prover, approximate_gates, proof_gen_time_ms, recursive,
   inputs, outputs, privacy_guarantee, plain_english, domain)
SELECT
  'envelope_circuit',
  'selective_disclosure_proof',
  'plonky3',
  20000,   -- ESTIMATE for the future in-AIR Poseidon2 knowledge version; commitment primitive is lighter.
  1200,
  false,
  '{"private":["identity_secret","field_values","field_salts","recipient_key"],"public":["envelope_root","scoped_nullifier","recipient_id","domain","field_count"],"disclosed_subset":"owner-selected indices, sealed to recipient"}'::jsonb,
  '{"recipient_opens":["selected field (index,label,value)"],"hidden":["undisclosed field values"],"binds":["scoped nullifier (one-time, per-recipient)"]}'::jsonb,
  'The owner chooses WHICH fields to disclose and to WHOM. Disclosed values are sealed to one recipient; undisclosed fields are only Poseidon2 commitments in the public root (one-way). A scoped nullifier = Poseidon2(secret, recipient_id, domain) makes each envelope one-time and non-re-scopable. Eavesdropper-confidentiality of disclosed fields awaits the KEM upgrade (a pre-shared recipient key is used today).',
  'A digital envelope where you pick exactly which facts to show a specific recipient — like handing one person a card that reveals your membership tier and reputation but keeps your region and KYC level sealed. Only that recipient can open the shown fields; nobody learns the rest; and the envelope cannot be reused or handed to someone else.',
  'envelope'
WHERE NOT EXISTS (SELECT 1 FROM zkp_circuits WHERE circuit_name = 'envelope_circuit');
