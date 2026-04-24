CREATE TABLE IF NOT EXISTS agent_custodianship (
    id bigint generated always as identity primary key,
    human_sbt_token_id text not null,
    human_sbt_chain text not null default 'base-sepolia',
    human_sbt_contract_address text not null,
    agent_erc8004_token_id numeric not null,
    agent_erc8004_chain text not null default 'base-sepolia',
    agent_erc8004_contract_address text not null default '0x8004A818BFB912233c491871b3d84c89A494BD9e',
    custodianship_proof_commitment text not null,
    proof_public_statement text,
    challenge_nonce text not null,
    signature text not null,
    signer_address text not null,
    onchain_anchor_tx_hash text,
    status text not null check (status in ('pending','active','revoked','transferred')),
    established_at timestamptz not null default now(),
    revoked_at timestamptz,
    transferred_to_sbt_token_id text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

CREATE INDEX idx_agent_custodianship_human_sbt ON agent_custodianship (human_sbt_token_id);
CREATE INDEX idx_agent_custodianship_agent_erc8004 ON agent_custodianship (agent_erc8004_token_id);
CREATE INDEX idx_agent_custodianship_status ON agent_custodianship (status);
CREATE UNIQUE INDEX uq_active_custodianship ON agent_custodianship (human_sbt_token_id, agent_erc8004_token_id) WHERE status = 'active';
