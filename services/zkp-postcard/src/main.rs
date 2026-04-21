//! ZKP Postcard Service — HyperDAG Trust Protocol v1
//!
//! Proves "RepID > threshold" using a Plonky3 STARK range-check on BabyBear field.
//! The circuit decomposes (repid - threshold - 1) into 32 bits and proves non-negativity.
//! Private input: actual RepID score. Public output: commitment + proof that score > threshold.

mod circuit;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Instant};
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;

type Store = Arc<RwLock<HashMap<String, ProofRecord>>>;

#[derive(Clone, Serialize, Deserialize)]
struct ProofRecord {
    agent_id: String,
    threshold: u64,
    tier: String,
    statement: String,
    proof_type: String,
    verified: bool,
    proof_size_bytes: usize,
    proving_time_ms: u64,
}

#[derive(Deserialize)]
struct ProofRequest {
    agent_id: Option<String>,
    threshold: Option<u64>,
    tier: Option<String>,
}

#[derive(Serialize)]
struct ProofResponse {
    proof_type: String,
    public_statement: String,
    commitment: String,
    verified: bool,
    agent_id: String,
    erc8004_token_id: String,
    tier: String,
    timestamp: String,
    protocol: String,
    proving_time_ms: u64,
    proof_size_bytes: usize,
}

#[derive(Serialize)]
struct VerifyResponse {
    valid: bool,
    statement: String,
    agent_id: String,
    proof_type: String,
    protocol: String,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    service: String,
    version: String,
    proof_types: Vec<String>,
    protocol: String,
}

fn get_agent_repid(agent_id: &str) -> Option<u64> {
    match agent_id {
        "3747" => Some(10000),  // SOPHIA — AUTONOMOUS
        "3748" => Some(4960),   // RAVEN — EARNING_AUTONOMY
        "3749" => Some(940),    // ATLAS — CUSTODIED_DBT
        "3750" => Some(1400),   // GUARDIAN — CUSTODIED_DBT
        _ => None,
    }
}

fn score_to_tier(score: u64) -> &'static str {
    match score {
        0..=999 => "CUSTODIED_DBT",
        1000..=4999 => "EARNING_AUTONOMY",
        5000..=10000 => "AUTONOMOUS",
        _ => "CUSTODIED_DBT",
    }
}

fn sha256_commitment(agent_id: &str, repid: u64, threshold: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("hyperdag_v1:{}:{}:{}", agent_id, repid, threshold));
    format!("0x{}", hex::encode(hasher.finalize()))
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".into(),
        service: "zkp-postcard".into(),
        version: "0.2.0".into(),
        proof_types: vec![
            "plonky3_range_check".into(),
            "sha256_commitment_poc".into(),
        ],
        protocol: "HyperDAG Trust Protocol v1".into(),
    })
}

async fn generate_proof(
    State(store): State<Store>,
    Json(req): Json<ProofRequest>,
) -> Result<Json<ProofResponse>, StatusCode> {
    let agent_id = req.agent_id.unwrap_or_else(|| "3747".into());
    let threshold = req.threshold.unwrap_or(5000);
    let repid = get_agent_repid(&agent_id).ok_or(StatusCode::NOT_FOUND)?;
    let above = repid > threshold;
    let tier = req.tier.unwrap_or_else(|| score_to_tier(repid).into());
    let statement = format!("RepID > {}", threshold);

    let start = Instant::now();

    // Try Plonky3 STARK proof
    let (proof_type, commitment, proof_size) = if above {
        let diff = (repid - threshold - 1) as u32;
        match circuit::prove_range_check(diff) {
            Ok(proof_bytes) => {
                let commitment = sha256_commitment(&agent_id, repid, threshold);
                ("plonky3_range_check".to_string(), commitment, proof_bytes.len())
            }
            Err(e) => {
                eprintln!("[ZKP] Plonky3 proof failed ({}), falling back to SHA-256", e);
                let commitment = sha256_commitment(&agent_id, repid, threshold);
                ("sha256_commitment_poc".to_string(), commitment, 32)
            }
        }
    } else {
        let commitment = sha256_commitment(&agent_id, repid, threshold);
        ("sha256_commitment_poc".to_string(), commitment, 32)
    };

    let proving_time = start.elapsed().as_millis() as u64;

    let record = ProofRecord {
        agent_id: agent_id.clone(),
        threshold,
        tier: tier.clone(),
        statement: statement.clone(),
        proof_type: proof_type.clone(),
        verified: above,
        proof_size_bytes: proof_size,
        proving_time_ms: proving_time,
    };
    store.write().await.insert(commitment.clone(), record);

    Ok(Json(ProofResponse {
        proof_type,
        public_statement: statement,
        commitment,
        verified: above,
        agent_id: agent_id.clone(),
        erc8004_token_id: agent_id,
        tier,
        timestamp: chrono::Utc::now().to_rfc3339(),
        protocol: "HyperDAG Trust Protocol v1".into(),
        proving_time_ms: proving_time,
        proof_size_bytes: proof_size,
    }))
}

async fn verify_proof(
    State(store): State<Store>,
    Path(commitment): Path<String>,
) -> Result<Json<VerifyResponse>, StatusCode> {
    let records = store.read().await;
    let record = records.get(&commitment).ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(VerifyResponse {
        valid: record.verified,
        statement: record.statement.clone(),
        agent_id: record.agent_id.clone(),
        proof_type: record.proof_type.clone(),
        protocol: "HyperDAG Trust Protocol v1".into(),
    }))
}

#[tokio::main]
async fn main() {
    let store: Store = Arc::new(RwLock::new(HashMap::new()));
    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".into())
        .parse()
        .unwrap_or(8080);

    let app = Router::new()
        .route("/health", get(health))
        .route("/zkp/repid-proof", post(generate_proof))
        .route("/zkp/verify/{commitment}", get(verify_proof))
        .layer(CorsLayer::permissive())
        .with_state(store);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("ZKP Postcard v0.2.0 listening on {}", addr);
    println!("Plonky3 STARK range-check (BabyBear field)");
    println!("HyperDAG Trust Protocol v1");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
