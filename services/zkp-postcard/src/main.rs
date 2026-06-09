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
use base64::Engine;

struct AppState {
    store: Arc<RwLock<HashMap<String, ProofRecord>>>,
    http_client: reqwest::Client,
    supabase_url: String,
    supabase_key: String,
}

type SharedState = Arc<AppState>;

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
    requester_pubkey: Option<String>,
    tier: Option<String>,
    timestamp: Option<u64>,
    threshold: Option<u64>,
    repid_score: Option<u64>,
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
    proof_bytes: String,
    // Phase 3 fields
    repid_score_actual: u64,
    repid_score_supplied: Option<u64>,
    score_source: String,
    // 0.3.0 freshness — the authoritative epoch bound into the proof + where it came from.
    epoch: u64,
    epoch_source: String,
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

async fn fetch_agent_repid(
    state: &SharedState,
    agent_id: &str,
) -> Result<(u64, String), StatusCode> {
    // Check if agent_id is a UUID or a legacy numeric ID
    // If it's 3747, 3748, etc., we might need to map it or it might be in the 'id' column as UUID-equivalent
    // The sample showed 'id' is UUID.
    
    let url = format!("{}/rest/v1/repid_agents?id=eq.{}&select=current_repid,tier", state.supabase_url, agent_id);
    
    let res = state.http_client
        .get(&url)
        .header("apikey", &state.supabase_key)
        .header("Authorization", format!("Bearer {}", state.supabase_key))
        .send()
        .await
        .map_err(|e| {
            eprintln!("[ZKP] Supabase request failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if res.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(StatusCode::NOT_FOUND);
    }

    let agents: Vec<serde_json::Value> = res.json().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let agent = agents.first().ok_or(StatusCode::NOT_FOUND)?;

    let score = agent["current_repid"].as_u64().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let tier = agent["tier"].as_str().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?.to_string();

    Ok((score, tier))
}

fn score_to_tier(score: u64) -> &'static str {
    match score {
        0..=499 => "PROBATIONARY",
        500..=999 => "EARNING",
        1000..=4999 => "ESTABLISHED",
        5000..=7999 => "AUTONOMOUS",
        8000..=10000 => "VETERAN",
        _ => "PROBATIONARY",
    }
}

fn tier_to_threshold(tier: &str) -> Result<u64, &'static str> {
    match tier {
        "PROBATIONARY" => Ok(0),
        "EARNING" => Ok(499),
        "ESTABLISHED" => Ok(999),
        "AUTONOMOUS" => Ok(4999),
        "VETERAN" => Ok(7999),
        "CUSTODIED_DBT" | "EARNING_AUTONOMY" => Err("Obsolete tier nomenclature"),
        _ => Err("Unknown tier"),
    }
}

fn sha256_commitment(agent_id: &str, repid: u64, threshold: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("hyperdag_v1:{}:{}:{}", agent_id, repid, threshold));
    format!("0x{}", hex::encode(hasher.finalize()))
}

const DEFAULT_EPOCH_RPC: &str = "https://sepolia.base.org";

/// Fetch the AUTHORITATIVE freshness epoch from chain (Base Sepolia block height):
/// `epoch = block_height / EPOCH_BLOCKS` (a coarse window so brief lag/reorgs don't shift it).
/// NEVER derived from agent input. Returns (epoch, source). Fail-closed: an error here blocks proof
/// minting — better no proof than a proof that isn't freshness-bound. Configurable via EPOCH_RPC_URL
/// and EPOCH_BLOCKS.
async fn fetch_authoritative_epoch(state: &SharedState) -> Result<(u64, String), String> {
    let rpc = std::env::var("EPOCH_RPC_URL").unwrap_or_else(|_| DEFAULT_EPOCH_RPC.to_string());
    let epoch_blocks: u64 = std::env::var("EPOCH_BLOCKS")
        .ok().and_then(|s| s.parse().ok()).filter(|n| *n > 0).unwrap_or(300);
    let body = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": [] });
    let res = state.http_client.post(&rpc).json(&body)
        .timeout(std::time::Duration::from_secs(8)).send().await
        .map_err(|e| format!("epoch rpc request failed: {}", e))?;
    let j: serde_json::Value = res.json().await.map_err(|e| format!("epoch rpc bad json: {}", e))?;
    let hexstr = j["result"].as_str().ok_or_else(|| "epoch rpc: missing result".to_string())?;
    let block = u64::from_str_radix(hexstr.trim_start_matches("0x"), 16)
        .map_err(|e| format!("epoch rpc: bad block hex: {}", e))?;
    Ok((block / epoch_blocks, format!("base-sepolia:block/{}", epoch_blocks)))
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".into(),
        service: "zkp-postcard".into(),
        version: "0.3.0".into(),
        proof_types: vec![
            "plonky3_range_check".into(),
            "sha256_commitment_poc".into(),
        ],
        protocol: "HyperDAG Trust Protocol v1".into(),
    })
}

async fn generate_proof(
    State(state): State<SharedState>,
    Json(req): Json<ProofRequest>,
) -> Result<Json<ProofResponse>, (StatusCode, Json<serde_json::Value>)> {
    let agent_id = match req.agent_id.clone() {
        Some(id) => id,
        None => return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "missing_agent_id" })))),
    };
    
    if req.repid_score.is_some() {
        println!("[ZKP] client_supplied_score={:?} ignored, using server-side lookup", req.repid_score);
    }

    // Server-side lookup
    let (repid, actual_tier) = fetch_agent_repid(&state, &agent_id).await.map_err(|status| {
        if status == StatusCode::NOT_FOUND {
            (StatusCode::NOT_FOUND, Json(serde_json::json!({
                "error": "agent_not_found",
                "agent_id": agent_id
            })))
        } else {
            (status, Json(serde_json::json!({ "error": "internal_error" })))
        }
    })?;

    let tier = req.tier.clone().unwrap_or(actual_tier);
    
    let threshold = match req.threshold {
        Some(t) => t,
        None => tier_to_threshold(&tier).map_err(|_| (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "invalid_tier" }))))?,
    };
    let above = repid > threshold;

    // 0.3.0 FRESHNESS: bind an AUTHORITATIVE epoch (block-height-derived) into the proof. The agent's
    // own `timestamp` field is IGNORED — letting the agent pick the epoch would defeat replay-across-
    // time (they'd post-date a proof). Fail-closed: no authoritative epoch → no proof.
    if req.timestamp.is_some() {
        println!("[ZKP] client-supplied timestamp ignored — epoch is authoritative (block-height-derived)");
    }
    let (epoch, epoch_source) = fetch_authoritative_epoch(&state).await.map_err(|e| {
        (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "error": "epoch_unavailable", "detail": e })))
    })?;

    let statement = format!("RepID > {} @ epoch {}", threshold, epoch);

    let start = Instant::now();

    // Try Plonky3 STARK proof
    let (proof_type, commitment, proof_bytes) = if above {
        let diff = (repid - threshold - 1) as u32;
        // Agent-bound + freshness-bound proof: public tuple {agent_id, threshold, repid_score, epoch}.
        match circuit::prove_range_check(diff, &agent_id, threshold, repid, epoch) {
            Ok(bytes) => {
                let commitment = sha256_commitment(&agent_id, repid, threshold);
                ("plonky3_range_check".to_string(), commitment, bytes)
            }
            Err(e) => {
                eprintln!("[ZKP] Plonky3 proof failed ({}), falling back to SHA-256", e);
                let commitment = sha256_commitment(&agent_id, repid, threshold);
                ("sha256_commitment_poc".to_string(), commitment, "sha256_fallback_placeholder".as_bytes().to_vec())
            }
        }
    } else {
        let commitment = sha256_commitment(&agent_id, repid, threshold);
        ("sha256_commitment_poc".to_string(), commitment, "not_above_threshold".as_bytes().to_vec())
    };

    let proof_size = proof_bytes.len();
    let proof_bytes_str = base64::engine::general_purpose::STANDARD.encode(&proof_bytes);

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
    state.store.write().await.insert(commitment.clone(), record);

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
        proof_bytes: proof_bytes_str,
        repid_score_actual: repid,
        repid_score_supplied: req.repid_score,
        score_source: "server_side_lookup".into(),
        epoch,
        epoch_source,
    }))
}

async fn verify_proof(
    State(state): State<SharedState>,
    Path(commitment): Path<String>,
) -> Result<Json<VerifyResponse>, StatusCode> {
    let records = state.store.read().await;
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
    let store = Arc::new(RwLock::new(HashMap::new()));
    let http_client = reqwest::Client::new();
    
    let supabase_url = std::env::var("SUPABASE_URL")
        .expect("SUPABASE_URL must be set");
    let supabase_key = std::env::var("SUPABASE_SERVICE_KEY")
        .or_else(|_| std::env::var("SUPABASE_SERVICE_ROLE_KEY"))
        .expect("SUPABASE_SERVICE_KEY or SUPABASE_SERVICE_ROLE_KEY must be set");

    let state = Arc::new(AppState {
        store,
        http_client,
        supabase_url,
        supabase_key,
    });

    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".into())
        .parse()
        .unwrap_or(8080);

    let app = Router::new()
        .route("/health", get(health))
        .route("/zkp/repid-proof", post(generate_proof))
        .route("/prove/trade_auth", post(generate_proof))
        .route("/zkp/verify/{commitment}", get(verify_proof))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("ZKP Postcard v0.2.0 listening on {}", addr);
    println!("Plonky3 STARK range-check (BabyBear field)");
    println!("HyperDAG Trust Protocol v1");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
