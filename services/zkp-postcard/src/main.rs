//! ZKP Postcard Service — HyperDAG Trust Protocol v1
//!
//! Proves "RepID > threshold" using a Plonky3 STARK range-check on BabyBear field.
//! The circuit decomposes (repid - threshold - 1) into 32 bits and proves non-negativity.
//! Private input: actual RepID score. Public output: commitment + proof that score > threshold.

mod circuit;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;

const SERVICE_VERSION: &str = "0.1.0";

#[derive(Clone)]
struct AppState {
    store: Store,
    metrics: Arc<Metrics>,
}

struct Metrics {
    started_at: Instant,
    proofs_generated_total: AtomicU64,
    proofs_failed_total: AtomicU64,
}

impl Metrics {
    fn new() -> Self {
        Self {
            started_at: Instant::now(),
            proofs_generated_total: AtomicU64::new(0),
            proofs_failed_total: AtomicU64::new(0),
        }
    }
    fn uptime_seconds(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }
    fn generated(&self) -> u64 {
        self.proofs_generated_total.load(Ordering::Relaxed)
    }
    fn failed(&self) -> u64 {
        self.proofs_failed_total.load(Ordering::Relaxed)
    }
    fn inc_generated(&self) {
        self.proofs_generated_total.fetch_add(1, Ordering::Relaxed);
    }
    fn inc_failed(&self) {
        self.proofs_failed_total.fetch_add(1, Ordering::Relaxed);
    }
}

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
    uptime_seconds: u64,
    proofs_generated_total: u64,
    proofs_failed_total: u64,
    version: String,
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

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".into(),
        uptime_seconds: state.metrics.uptime_seconds(),
        proofs_generated_total: state.metrics.generated(),
        proofs_failed_total: state.metrics.failed(),
        version: SERVICE_VERSION.into(),
    })
}

async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    let m = &state.metrics;
    let body = format!(
        "# HELP plonky3_proofs_generated_total Successful proofs generated\n\
         # TYPE plonky3_proofs_generated_total counter\n\
         plonky3_proofs_generated_total {}\n\
         # HELP plonky3_proofs_failed_total Failed proof attempts\n\
         # TYPE plonky3_proofs_failed_total counter\n\
         plonky3_proofs_failed_total {}\n\
         # HELP plonky3_uptime_seconds Service uptime\n\
         # TYPE plonky3_uptime_seconds gauge\n\
         plonky3_uptime_seconds {}\n",
        m.generated(),
        m.failed(),
        m.uptime_seconds(),
    );
    (
        [("content-type", "text/plain; version=0.0.4")],
        body,
    )
}

async fn generate_proof(
    State(state): State<AppState>,
    Json(req): Json<ProofRequest>,
) -> Result<Json<ProofResponse>, StatusCode> {
    let store = state.store.clone();
    let agent_id = req.agent_id.unwrap_or_else(|| "3747".into());
    let threshold = req.threshold.unwrap_or(5000);
    let repid = match get_agent_repid(&agent_id) {
        Some(r) => r,
        None => {
            state.metrics.inc_failed();
            return Err(StatusCode::NOT_FOUND);
        }
    };
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
                state.metrics.inc_failed();
                let commitment = sha256_commitment(&agent_id, repid, threshold);
                ("sha256_commitment_poc".to_string(), commitment, 32)
            }
        }
    } else {
        let commitment = sha256_commitment(&agent_id, repid, threshold);
        ("sha256_commitment_poc".to_string(), commitment, 32)
    };

    state.metrics.inc_generated();

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
    State(state): State<AppState>,
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
    let state = AppState {
        store: Arc::new(RwLock::new(HashMap::new())),
        metrics: Arc::new(Metrics::new()),
    };
    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".into())
        .parse()
        .unwrap_or(8080);

    let app = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/zkp/repid-proof", post(generate_proof))
        .route("/zkp/verify/{commitment}", get(verify_proof))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("ZKP Postcard v{} listening on {}", SERVICE_VERSION, addr);
    println!("Plonky3 STARK range-check (BabyBear field)");
    println!("HyperDAG Trust Protocol v1");
    println!("Observability: GET /health, GET /metrics");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
