mod bft_consensus;
mod pythagorean_comma;
mod task_queue;
mod anfis_router;

use axum::{
    routing::{get, post},
    Router, Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use anfis_router::{AnfisInput, RoutingDecision};

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    service: String,
    version: String,
    modules: Vec<String>,
}

#[derive(Deserialize)]
struct BftEvaluateRequest {
    harm: f64,
    epistemic: f64,
    evidence: f64,
    scope: f64,
}

#[derive(Serialize)]
struct BftEvaluateResponse {
    dissonance: f64,
    vetoed: bool,
    result: String,
    unity_score: f64,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        service: "rust-brain".to_string(),
        version: "0.2.0".to_string(),
        modules: vec!["bft".to_string(), "anfis".to_string(), "veto".to_string()],
    })
}

async fn anfis_route(Json(payload): Json<AnfisInput>) -> Json<RoutingDecision> {
    let decision = anfis_router::route(payload);
    Json(decision)
}

async fn bft_evaluate(Json(payload): Json<BftEvaluateRequest>) -> Json<BftEvaluateResponse> {
    // d = (0.4×harm + 0.3×epistemic + 0.2×evidence + 0.1×scope) × (531441/524288)
    let raw = 0.4 * payload.harm + 0.3 * payload.epistemic + 0.2 * payload.evidence + 0.1 * payload.scope;
    let dissonance = raw * pythagorean_comma::PYTHAGOREAN_COMMA_RATIO;
    let vetoed = dissonance > 0.0195;
    let result = if vetoed { "HitlRequired" } else { "Approved" }.to_string();
    
    Json(BftEvaluateResponse {
        dissonance,
        vetoed,
        result,
        unity_score: 1.0 - dissonance,
    })
}

async fn veto_threshold() -> Json<Value> {
    Json(json!({
        "pythagorean_comma": pythagorean_comma::PYTHAGOREAN_COMMA_RATIO,
        "threshold": 0.0195,
        "constitutional_block": 0.48,
        "phi": 1.61803398875
    }))
}

#[tokio::main]
async fn main() {
    println!("TrustRails Rust-Brain starting...");
    
    let app = Router::new()
        .route("/health", get(health))
        .route("/anfis/route", post(anfis_route))
        .route("/bft/evaluate", post(bft_evaluate))
        .route("/veto/threshold", get(veto_threshold))
        .layer(CorsLayer::permissive());

    let port: u16 = std::env::var("PORT").unwrap_or_else(|_| "8081".into()).parse().unwrap_or(8081);
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await.unwrap();
    println!("Server running on port {}", port);
    
    axum::serve(listener, app).await.unwrap();
}
