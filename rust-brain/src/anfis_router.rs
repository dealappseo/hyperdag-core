use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct AnfisInput {
    pub task_complexity: f64,
    pub cost_sensitivity: f64,
    pub latency_requirement: f64,
    pub capability_required: f64,
}

#[derive(Serialize)]
pub struct RoutingDecision {
    pub provider: String,
    pub confidence: f64,
    pub reasoning: String,
    pub estimated_cost_per_1k: f64,
}

fn triangle_membership(x: f64, peak: f64, width: f64) -> f64 {
    let mut val = 1.0 - ((x - peak).abs() / width);
    if val < 0.0 { val = 0.0; }
    val
}

pub fn route(input: AnfisInput) -> RoutingDecision {
    // Fuzzification (Layer 1)
    let comp_low = triangle_membership(input.task_complexity, 0.0, 0.5);
    let comp_med = triangle_membership(input.task_complexity, 0.5, 0.5);
    let comp_high = triangle_membership(input.task_complexity, 1.0, 0.5);

    let lat_low = triangle_membership(input.latency_requirement, 0.0, 0.5);
    let lat_med = triangle_membership(input.latency_requirement, 0.5, 0.5);
    let lat_high = triangle_membership(input.latency_requirement, 1.0, 0.5);

    let cost_low = triangle_membership(input.cost_sensitivity, 0.0, 0.5);
    let cost_med = triangle_membership(input.cost_sensitivity, 0.5, 0.5);
    let cost_high = triangle_membership(input.cost_sensitivity, 1.0, 0.5);

    let cap_low = triangle_membership(input.capability_required, 0.0, 0.5);
    let cap_med = triangle_membership(input.capability_required, 0.5, 0.5);
    let cap_high = triangle_membership(input.capability_required, 1.0, 0.5);

    // Rule Strength (Layer 2)
    // 1: IF complexity=LOW AND latency=HIGH -> groq
    let score_groq = comp_low * lat_high;
    
    // 2: IF complexity=MEDIUM AND cost=HIGH -> deepseek
    let score_deepseek = comp_med * cost_high;
    
    // 3: IF complexity=HIGH AND capability=HIGH -> anthropic
    let score_anthropic = comp_high * cap_high;
    
    // 4: IF complexity=HIGH AND latency=HIGH -> cerebras
    let score_cerebras = comp_high * lat_high;

    // Determine max rule (simplified output layer)
    let mut best_score = 0.0001; // fallback threshold
    let mut provider = "openrouter".to_string();
    let mut reasoning = "Fallback to openrouter".to_string();
    let mut estimated_cost = 0.001;

    if score_groq > best_score {
        best_score = score_groq;
        provider = "groq".to_string();
        reasoning = "Low complexity + high latency requirement -> groq".to_string();
        estimated_cost = 0.0; // free tier
    }
    if score_deepseek > best_score {
        best_score = score_deepseek;
        provider = "deepseek".to_string();
        reasoning = "Medium complexity + high cost sensitivity -> deepseek".to_string();
        estimated_cost = 0.0002;
    }
    if score_anthropic > best_score {
        best_score = score_anthropic;
        provider = "anthropic".to_string();
        reasoning = "High complexity + high capability -> anthropic".to_string();
        estimated_cost = 0.003;
    }
    if score_cerebras > best_score {
        best_score = score_cerebras;
        provider = "cerebras".to_string();
        reasoning = "High complexity + high latency constraint -> cerebras".to_string();
        estimated_cost = 0.0015;
    }

    RoutingDecision {
        provider,
        confidence: best_score, // simplified normalization for this version
        reasoning,
        estimated_cost_per_1k: estimated_cost,
    }
}
