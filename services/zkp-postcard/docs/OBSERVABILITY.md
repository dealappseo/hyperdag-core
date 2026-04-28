# Plonky3 prover observability

The Axum service exposes two unauthenticated read-only endpoints for
liveness and metrics. Both are O(1) and never touch the proof store.

## `GET /health`

JSON, intended for load balancers, the TS bridge's pre-flight cache,
and humans.

```json
{
  "status": "ok",
  "uptime_seconds": 12847,
  "proofs_generated_total": 318,
  "proofs_failed_total": 4,
  "version": "0.1.0"
}
```

`status` is always `"ok"` while the process is up — Axum can't respond
otherwise. A non-`200` (or no response inside the timeout) is what
callers should treat as "down."

## `GET /metrics`

Prometheus exposition format. Same numbers as `/health`, in the format
Prometheus / Grafana / Railway scrape directly:

```
# HELP plonky3_proofs_generated_total Successful proofs generated
# TYPE plonky3_proofs_generated_total counter
plonky3_proofs_generated_total 318
# HELP plonky3_proofs_failed_total Failed proof attempts
# TYPE plonky3_proofs_failed_total counter
plonky3_proofs_failed_total 4
# HELP plonky3_uptime_seconds Service uptime
# TYPE plonky3_uptime_seconds gauge
plonky3_uptime_seconds 12847
```

`generated` and `failed` are atomic `u64` counters. They increment
inside the existing `generate_proof` handler — `generated` on every
successful Plonky3 STARK or SHA-256 commitment path, `failed` when
`get_agent_repid` returns `None` or the Plonky3 prover errors out and
the handler falls back to SHA-256.

## Scraping from Railway / Prometheus

1. Expose the prover service publicly (Railway domain) **or** keep it
   private and have only the repid-engine reach it via internal
   networking.
2. Add a Prometheus scrape config:

   ```yaml
   scrape_configs:
     - job_name: plonky3-prover
       scrape_interval: 30s
       metrics_path: /metrics
       static_configs:
         - targets: ['<prover-host>:8080']
   ```
3. The bridge in `repid-engine/src/zkp/plonky3-real.ts` queries
   `/health` (not `/metrics`) for its in-process pre-flight cache —
   `/metrics` is purely for external scraping.

## 60-second health cache rationale (TS bridge)

Every call to `generateProofReal()` would otherwise pay a TCP/HTTP
round-trip to `/health` before deciding whether to attempt a proof or
go straight to HMAC fallback. With proof rates of multiple per second,
that's wasteful. The cache:

- TTL: 60 seconds. Health doesn't flap on a sub-minute timescale; if
  it does, the cache misses force a re-check.
- Failure-mode: when `/health` is unreachable or non-200, the cached
  state is `{ healthy: false }`. Subsequent calls within 60s skip the
  proof attempt and go straight to HMAC fallback, avoiding the 5s
  proof timeout penalty on every request.
- First call after process start: pays the round-trip. After that,
  cached.
- Trade-off: if the prover starts up partway through a 60s window of
  cached "down", the bridge keeps using HMAC for up to 60s after the
  prover came up. Acceptable; the alternative is a hammer of failed
  prove calls.

## Counter semantics — what counts as "failed"

`proofs_failed_total` only increments on internal handler errors:

- Unknown `agent_id` (no canonical RepID in the in-process map).
- Plonky3 STARK prover returns `Err(...)`.

`/health` and `/metrics` calls do **not** affect counters — those are
read-only and free.

## Versioning

`SERVICE_VERSION` (currently `"0.1.0"`) lives as a `const` in
`services/zkp-postcard/src/main.rs`. Bump it in the same commit that
ships a behavior or schema change to either endpoint.
