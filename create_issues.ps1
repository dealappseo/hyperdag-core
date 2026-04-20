gh issue create -R DealAppSeo/hyperdag-core --title "Improve epistemic_uncertainty: add logprob entropy support" --body "Currently epistemic_uncertainty uses hedge keyword density as a proxy
for the epistemic signal in HAL's 5-signal extractor.

For LLM providers that return logprobs (OpenAI, Anthropic, Google),
true token entropy can be computed:
  H = -Σ p(t) log p(t) over top-k tokens

Task:
- Add optional logprobs parameter to extractHALSignals()
- If provided: compute Shannon entropy, normalize to 0-1
- If not provided: fall back to current hedge density proxy
- Compare both methods on 20 TruthfulQA questions

File: repid-engine/src/services/hal-signals.ts

This would meaningfully improve the signal independence that LASSO
calibration depends on. All perspectives welcome — if you think
there is a better approach to epistemic uncertainty measurement,
please share it here. All perspectives welcome." --label "good first issue"

gh issue create -R DealAppSeo/hyperdag-core --title "Validate phyllotaxis rule placement vs uniform grid" --body "CommaANFIS uses phyllotaxis (golden angle 137.508°) for fuzzy
membership function center placement. The hypothesis is that this
reduces blind spots in the 5-dimensional signal space compared to
uniform grid partitioning.

This is currently an architectural choice without empirical validation.
We do not know if it actually helps.

Task:
- Implement uniform grid variant of CommaANFIS (baseline)
- Run both variants on 100 scored decisions
- Compare: false positive rate, false negative rate, PCDSS metric
- Report results in docs/PHYLLOTAXIS_VALIDATION.md

We genuinely do not know the answer here. If phyllotaxis does not
help, we should remove it. The math is elegant but elegance is
not the same as correctness. All perspectives welcome." --label "help wanted"

gh issue create -R DealAppSeo/hyperdag-core --title "Verify N ∈ {5,7,12} constraint for generalized comma formula" --body "The generalized Pythagorean Comma formula:
  C(N) = (3/2)^N / 2^k
  where k = floor(N × log₂(3/2) + 0.5)

produces operationally useful dissonance thresholds (|Δ(N)| < 0.10)
only at specific values of N. We have identified N ∈ {5,7,12} as
the constrained set that preserves the irrational gap property.

Task:
- Compute C(N) and |Δ(N)| for all N from 2 to 20
- Identify all N where |Δ(N)| < 0.10 (usable as threshold)
- Determine if there are values outside {5,7,12} that qualify
- Publish results as a table in docs/COMMA_ANALYSIS.md

This directly informs the LASSO pruning constraint — if additional
values of N qualify, we may be constraining unnecessarily.
All mathematical perspectives welcome."

gh issue create -R DealAppSeo/hyperdag-core --title "Wire 5-signal extractor into CommaANFIS forward pass" --body "Two components exist but are not yet connected:
1. hal-signals.ts: computes 5 independent HAL signals from claim text
2. anfis-comma.ts: runs CommaANFIS forward pass

Currently the score-event endpoint uses only certainty_at_claim
as the CommaANFIS input. This means the ANFIS has 5 input channels
but only 1 is independently populated.

Task:
- In the score-event handler, call extractHALSignals() when
  decision_text is present
- Pass the 5 signals as inputs to commaANFIS()
- Log both the individual signals and the final HAL score
- Update the Supabase score-event record to store signals in metadata

This is the foundational step for LASSO calibration. Without
independent signals, the threshold optimization cannot find a
meaningful decision boundary.

Files to modify:
- repid-engine/src/routes/agents.ts (or wherever score-event lives)
- repid-engine/src/services/anfis-comma.ts (accept 5-signal input)

All approaches welcome — if you have a better way to extract
domain signals from claim text, please suggest it. All perspectives welcome." --label "good first issue"

gh issue create -R DealAppSeo/hyperdag-core --title "Ethics layer design: measurement vs. definition" --body "The RepID ethics layer maps three principles to measurable signals:
- Micah 6:8 (act justly, love mercy, walk humbly) → Justice score
- Philippians 4:8 (true, honest, right, pure) → Truth score
- Matthew 7:12 (Golden Rule) → Reciprocity score

There is a deep design question here that we do not have a
settled answer to:

Is this a MEASUREMENT system (measuring how well agents approximate
ethical behavior as defined by humans) or a DEFINITION system
(defining what ethical behavior IS via mathematical scoring)?

If measurement: LASSO optimization of the weights is appropriate.
If definition: LASSO would allow the machine to define ethics by
optimizing for a metric — which is a category error with
significant implications.

Our current position: the weights are CONSTITUTIONAL (equal 1/3,
immutable without DAO vote) and are never LASSO-optimized. HAL
performance is tracked separately from ethics scores.

We are not certain this is right. We welcome perspectives from
ethicists, AI safety researchers, legal scholars, and anyone
who has thought carefully about this question.

This issue is intentionally open-ended. There is no assigned task.
We are looking for dialogue. All perspectives welcome." --label "help wanted"
