# Risk scoring

Risk scoring in Mansa is a deterministic, auditable function of the
findings produced by the analysis rules. No external data, heuristics,
or randomness are involved.

## Per-finding score

Each finding is scored as:

```
risk = severity_weight × confidence × exposure_factor × 35
```

Where:

| Component          | Range    | How it is set                                        |
|--------------------|----------|------------------------------------------------------|
| `severity_weight`  | 0–4      | `critical`=4, `high`=3, `medium`=2, `low`=1, else 0 |
| `confidence`       | 0.0–1.0  | `confirmed`=1.0, `observed`=0.9, `probable`=0.7, `possible`=0.5, `unknown`=0.3, `not_observed`=0.0 |
| `exposure_factor`  | fixed    | `3.0` for all findings (RF exposure heuristic)       |

The raw result is capped at **100**.

## Aggregate risk

The session risk score is the arithmetic mean of the per-finding risk
scores:

```
risk = ⌊ Σ score(finding_i) / n_findings ⌋
```

When there are no findings, the risk score is 0.

## Risk level thresholds

| Score range | Risk level   |
|-------------|-------------|
| 80–100      | **critical** |
| 60–79       | **high**     |
| 35–59       | **medium**   |
| 1–34        | **low**      |
| 0           | **none**     |

The risk level is displayed on every summary and stored in
`session.risk_level`.

## Confirmation thresholds

Some operations — including full report generation — require the human
operator to confirm awareness when the session risk level is **high** or
**critical**. This prevents inadvertent exposure of sensitive
assessment data. See [Authorization](authorization.md) for the broader
confirmation model.

## Simulation behavior

The simulation dataset produces a consistent, non-zero risk profile.
Because the dataset is fixed, the risk score and level are identical
across all runs, making it suitable as a CI regression signal.

## Interpreting scores

A medium risk level means the session contained findings whose
severity and confidence profiles fall in the center of the weighted
scale. It does not necessarily indicate a vulnerability — it reflects
the aggregate posture of the observed environment as weighted by the
evidence available.

Next: [Sessions and evidence](sessions-and-evidence.md).