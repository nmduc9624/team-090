# Gold Standard Rubric

The final app should be evaluated with a rubric, not only a flat accuracy score. The goal is to check whether a generated hunt package is technically correct, useful for a SOC junior, and safe enough to drive warning/ask-for-help workflows.

## Required gates

- Output must be schema-valid.
- Critical cases fail if the primary intent, primary telemetry, primary MITRE family, or selected query domain is wrong.
- The output must not include blocked wrong-domain concepts from the golden case matrix.
- Query drafts are judged as draft guidance; Generic, KQL, SPL, or Sigma are acceptable if the domain and fields are correct.
- Warning output is only a draft and must require analyst confirmation.
- Recommended response must not claim that disruptive actions were already performed.

## Rubric dimensions

Each dimension is scored from 1 to 5.

| Dimension | What good looks like |
|---|---|
| Intent correctness | The package stays on the correct technical subcategory, not only the broad category. |
| MITRE relevance | MITRE techniques match the behavior and avoid unrelated techniques. |
| Telemetry relevance | Required telemetry points analysts to the right log sources without wrong-domain noise. |
| Query usefulness | Query drafts or generic query logic match the alert intent and expected telemetry. |
| Investigation flow quality | Steps are ordered, actionable, and understandable for a SOC junior. |
| Priority action quality | First actions reduce risk/uncertainty and avoid premature destructive actions. |
| False positive handling | Benign/approved activity checks are practical and specific to the alert. |
| Warning appropriateness | Warning preview is sent only when useful, tags the right role, and requires confirmation. |
| Junior readability | Output is concise, explainable, and not buried in noisy repeated checklist items. |
| Hallucination/noise control | The package avoids blocked MITRE, telemetry, queries, and unrelated scenario details. |

## Severity thresholds

| Severity | Minimum rubric score |
|---|---:|
| Critical | 4.60 / 5 |
| High | 4.40 / 5 |
| Medium/High | 4.25 / 5 |
| Medium | 4.00 / 5 |

## Golden datasets

- `evaluation/datasets/gold_standard/cases/`: hand-authored external variants for generalization checks.
- `evaluation/datasets/gold_standard/golden_case_matrix.json`: representative case matrix used by the automated rubric runner.

The matrix contains expected MITRE, telemetry, query keywords, blocked wrong-domain terms, priority topics, false-positive topics, and warning expectations.
