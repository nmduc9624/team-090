# Validation Report

- Case count: 120
- Unique case IDs: 120
- Unique alert IDs: 120
- RAG playbooks: 12
- Shared RAG docs: 5

## Incident Distribution

| Incident type | Count |
| --- | --- |
| Suspicious Login / Brute Force | 30 |
| Phishing Email | 30 |
| Malware / EDR Alert | 30 |
| Suspicious Outbound Connection | 30 |

## Source Distribution

| Source file | Count |
| --- | --- |
| data_duc.docx | 40 |
| data_tuan.docx | 40 |
| curated_supplemental_cases | 40 |

## Severity Distribution

| Severity | Count |
| --- | --- |
| High | 53 |
| Medium | 46 |
| Low | 9 |
| Critical | 12 |

## Remaining Gap Against Original Data Plan

The current normalized set contains 120 cases, matching the original memory/data plan: 80 train/demo seed cases and 40 curated test_gold cases.

## Split Distribution

| Split | Count |
| --- | --- |
| train_demo_seed | 80 |
| test_gold | 40 |

## TP/FP Assessment Distribution

| Assessment | Count |
| --- | --- |
| likely_true_positive | 65 |
| inconclusive | 44 |
| needs_validation_possible_false_positive | 11 |

## Benign / False Positive Coverage

- Count: 11
- Cases: PHISH-N05, PHISH-N09, LOGIN-T02, LOGIN-T06, LOGIN-T10, PHISH-T02, PHISH-T06, EDR-T02, EDR-T08, NET-T02, NET-T06

## Edge Case Coverage

- Count: 8
- Cases: LOGIN-T03, LOGIN-T04, LOGIN-T07, PHISH-T08, EDR-T06, EDR-T10, NET-T09, NET-T10

## Issues

- No blocking schema issues found.