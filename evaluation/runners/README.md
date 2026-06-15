# Evaluation Runner

This folder contains the MVP evaluation runner for the AI Threat Intel to Hunt Package Assistant.

## What it checks

The runner reads every report in:

```text
evaluation/datasets/threat_reports
```

For each case, it runs the backend analyzer and compares the generated hunt package with:

```text
evaluation/datasets/expected_hunt_packages
```

It measures:

- analyzer success/failure
- schema validity
- required field completeness
- telemetry recall
- MITRE technique recall
- IOC recall
- behavior overlap
- query draft count
- weak-case reasons

## Run

From the project root:

```powershell
cd D:\AI20k\team-090
.\backend\.venv\Scripts\python.exe .\evaluation\runners\run_mvp_evaluation.py
```

Quick smoke test:

```powershell
.\backend\.venv\Scripts\python.exe .\evaluation\runners\run_mvp_evaluation.py --limit 5
```

## Output

Each run writes files under:

```text
evaluation/runs/<timestamp>
```

Generated files:

- `summary.json`
- `case_results.json`
- `case_results.csv`
- `report.md`
- `generated_hunt_packages/*.json`

Runtime outputs are ignored by git through `.gitignore`.
