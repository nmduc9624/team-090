# MVP Final Check

Final verification date: 2026-06-14

## Completed Scope

- Root README updated with full app setup/run/evaluation guide.
- Root demo document added: `DEMO_FLOW.md`.
- Frontend MVP implemented with React/Vite.
- Backend sample-report APIs added for the frontend.
- Analyzer upgraded from mock keyword rules to hybrid retrieval + rules.
- 100-case alert catalog and evaluation dataset are available.
- 5 holdout reports were added outside the 100 curated reference cases.
- Evaluation runners are available for curated and holdout checks.
- Local cache/build metadata was cleaned and ignored where appropriate.

## Final Verification Commands

### Backend Tests

```powershell
cd D:\AI20k\team-090\backend
.\.venv\Scripts\python.exe -m pytest -q
```

Result:

```text
6 passed
```

### Frontend Build

```powershell
cd D:\AI20k\team-090\frontend
npm.cmd run build
```

Result:

```text
build passed
```

### 100-Case Evaluation

```powershell
cd D:\AI20k\team-090
.\backend\.venv\Scripts\python.exe .\evaluation\runners\run_mvp_evaluation.py
```

Latest run:

```text
Run ID: 20260614_231526
Total cases: 100
Analyzed successfully: 100
Failed: 0
Passed cases: 100
Weak cases: 0
Quality gate: passed
```

Report:

```text
evaluation/runs/20260614_231526/report.md
```

### Holdout Smoke Test

```powershell
cd D:\AI20k\team-090
.\backend\.venv\Scripts\python.exe .\evaluation\runners\run_holdout_smoke.py
```

Latest run:

```text
Run ID: holdout_20260614_231529
Total cases: 5
Passed cases: 5
Weak or failed cases: 0
Quality gate: passed
```

Report:

```text
evaluation/runs/holdout_20260614_231529/report.md
```

## MVP Result

The MVP is functionally complete for local demo:

- Backend runs locally.
- Frontend runs locally.
- Frontend can load sample reports and call backend analysis.
- Hybrid analyzer generates structured hunt packages.
- Curated 100-case evaluation passes.
- Holdout smoke test passes.

## Known Limitation

The 100-case evaluation uses curated reference data, so it validates MVP coverage for known scenarios. Holdout smoke tests add confidence for new wording, but production use still needs more external reports, analyst feedback, persistent storage, and LLM-backed generation with schema validation.
## Analyzer Upgrade Check - 2026-06-17

Reason:

- A new Slack/SaaS OAuth file export report was partially misclassified as Cloud IAM Admin Policy Attached.
- The old hybrid merge also pulled unrelated endpoint MITRE/query noise such as mshta, registry run key, and LSASS.

Changes:

- Retriever now uses intent-aware scoring for OAuth/SaaS/data-export reports.
- Analyzer now has SaaS/OAuth context guardrails.
- SaaS/OAuth reports are filtered to relevant telemetry and MITRE techniques.
- Query selector now ignores `*: none` indicator fields and avoids endpoint templates for SaaS-only reports.
- Added `saas_oauth_file_export_hunt.kql`.
- Added regression test for Slack OAuth file export.

Verification:

```text
Backend tests: 7 passed
Frontend build: passed
100-case evaluation run: 20260617_160632
100-case evaluation: 100/100 passed
Holdout smoke run: holdout_20260617_160630
Holdout smoke: 5/5 passed
```

Slack OAuth test output now returns:

```text
Telemetry: cloud_audit, auth, email_audit, proxy
MITRE: T1528, T1530, T1567.002, T1078
Queries: Oauth Consent Hunt, Saas Oauth File Export Hunt
No endpoint registry/mshta/LSASS query noise
```

## Developer Platform Guardrail Check - 2026-06-17

Reason:

- Developer platform OAuth abuse needs separate handling from generic SaaS OAuth.
- GitHub/GitLab reports may mention repository access, deploy keys, and secrets metadata.
- The analyzer should not pull endpoint-only noise such as mshta, registry run keys, LSASS, EDR registry, or EDR process queries.

Changes:

- Added Developer Platform OAuth behavior detection for GitHub, GitLab, repositories, deploy keys, and secrets metadata.
- Added MITRE mapping for repository access, deploy key creation, and secrets metadata access.
- Added developer-platform context guardrail to keep telemetry focused on `cloud_audit`, `auth`, and `proxy`.
- Added `developer_oauth_repo_access_hunt.kql`.
- Added regression test for GitHub OAuth repository access with deploy key and secrets metadata activity.

Verification:

```text
Backend tests: 8 passed
Frontend build: passed
100-case evaluation run: 20260617_163953
100-case evaluation: 100/100 passed
Holdout smoke run: holdout_20260617_163952
Holdout smoke: 5/5 passed
```

GitHub OAuth test output now returns:

```text
Telemetry: cloud_audit, auth, proxy
MITRE: T1528, T1098, T1552, T1530, T1078
Queries: Developer Oauth Repo Access Hunt, Oauth Consent Hunt, Saas Oauth File Export Hunt
No endpoint registry/mshta/LSASS query noise
```

## Deliverable Documentation Check - 2026-06-17

Completed artifacts:

- Architecture diagram: `docs/architecture/mvp_architecture.md`
- Manual evaluation evidence: `evaluation/manual_evidence/manual_test_cases_2026-06-17.md`
- PR merged evidence/checklist: `docs/repo/pr_merged_evidence.md`
- README setup, env vars, sample API queries, and artifact locations: `README.md`

Verification:

```text
Backend tests: 8 passed
Frontend build: passed
100-case evaluation run: 20260617_230731
100-case evaluation: 100/100 passed
Holdout smoke run: holdout_20260617_230731
Holdout smoke: 5/5 passed
```

Note:

- The requested 3-minute video was intentionally excluded.
- The local repository does not contain GitHub PR metadata, so the `>= 10 merged PRs` item is documented as a truthful GitHub-side requirement instead of being marked as completed locally.
