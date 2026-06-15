"""Run schema/completeness smoke test for holdout reports.

Holdout reports are intentionally not part of the 100 curated reference cases.
This runner validates that the analyzer still returns useful, schema-valid hunt
packages for new report wording.
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.schemas.hunt_package import HuntPackage  # noqa: E402
from app.schemas.threat_report import ThreatReportRequest  # noqa: E402
from app.services.threat_reports.analyzer import analyze_report  # noqa: E402


REQUIRED_LIST_FIELDS = ["key_behaviors", "mitre_mapping", "required_telemetry", "hunt_checklist"]
REQUIRED_TEXT_FIELDS = ["threat_summary", "correlation_logic", "escalation_condition", "analyst_notes"]


@dataclass
class HoldoutResult:
    slug: str
    status: str
    behavior_count: int
    mitre_count: int
    telemetry_count: int
    checklist_count: int
    query_count: int
    matched_reference_note: str
    error: str = ""


def title_from_markdown(slug: str, content: str) -> str:
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            return stripped.strip("# ")[:160]
    return slug.replace("_", " ").title()


def package_to_dict(package: HuntPackage) -> dict:
    if hasattr(package, "model_dump"):
        return package.model_dump()
    return package.dict()


def run() -> Path:
    reports_dir = PROJECT_ROOT / "evaluation" / "datasets" / "holdout_reports"
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = PROJECT_ROOT / "evaluation" / "runs" / f"holdout_{run_id}"
    generated_dir = run_dir / "generated_hunt_packages"
    generated_dir.mkdir(parents=True, exist_ok=True)

    results: list[HoldoutResult] = []
    for report_path in sorted(reports_dir.glob("*.md")):
        content = report_path.read_text(encoding="utf-8")
        title = title_from_markdown(report_path.stem, content)
        try:
            package = analyze_report(ThreatReportRequest(title=title, content=content, source_name="holdout"))
            data = package_to_dict(package)
            HuntPackage.model_validate(data)
            generated_dir.joinpath(f"{report_path.stem}.json").write_text(
                json.dumps(data, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            missing = []
            for field in REQUIRED_TEXT_FIELDS:
                if not data.get(field):
                    missing.append(field)
            for field in REQUIRED_LIST_FIELDS:
                if not data.get(field):
                    missing.append(field)
            status = "passed" if not missing else "weak"
            results.append(
                HoldoutResult(
                    slug=report_path.stem,
                    status=status,
                    behavior_count=len(data.get("key_behaviors", [])),
                    mitre_count=len(data.get("mitre_mapping", [])),
                    telemetry_count=len(data.get("required_telemetry", [])),
                    checklist_count=len(data.get("hunt_checklist", [])),
                    query_count=len(data.get("query_drafts", [])),
                    matched_reference_note=data.get("analyst_notes", ""),
                    error=", ".join(missing),
                )
            )
        except Exception as exc:
            results.append(
                HoldoutResult(
                    slug=report_path.stem,
                    status="failed",
                    behavior_count=0,
                    mitre_count=0,
                    telemetry_count=0,
                    checklist_count=0,
                    query_count=0,
                    matched_reference_note="",
                    error=str(exc),
                )
            )

    passed = sum(1 for result in results if result.status == "passed")
    summary = {
        "run_id": f"holdout_{run_id}",
        "total_cases": len(results),
        "passed_cases": passed,
        "weak_or_failed_cases": len(results) - passed,
        "quality_gate": "passed" if passed == len(results) else "needs_improvement",
    }
    run_dir.joinpath("summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    run_dir.joinpath("case_results.json").write_text(
        json.dumps([asdict(result) for result in results], indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    lines = [
        "# Holdout Smoke Test Report",
        "",
        f"- Run ID: `{summary['run_id']}`",
        f"- Total cases: {summary['total_cases']}",
        f"- Passed cases: {summary['passed_cases']}",
        f"- Weak or failed cases: {summary['weak_or_failed_cases']}",
        f"- Quality gate: {summary['quality_gate']}",
        "",
        "| Case | Status | Behaviors | MITRE | Telemetry | Checklist | Queries | Note |",
        "|---|---|---:|---:|---:|---:|---:|---|",
    ]
    for result in results:
        lines.append(
            f"| `{result.slug}` | {result.status} | {result.behavior_count} | {result.mitre_count} | {result.telemetry_count} | {result.checklist_count} | {result.query_count} | {result.matched_reference_note.replace('|', '/')} |"
        )
    run_dir.joinpath("report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return run_dir


if __name__ == "__main__":
    path = run()
    print(f"Holdout smoke complete: {path}")
    print(path.joinpath("summary.json").read_text(encoding="utf-8"))
