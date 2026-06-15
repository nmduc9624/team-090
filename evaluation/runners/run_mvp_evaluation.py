"""Run MVP evaluation for all synthetic alert cases.

The runner executes the backend analyzer against every markdown report in
`evaluation/datasets/threat_reports`, validates the generated hunt package,
compares it with the expected hunt package, and writes JSON/CSV/Markdown
reports under `evaluation/runs/<timestamp>`.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from statistics import mean
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.schemas.hunt_package import HuntPackage  # noqa: E402
from app.schemas.threat_report import ThreatReportRequest  # noqa: E402
from app.services.threat_reports.analyzer import analyze_report  # noqa: E402


REQUIRED_FIELDS = [
    "threat_summary",
    "key_behaviors",
    "mitre_mapping",
    "required_telemetry",
    "hunt_checklist",
    "correlation_logic",
    "escalation_condition",
]

IOC_FIELDS = ["domains", "ips", "hashes", "files", "processes", "registry_keys"]


@dataclass
class CaseResult:
    slug: str
    status: str
    title: str
    error: str
    completeness_score: float
    expected_telemetry_recall: float
    expected_mitre_recall: float
    expected_ioc_recall: float
    behavior_overlap: float
    query_count: int
    behavior_count: int
    ioc_count: int
    mitre_count: int
    telemetry_count: int
    checklist_count: int
    weak_reasons: list[str]


def normalize(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().lower())


def technique_ids(values: list[str]) -> set[str]:
    ids: set[str] = set()
    for value in values:
        ids.update(re.findall(r"T\d{4}(?:\.\d{3})?", value.upper()))
    return ids


def flatten_ioc(ioc: dict[str, list[str]]) -> set[str]:
    values: set[str] = set()
    for field in IOC_FIELDS:
        for item in ioc.get(field, []):
            if item:
                values.add(normalize(item))
    return values


def recall(predicted: set[str], expected: set[str]) -> float:
    if not expected:
        return 1.0
    if not predicted:
        return 0.0
    return len(predicted & expected) / len(expected)


def behavior_score(predicted: list[str], expected: list[str]) -> float:
    if not expected:
        return 1.0
    if not predicted:
        return 0.0
    predicted_text = " ".join(normalize(item) for item in predicted)
    hits = 0
    for item in expected:
        normalized = normalize(item)
        tokens = [token for token in re.split(r"[^a-z0-9_.-]+", normalized) if len(token) >= 4]
        if normalized in predicted_text or any(token in predicted_text for token in tokens[:4]):
            hits += 1
    return hits / len(expected)


def non_empty(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list):
        return len(value) > 0
    return value is not None


def model_to_dict(package: HuntPackage) -> dict[str, Any]:
    if hasattr(package, "model_dump"):
        return package.model_dump()
    return package.dict()


def title_from_markdown(slug: str, content: str) -> str:
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            return stripped.strip("# ")[:160]
    return slug.replace("_", " ").title()


def evaluate_case(report_path: Path, expected_path: Path, output_dir: Path) -> tuple[CaseResult, dict[str, Any] | None]:
    slug = report_path.stem
    content = report_path.read_text(encoding="utf-8")
    title = title_from_markdown(slug, content)
    expected = json.loads(expected_path.read_text(encoding="utf-8"))

    try:
        package = analyze_report(ThreatReportRequest(title=title, content=content, source_name="evaluation"))
        generated = model_to_dict(package)
        HuntPackage.model_validate(generated)
    except Exception as exc:  # pragma: no cover - evaluation should report failures, not crash early.
        return (
            CaseResult(
                slug=slug,
                status="failed",
                title=title,
                error=str(exc),
                completeness_score=0.0,
                expected_telemetry_recall=0.0,
                expected_mitre_recall=0.0,
                expected_ioc_recall=0.0,
                behavior_overlap=0.0,
                query_count=0,
                behavior_count=0,
                ioc_count=0,
                mitre_count=0,
                telemetry_count=0,
                checklist_count=0,
                weak_reasons=["analyzer_error"],
            ),
            None,
        )

    output_dir.joinpath(f"{slug}.json").write_text(
        json.dumps(generated, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    completeness_score = sum(non_empty(generated.get(field)) for field in REQUIRED_FIELDS) / len(REQUIRED_FIELDS)
    expected_telemetry = {normalize(item) for item in expected.get("required_telemetry", [])}
    actual_telemetry = {normalize(item) for item in generated.get("required_telemetry", [])}
    expected_mitre = technique_ids(expected.get("mitre_mapping", []))
    actual_mitre = technique_ids(generated.get("mitre_mapping", []))
    expected_ioc = flatten_ioc(expected.get("ioc", {}))
    actual_ioc = flatten_ioc(generated.get("ioc", {}))

    telemetry_recall = recall(actual_telemetry, expected_telemetry)
    mitre_recall = recall(actual_mitre, expected_mitre)
    ioc_recall = recall(actual_ioc, expected_ioc)
    behavior_overlap = behavior_score(generated.get("key_behaviors", []), expected.get("key_behaviors", []))

    weak_reasons = []
    if completeness_score < 1.0:
        weak_reasons.append("missing_required_fields")
    if telemetry_recall < 0.5:
        weak_reasons.append("low_telemetry_alignment")
    if mitre_recall < 0.5:
        weak_reasons.append("low_mitre_alignment")
    if expected_ioc and ioc_recall < 0.5:
        weak_reasons.append("low_ioc_alignment")
    if behavior_overlap < 0.5:
        weak_reasons.append("low_behavior_overlap")
    if not generated.get("query_drafts"):
        weak_reasons.append("no_query_drafts")

    ioc_count = sum(len(generated.get("ioc", {}).get(field, [])) for field in IOC_FIELDS)
    status = "passed" if not [reason for reason in weak_reasons if reason != "no_query_drafts"] else "weak"

    return (
        CaseResult(
            slug=slug,
            status=status,
            title=title,
            error="",
            completeness_score=round(completeness_score, 4),
            expected_telemetry_recall=round(telemetry_recall, 4),
            expected_mitre_recall=round(mitre_recall, 4),
            expected_ioc_recall=round(ioc_recall, 4),
            behavior_overlap=round(behavior_overlap, 4),
            query_count=len(generated.get("query_drafts", [])),
            behavior_count=len(generated.get("key_behaviors", [])),
            ioc_count=ioc_count,
            mitre_count=len(generated.get("mitre_mapping", [])),
            telemetry_count=len(generated.get("required_telemetry", [])),
            checklist_count=len(generated.get("hunt_checklist", [])),
            weak_reasons=weak_reasons,
        ),
        generated,
    )


def write_csv(results: list[CaseResult], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(asdict(results[0]).keys()))
        writer.writeheader()
        for result in results:
            row = asdict(result)
            row["weak_reasons"] = ";".join(result.weak_reasons)
            writer.writerow(row)


def write_markdown(summary: dict[str, Any], results: list[CaseResult], path: Path) -> None:
    weakest = sorted(
        results,
        key=lambda item: (
            item.status == "passed",
            item.completeness_score,
            item.expected_telemetry_recall,
            item.expected_mitre_recall,
            item.expected_ioc_recall,
            item.behavior_overlap,
        ),
    )[:20]

    lines = [
        "# MVP Evaluation Report",
        "",
        f"- Run ID: `{summary['run_id']}`",
        f"- Total cases: {summary['total_cases']}",
        f"- Analyzed successfully: {summary['analyzed_successfully']}",
        f"- Failed: {summary['failed_cases']}",
        f"- Passed quality gate: {summary['passed_cases']}",
        f"- Weak cases: {summary['weak_cases']}",
        f"- Average completeness: {summary['average_completeness_score']:.2%}",
        f"- Average telemetry recall: {summary['average_telemetry_recall']:.2%}",
        f"- Average MITRE recall: {summary['average_mitre_recall']:.2%}",
        f"- Average IOC recall: {summary['average_ioc_recall']:.2%}",
        f"- Average behavior overlap: {summary['average_behavior_overlap']:.2%}",
        "",
        "## Quality Gate",
        "",
        "A case is `passed` when the analyzer returns a schema-valid hunt package with all required fields and at least 50% alignment for telemetry, MITRE, IOC, and behavior where expected data exists. Missing query drafts are tracked as a warning because not every report currently maps to a query template.",
        "",
        "## Weakest Cases",
        "",
        "| Case | Status | Completeness | Telemetry | MITRE | IOC | Behavior | Reasons |",
        "|---|---|---:|---:|---:|---:|---:|---|",
    ]
    for result in weakest:
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{result.slug}`",
                    result.status,
                    f"{result.completeness_score:.0%}",
                    f"{result.expected_telemetry_recall:.0%}",
                    f"{result.expected_mitre_recall:.0%}",
                    f"{result.expected_ioc_recall:.0%}",
                    f"{result.behavior_overlap:.0%}",
                    ", ".join(result.weak_reasons) or "none",
                ]
            )
            + " |"
        )
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def run(limit: int | None = None) -> Path:
    reports_dir = PROJECT_ROOT / "evaluation" / "datasets" / "threat_reports"
    expected_dir = PROJECT_ROOT / "evaluation" / "datasets" / "expected_hunt_packages"
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = PROJECT_ROOT / "evaluation" / "runs" / run_id
    generated_dir = run_dir / "generated_hunt_packages"
    generated_dir.mkdir(parents=True, exist_ok=True)

    report_paths = sorted(path for path in reports_dir.glob("*.md") if path.name != ".gitkeep")
    if limit is not None:
        report_paths = report_paths[:limit]

    results: list[CaseResult] = []
    missing_expected: list[str] = []
    for report_path in report_paths:
        expected_path = expected_dir / f"{report_path.stem}.json"
        if not expected_path.exists():
            missing_expected.append(report_path.stem)
            continue
        result, _ = evaluate_case(report_path, expected_path, generated_dir)
        results.append(result)

    if not results:
        raise RuntimeError("No evaluation cases were executed.")

    passed = [result for result in results if result.status == "passed"]
    weak = [result for result in results if result.status == "weak"]
    failed = [result for result in results if result.status == "failed"]

    summary = {
        "run_id": run_id,
        "total_cases": len(results),
        "missing_expected_cases": missing_expected,
        "analyzed_successfully": len(results) - len(failed),
        "failed_cases": len(failed),
        "passed_cases": len(passed),
        "weak_cases": len(weak),
        "average_completeness_score": mean(result.completeness_score for result in results),
        "average_telemetry_recall": mean(result.expected_telemetry_recall for result in results),
        "average_mitre_recall": mean(result.expected_mitre_recall for result in results),
        "average_ioc_recall": mean(result.expected_ioc_recall for result in results),
        "average_behavior_overlap": mean(result.behavior_overlap for result in results),
        "average_query_count": mean(result.query_count for result in results),
        "quality_gate": "passed" if len(failed) == 0 and len(passed) == len(results) else "needs_improvement",
    }

    run_dir.joinpath("summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    run_dir.joinpath("case_results.json").write_text(
        json.dumps([asdict(result) for result in results], indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    write_csv(results, run_dir / "case_results.csv")
    write_markdown(summary, results, run_dir / "report.md")
    return run_dir


def main() -> None:
    parser = argparse.ArgumentParser(description="Run MVP evaluation for alert-to-hunt-package generation.")
    parser.add_argument("--limit", type=int, default=None, help="Evaluate only the first N cases.")
    args = parser.parse_args()
    run_dir = run(limit=args.limit)
    print(f"Evaluation complete: {run_dir}")
    print(run_dir.joinpath("summary.json").read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
