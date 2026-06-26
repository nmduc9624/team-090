"""Run rubric evaluation for final-app hunt package quality.

This runner evaluates generated hunt packages against the gold-standard rubric
instead of a single accuracy percentage. It focuses on technical correctness,
junior usability, workflow readiness, and noise control.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
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
os.chdir(BACKEND_ROOT)

from app.schemas.hunt_package import HuntPackage  # noqa: E402
from app.schemas.threat_report import ThreatReportRequest  # noqa: E402
from app.services.threat_reports.analyzer import analyze_report as analyze_hybrid  # noqa: E402
from app.services.threat_reports.dispatcher import analyze_report as analyze_dispatcher  # noqa: E402


SEVERITY_THRESHOLDS = {"Medium": 4.00, "Medium/High": 4.25, "High": 4.40, "Critical": 4.60}
OPENAI_INPUT_COST_PER_1M = 0.40
OPENAI_OUTPUT_COST_PER_1M = 1.60
RUBRIC_FIELDS = [
    "intent_correctness",
    "mitre_relevance",
    "telemetry_relevance",
    "query_usefulness",
    "investigation_flow_quality",
    "priority_action_quality",
    "false_positive_handling",
    "warning_appropriateness",
    "junior_readability",
    "hallucination_noise_control",
]


@dataclass
class RubricResult:
    slug: str
    title: str
    category: str
    intent: str
    severity: str
    status: str
    score: float
    threshold: float
    intent_correctness: float
    mitre_relevance: float
    telemetry_relevance: float
    query_usefulness: float
    investigation_flow_quality: float
    priority_action_quality: float
    false_positive_handling: float
    warning_appropriateness: float
    junior_readability: float
    hallucination_noise_control: float
    reasons: list[str]


def normalize(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().lower())


def technique_ids(values: list[str]) -> set[str]:
    ids: set[str] = set()
    for value in values:
        ids.update(re.findall(r"T\d{4}(?:\.\d{3})?", value.upper()))
    return ids


def contains_any(text: str, terms: list[str]) -> bool:
    lower = normalize(text)
    return any(normalize(term) in lower for term in terms if term)


def text_blob(package: dict[str, Any], fields: list[str] | None = None) -> str:
    if fields is None:
        return json.dumps(package, ensure_ascii=False)
    selected = {field: package.get(field) for field in fields}
    return json.dumps(selected, ensure_ascii=False)


def ratio_score(found: int, total: int) -> float:
    if total <= 0:
        return 5.0
    ratio = found / total
    if ratio >= 1.0:
        return 5.0
    if ratio >= 0.75:
        return 4.0
    if ratio >= 0.5:
        return 3.0
    if ratio > 0:
        return 2.0
    return 1.0


def list_text(items: Any) -> str:
    return json.dumps(items or [], ensure_ascii=False)


def score_case(case: dict[str, Any], package: dict[str, Any]) -> RubricResult:
    reasons: list[str] = []
    threshold = SEVERITY_THRESHOLDS.get(case.get("severity", "Medium/High"), 4.25)
    all_text = normalize(text_blob(package))
    operational_text = normalize(
        text_blob(
            package,
            [
                "threat_summary",
                "key_behaviors",
                "mitre_mapping",
                "required_telemetry",
                "hunt_checklist",
                "query_drafts",
                "correlation_logic",
                "escalation_condition",
                "risk_explanation",
                "investigation_flow",
                "priority_actions",
                "false_positive_checks",
                "recommended_response",
                "warning_preview",
            ],
        )
    )

    required_mitre = set(case.get("required_mitre", []))
    actual_mitre = technique_ids(package.get("mitre_mapping", []))
    mitre_hits = sum(1 for item in required_mitre if any(actual == item or actual.startswith(f"{item}.") or item.startswith(f"{actual}.") for actual in actual_mitre))
    mitre_relevance = ratio_score(mitre_hits, len(required_mitre))
    blocked_mitre = set(case.get("blocked_mitre", []))
    blocked_mitre_hits = [item for item in blocked_mitre if item in actual_mitre or any(actual.startswith(f"{item}.") for actual in actual_mitre)]
    if blocked_mitre_hits:
        mitre_relevance = min(mitre_relevance, 2.0)
        reasons.append(f"blocked_mitre:{','.join(blocked_mitre_hits)}")

    required_telemetry = [normalize(item) for item in case.get("required_telemetry", [])]
    actual_telemetry = [normalize(item) for item in package.get("required_telemetry", [])]
    telemetry_hits = sum(1 for item in required_telemetry if item in actual_telemetry)
    telemetry_relevance = ratio_score(telemetry_hits, len(required_telemetry))
    blocked_telemetry_hits = [item for item in case.get("blocked_telemetry", []) if normalize(item) in actual_telemetry]
    if blocked_telemetry_hits:
        telemetry_relevance = min(telemetry_relevance, 2.0)
        reasons.append(f"blocked_telemetry:{','.join(blocked_telemetry_hits)}")

    query_text = normalize(list_text(package.get("query_drafts", [])))
    query_keywords = case.get("required_query_keywords", [])
    query_hits = sum(1 for item in query_keywords if normalize(item) in query_text)
    query_usefulness = ratio_score(query_hits, len(query_keywords))
    if not package.get("query_drafts"):
        query_usefulness = 1.0
        reasons.append("missing_query_drafts")

    blocked_terms = [term for term in case.get("blocked_output_terms", []) if normalize(term) in operational_text]
    noise_score = 5.0
    if blocked_terms:
        noise_score = 1.0 if len(blocked_terms) > 1 else 2.0
        reasons.append(f"blocked_terms:{','.join(blocked_terms)}")

    intent_terms = [case.get("intent", ""), case.get("category", ""), *case.get("required_query_keywords", [])[:2]]
    intent_hits = sum(1 for item in intent_terms if item and normalize(item).replace("_", " ") in all_text)
    intent_correctness = ratio_score(intent_hits, max(2, len([item for item in intent_terms if item])))
    if blocked_terms:
        intent_correctness = min(intent_correctness, 3.0)

    investigation_flow = package.get("investigation_flow", [])
    if len(investigation_flow) >= 4 and all(step.get("title") and step.get("description") for step in investigation_flow if isinstance(step, dict)):
        investigation_flow_quality = 5.0
    elif len(investigation_flow) >= 3:
        investigation_flow_quality = 4.0
    elif investigation_flow:
        investigation_flow_quality = 3.0
    else:
        investigation_flow_quality = 1.0
        reasons.append("missing_investigation_flow")

    priority_actions = package.get("priority_actions", [])
    priority_text = normalize(list_text(priority_actions))
    priority_topics = case.get("expected_priority_topics", [])
    priority_hits = sum(1 for item in priority_topics if any(token in priority_text for token in _topic_tokens(item)))
    priority_action_quality = ratio_score(priority_hits, len(priority_topics))
    if not priority_actions:
        priority_action_quality = 1.0
        reasons.append("missing_priority_actions")

    false_positive_checks = package.get("false_positive_checks", [])
    false_positive_text = normalize(list_text(false_positive_checks))
    fp_topics = case.get("expected_false_positive_topics", [])
    fp_hits = sum(1 for item in fp_topics if any(token in false_positive_text for token in _topic_tokens(item)))
    false_positive_handling = ratio_score(fp_hits, len(fp_topics))
    if not false_positive_checks:
        false_positive_handling = 1.0
        reasons.append("missing_false_positive_checks")

    warning = package.get("warning_preview") or {}
    warning_expected = bool(case.get("warning_expected", False))
    warning_appropriateness = 5.0
    if not isinstance(warning, dict) or not warning.get("message"):
        warning_appropriateness = 2.0
        reasons.append("missing_warning_preview")
    else:
        should_send = bool(warning.get("should_send", False))
        requires_confirmation = bool(warning.get("requires_confirmation", False))
        if should_send != warning_expected:
            warning_appropriateness = min(warning_appropriateness, 3.0)
            reasons.append("warning_send_mismatch")
        if not requires_confirmation:
            warning_appropriateness = min(warning_appropriateness, 2.0)
            reasons.append("warning_without_confirmation")

    checklist_count = len(package.get("hunt_checklist", []))
    flow_count = len(investigation_flow)
    repeated_noise = _has_repeated_items(package.get("hunt_checklist", []))
    junior_readability = 5.0
    if checklist_count < 4 or flow_count < 3:
        junior_readability = 3.0
    if repeated_noise:
        junior_readability = min(junior_readability, 3.0)
        reasons.append("repeated_checklist_items")

    scores = {
        "intent_correctness": intent_correctness,
        "mitre_relevance": mitre_relevance,
        "telemetry_relevance": telemetry_relevance,
        "query_usefulness": query_usefulness,
        "investigation_flow_quality": investigation_flow_quality,
        "priority_action_quality": priority_action_quality,
        "false_positive_handling": false_positive_handling,
        "warning_appropriateness": warning_appropriateness,
        "junior_readability": junior_readability,
        "hallucination_noise_control": noise_score,
    }
    final_score = round(mean(scores.values()), 2)
    status = "passed" if final_score >= threshold and noise_score >= 3.0 and mitre_relevance >= 3.0 and telemetry_relevance >= 3.0 else "weak"
    return RubricResult(
        slug=case["slug"],
        title=package.get("report_title", case["slug"]),
        category=case.get("category", ""),
        intent=case.get("intent", ""),
        severity=case.get("severity", ""),
        status=status,
        score=final_score,
        threshold=threshold,
        reasons=reasons,
        **scores,
    )


def _topic_tokens(topic: str) -> list[str]:
    return [token for token in re.split(r"[^a-z0-9_.-]+", normalize(topic)) if len(token) >= 4]


def _has_repeated_items(items: list[str]) -> bool:
    seen: set[str] = set()
    for item in items:
        key = normalize(item)
        if key in seen:
            return True
        seen.add(key)
    return False


def title_from_markdown(slug: str, content: str) -> str:
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            return stripped.strip("# ")[:160]
    return slug.replace("_", " ").title()


def report_path_for_slug(slug: str) -> Path:
    candidates = [
        PROJECT_ROOT / "evaluation" / "datasets" / "threat_reports" / f"{slug}.md",
        PROJECT_ROOT / "data" / "threat_reports" / "samples" / f"{slug}.md",
    ]
    for path in candidates:
        if path.exists():
            return path
    raise FileNotFoundError(f"No markdown report found for {slug}")


def model_to_dict(package: HuntPackage) -> dict[str, Any]:
    if hasattr(package, "model_dump"):
        return package.model_dump()
    return package.dict()


def analyze_case(case: dict[str, Any], mode: str) -> dict[str, Any]:
    report_path = report_path_for_slug(case["slug"])
    content = report_path.read_text(encoding="utf-8")
    title = title_from_markdown(case["slug"], content)
    request = ThreatReportRequest(title=title, content=content, source_name="rubric_evaluation")
    analyzer = analyze_dispatcher if mode == "configured" else analyze_hybrid
    package = analyzer(request)
    generated = model_to_dict(package)
    HuntPackage.model_validate(generated)
    return generated


def evaluate_external_case(case_path: Path, mode: str) -> tuple[RubricResult, dict[str, Any]]:
    raw = json.loads(case_path.read_text(encoding="utf-8"))
    expected = raw.get("expected", {})
    criteria = {
        "slug": case_path.stem,
        "category": raw.get("category", "External"),
        "intent": raw.get("intent", raw.get("title", case_path.stem)),
        "severity": raw.get("severity", "Medium/High"),
        "required_mitre": sorted(technique_ids(expected.get("mitre_mapping", []))),
        "blocked_mitre": [],
        "required_telemetry": expected.get("required_telemetry", []),
        "blocked_telemetry": [],
        "required_query_keywords": _derive_query_keywords(expected),
        "blocked_output_terms": [],
        "expected_priority_topics": expected.get("key_behaviors", [])[:3],
        "expected_false_positive_topics": ["approved", "expected"],
        "warning_expected": raw.get("severity") in {"Critical", "High", "Medium/High"},
    }
    content = f"severity: {raw.get('severity', 'Medium/High')}\ncategory: {raw.get('category', 'External')}\n\n{raw.get('content', '')}"
    request = ThreatReportRequest(title=raw.get("title", case_path.stem), content=content, source_name="external_rubric")
    analyzer = analyze_dispatcher if mode == "configured" else analyze_hybrid
    generated = model_to_dict(analyzer(request))
    HuntPackage.model_validate(generated)
    return score_case(criteria, generated), generated


def _derive_query_keywords(expected: dict[str, Any]) -> list[str]:
    text = normalize(json.dumps(expected, ensure_ascii=False))
    tokens = []
    for token in re.split(r"[^a-z0-9_.-]+", text):
        if len(token) >= 6 and token not in {"search", "review", "confirm", "telemetry"}:
            tokens.append(token)
        if len(tokens) >= 3:
            break
    return tokens


def write_csv(results: list[RubricResult], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(asdict(results[0]).keys()))
        writer.writeheader()
        for result in results:
            row = asdict(result)
            row["reasons"] = ";".join(result.reasons)
            writer.writerow(row)


def write_markdown(summary: dict[str, Any], results: list[RubricResult], path: Path) -> None:
    lines = [
        "# Rubric Evaluation Report",
        "",
        f"- Run ID: `{summary['run_id']}`",
        f"- Mode: `{summary['mode']}`",
        f"- Total cases: {summary['total_cases']}",
        f"- Passed: {summary['passed_cases']}",
        f"- Weak: {summary['weak_cases']}",
        f"- Average rubric score: {summary['average_score']:.2f} / 5",
        "",
        "## Weak Cases",
        "",
        "| Case | Severity | Score | Threshold | Reasons |",
        "|---|---|---:|---:|---|",
    ]
    for result in sorted(results, key=lambda item: (item.status == "passed", item.score, item.slug)):
        if result.status != "passed":
            lines.append(f"| `{result.slug}` | {result.severity} | {result.score:.2f} | {result.threshold:.2f} | {', '.join(result.reasons) or 'needs review'} |")
    lines.extend(
        [
            "",
            "## All Cases",
            "",
            "| Case | Category | Intent | Severity | Status | Score |",
            "|---|---|---|---|---|---:|",
        ]
    )
    for result in sorted(results, key=lambda item: item.slug):
        lines.append(f"| `{result.slug}` | {result.category} | {result.intent} | {result.severity} | {result.status} | {result.score:.2f} |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run(mode: str, include_external: bool, limit: int | None = None) -> Path:
    matrix_path = PROJECT_ROOT / "evaluation" / "datasets" / "gold_standard" / "golden_case_matrix.json"
    cases = json.loads(matrix_path.read_text(encoding="utf-8"))
    offset = getattr(run, "offset", 0)
    if offset:
        cases = cases[offset:]
    if limit is not None:
        cases = cases[:limit]

    run_id = datetime.now().strftime("rubric_%Y%m%d_%H%M%S")
    run_dir = PROJECT_ROOT / "evaluation" / "runs" / run_id
    generated_dir = run_dir / "generated_hunt_packages"
    generated_dir.mkdir(parents=True, exist_ok=True)

    results: list[RubricResult] = []
    usage_totals = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    for case in cases:
        generated = analyze_case(case, mode)
        _add_usage(usage_totals, generated)
        generated_dir.joinpath(f"{case['slug']}.json").write_text(json.dumps(generated, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        results.append(score_case(case, generated))

    if include_external:
        external_dir = PROJECT_ROOT / "evaluation" / "datasets" / "gold_standard" / "cases"
        for case_path in sorted(external_dir.glob("*.json")):
            result, generated = evaluate_external_case(case_path, mode)
            _add_usage(usage_totals, generated)
            generated_dir.joinpath(f"external_{case_path.stem}.json").write_text(json.dumps(generated, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            results.append(result)

    summary = {
        "run_id": run_id,
        "mode": mode,
        "total_cases": len(results),
        "passed_cases": sum(1 for result in results if result.status == "passed"),
        "weak_cases": sum(1 for result in results if result.status != "passed"),
        "average_score": mean(result.score for result in results),
        "severity_breakdown": _severity_breakdown(results),
        "openai_usage": usage_totals,
        "estimated_openai_cost_usd": _estimate_openai_cost(usage_totals),
    }
    run_dir.joinpath("summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    run_dir.joinpath("rubric_results.json").write_text(json.dumps([asdict(result) for result in results], indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_csv(results, run_dir / "rubric_results.csv")
    write_markdown(summary, results, run_dir / "report.md")
    return run_dir


def _severity_breakdown(results: list[RubricResult]) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for severity in sorted({result.severity for result in results}):
        subset = [result for result in results if result.severity == severity]
        output[severity] = {
            "count": len(subset),
            "passed": sum(1 for result in subset if result.status == "passed"),
            "weak": sum(1 for result in subset if result.status != "passed"),
            "average_score": round(mean(result.score for result in subset), 2),
            "threshold": SEVERITY_THRESHOLDS.get(severity, 4.25),
        }
    return output


def _add_usage(totals: dict[str, int], generated: dict[str, Any]) -> None:
    notes = generated.get("analyst_notes", "")
    match = re.search(
        r"OpenAI usage:\s*prompt_tokens=(\d+|None),\s*completion_tokens=(\d+|None),\s*total_tokens=(\d+|None)",
        notes,
    )
    if not match:
        return
    prompt, completion, total = match.groups()
    totals["prompt_tokens"] += int(prompt) if prompt != "None" else 0
    totals["completion_tokens"] += int(completion) if completion != "None" else 0
    totals["total_tokens"] += int(total) if total != "None" else 0


def _estimate_openai_cost(usage: dict[str, int]) -> float:
    return round(
        (usage["prompt_tokens"] / 1_000_000 * OPENAI_INPUT_COST_PER_1M)
        + (usage["completion_tokens"] / 1_000_000 * OPENAI_OUTPUT_COST_PER_1M),
        6,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Run final-app rubric evaluation.")
    parser.add_argument("--mode", choices=["hybrid", "configured"], default="hybrid", help="hybrid avoids LLM/API; configured uses the app dispatcher and current env.")
    parser.add_argument("--include-external", action="store_true", help="Also evaluate hand-authored external gold standard variants.")
    parser.add_argument("--offset", type=int, default=0, help="Skip the first N matrix cases.")
    parser.add_argument("--limit", type=int, default=None, help="Evaluate only the first N matrix cases.")
    args = parser.parse_args()
    run.offset = args.offset
    run_dir = run(mode=args.mode, include_external=args.include_external, limit=args.limit)
    print(f"Rubric evaluation complete: {run_dir}")
    print(run_dir.joinpath("summary.json").read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
