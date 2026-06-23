"""Compare hybrid analyzer and RAG analyzer on a small holdout set.

This runner is intentionally lightweight. It proves the RAG path can execute,
produce valid HuntPackage objects, and report basic comparison metrics without
requiring an OpenAI API key. If `APP_OPENAI_API_KEY` is set and
`APP_AI_PROVIDER=openai`, the RAG path will call the LLM; otherwise it falls
back to hybrid output enriched with RAG citations and guardrails.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.core.config import get_settings  # noqa: E402
from app.schemas.hunt_package import HuntPackage  # noqa: E402
from app.schemas.threat_report import ThreatReportRequest  # noqa: E402
from app.services.rag.indexer import rebuild_rag_index  # noqa: E402
from app.services.rag.rag_analyzer import analyze_report_with_rag  # noqa: E402
from app.services.threat_reports.analyzer import analyze_report as analyze_hybrid  # noqa: E402


CASES = [
    {
        "slug": "github_oauth_repo_access_holdout",
        "title": "Suspicious GitHub OAuth App Accesses Private Repositories",
        "content": """
A developer authorizes an unverified GitHub OAuth app. The app accesses multiple private repositories,
reads repository secrets metadata, creates a deploy key, and the developer logs in from a new IP address.
""",
    },
    {
        "slug": "slack_oauth_export_holdout",
        "title": "Suspicious Slack OAuth App Exports Files",
        "content": """
A user grants an unverified Slack OAuth app broad file and channel permissions. Audit logs show the app
reading private channel history and exporting files shortly after a login from an unfamiliar IP address.
""",
    },
    {
        "slug": "linux_cron_download_holdout",
        "title": "Linux Cron Downloads Shell Script",
        "content": """
Linux audit logs show a new cron entry executing curl to download a shell script into /tmp and running it
with bash. DNS and proxy logs show outbound traffic to a rare domain after the cron change.
""",
    },
]


def model_to_dict(package: HuntPackage) -> dict[str, Any]:
    return package.model_dump() if hasattr(package, "model_dump") else package.dict()


def main() -> None:
    settings = get_settings()
    rebuild_rag_index()
    run_id = datetime.now().strftime("rag_compare_%Y%m%d_%H%M%S")
    output_dir = PROJECT_ROOT / "evaluation" / "runs" / run_id
    output_dir.mkdir(parents=True, exist_ok=True)

    rows = []
    previous_mode = settings.analyzer_mode
    settings.analyzer_mode = "rag"
    try:
        for case in CASES:
            request = ThreatReportRequest(title=case["title"], content=case["content"], source_name="rag_comparison")
            hybrid = analyze_hybrid(request)
            rag = analyze_report_with_rag(request)
            hybrid_data = model_to_dict(hybrid)
            rag_data = model_to_dict(rag)
            HuntPackage.model_validate(rag_data)

            row = {
                "slug": case["slug"],
                "hybrid_telemetry": hybrid_data["required_telemetry"],
                "rag_telemetry": rag_data["required_telemetry"],
                "hybrid_mitre_count": len(hybrid_data["mitre_mapping"]),
                "rag_mitre_count": len(rag_data["mitre_mapping"]),
                "rag_schema_valid": True,
                "rag_has_citations": "Retrieved sources:" in rag_data["analyst_notes"],
            }
            rows.append(row)
            (output_dir / f"{case['slug']}_hybrid.json").write_text(json.dumps(hybrid_data, indent=2, ensure_ascii=False), encoding="utf-8")
            (output_dir / f"{case['slug']}_rag.json").write_text(json.dumps(rag_data, indent=2, ensure_ascii=False), encoding="utf-8")
    finally:
        settings.analyzer_mode = previous_mode

    summary = {
        "run_id": run_id,
        "total_cases": len(rows),
        "schema_valid_cases": sum(1 for row in rows if row["rag_schema_valid"]),
        "citation_cases": sum(1 for row in rows if row["rag_has_citations"]),
        "quality_gate": "passed" if all(row["rag_schema_valid"] for row in rows) else "failed",
        "cases": rows,
    }
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"RAG comparison complete: {output_dir}")
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
