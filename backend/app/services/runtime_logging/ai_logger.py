from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.schemas.hunt_package import HuntPackage
from app.schemas.threat_report import ThreatReportRequest

VN_TZ = timezone(timedelta(hours=7))
PROJECT_ROOT = Path(__file__).resolve().parents[4]


def _runtime_log_path() -> Path:
    configured = os.environ.get("AI_LOG_DIR", ".ai-log")
    log_dir = Path(configured)
    if not log_dir.is_absolute():
        log_dir = PROJECT_ROOT / log_dir
    return log_dir / "runtime.jsonl"


def _content_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _base_event(event: str, request_id: str, request: ThreatReportRequest) -> dict[str, Any]:
    settings = get_settings()
    content = request.content or ""
    return {
        "ts": datetime.now(VN_TZ).isoformat(),
        "event": event,
        "request_id": request_id,
        "report_title": request.title or "Untitled report",
        "report_content_hash": _content_hash(content),
        "report_content_length": len(content),
        "source_name": request.source_name or "",
        "analyzer_mode": settings.analyzer_mode,
        "ai_provider": settings.ai_provider,
        "model": settings.openai_chat_model if settings.ai_provider.lower() == "openai" else "",
    }


def write_runtime_event(entry: dict[str, Any]) -> None:
    try:
        log_path = _runtime_log_path()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
    except Exception as exc:  # pragma: no cover - logging must not break app flow
        print(f"[ai-runtime-log] Failed to write runtime log: {exc}")


def log_analyze_requested(request_id: str, request: ThreatReportRequest) -> None:
    entry = _base_event("analyze_requested", request_id, request)
    entry["status"] = "started"
    write_runtime_event(entry)


def log_generation_completed(
    request_id: str,
    request: ThreatReportRequest,
    package: HuntPackage,
    latency_ms: float,
    status: str = "success",
) -> None:
    entry = _base_event("ai_generation_completed", request_id, request)
    entry.update(
        {
            "status": status,
            "package_id": package.package_id,
            "severity_hint": package.severity_hint,
            "confidence_score": package.confidence_score,
            "latency_ms": round(latency_ms, 2),
            "query_draft_count": len(package.query_drafts),
            "ioc_domain_count": len(package.ioc.domains),
            "ioc_ip_count": len(package.ioc.ips),
            "mitre_mapping_count": len(package.mitre_mapping),
        }
    )
    write_runtime_event(entry)


def log_generation_failed(
    request_id: str,
    request: ThreatReportRequest,
    latency_ms: float,
    error: Exception,
) -> None:
    entry = _base_event("ai_generation_failed", request_id, request)
    entry.update(
        {
            "status": "failed",
            "latency_ms": round(latency_ms, 2),
            "error_type": type(error).__name__,
            "error_message": str(error)[:300],
        }
    )
    write_runtime_event(entry)


def log_discord_ticket_requested(request_id: str, package: HuntPackage) -> None:
    entry = {
        "ts": datetime.now(VN_TZ).isoformat(),
        "event": "discord_ticket_requested",
        "request_id": request_id,
        "package_id": package.package_id,
        "report_title": package.report_title,
        "severity_hint": package.severity_hint,
        "status": "queued",
    }
    write_runtime_event(entry)
