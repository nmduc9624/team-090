import json
import time
from uuid import uuid4
import urllib.request
from typing import Any
from fastapi import APIRouter, BackgroundTasks, Depends
from pydantic import BaseModel, Field

from app.core.auth import AuthenticatedUser, get_current_user
from app.schemas.hunt_package import HuntPackage
from app.schemas.threat_report import ThreatReportRequest
from app.services.firestore.audit_repository import AuditRepository
from app.services.firestore.cases_repository import CasesRepository
from app.services.firestore.help_requests_repository import HelpRequestsRepository
from app.services.firestore.tickets_repository import TicketsRepository
from app.services.firestore.warnings_repository import WarningsRepository
from app.services.threat_reports.dispatcher import analyze_report
from app.services.runtime_logging.ai_logger import (
    log_analyze_requested,
    log_discord_ticket_requested,
    log_generation_completed,
    log_generation_failed,
)

router = APIRouter(prefix="/api/threat-reports", tags=["threat-reports"])


def _short_list(values: list[str], limit: int = 5) -> list[str]:
    return [value for value in values if value][:limit]


def _username_from_email(email: str) -> str:
    name = (email or "").split("@", 1)[0].strip()
    return name or "junior"


def _build_warning_payload(package: HuntPackage, user: AuthenticatedUser | None = None) -> dict:
    current_step = package.investigation_flow[0] if package.investigation_flow else None
    evidence_needed: list[str] = []
    if current_step:
        evidence_needed.extend(current_step.expected_evidence)
    evidence_needed.extend(package.required_telemetry)
    evidence_needed.extend(package.key_behaviors)
    evidence_needed.extend(package.hunt_checklist[:4])

    return {
        "case_id": package.package_id,
        "alert_title": package.report_title,
        "requester_user_id": getattr(user, "uid", ""),
        "requester_email": getattr(user, "email", ""),
        "requester_username": _username_from_email(getattr(user, "email", "")),
        "severity": package.severity_hint or "Medium/High",
        "confidence_score": package.confidence_score,
        "confidence_reasons": _short_list(package.confidence_reasons, 4),
        "risk_explanation": package.risk_explanation,
        "current_step": current_step.model_dump() if current_step else None,
        "evidence_to_check": _short_list(evidence_needed, 8),
        "priority_actions": [action.model_dump() for action in package.priority_actions[:5]],
        "warning_preview": package.warning_preview.model_dump(),
        "warning_types": [
            "initial_warning",
            "step_warning",
            "priority_action_warning",
            "approval_required",
            "final_summary",
        ],
    }


def notify_bot(package: HuntPackage, user: AuthenticatedUser | None = None):
    payload = _build_warning_payload(package, user)
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        "http://127.0.0.1:8001/api/ticket",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=2) as response:
            response_data = json.loads(response.read().decode("utf-8") or "{}")
            mapping = response_data.get("mapping") or {}
            TicketsRepository().upsert_ticket(
                package.package_id,
                {
                    "provider": "discord",
                    "status": mapping.get("status") or "open",
                    "channel_id": str(mapping.get("channel_id") or ""),
                    "channel_name": mapping.get("channel_name") or "",
                    "alert_title": package.report_title,
                    "severity": package.severity_hint or "Medium/High",
                    "created_from": "analyze",
                },
                user,
            )
    except Exception as e:
        print(f"Failed to notify Discord bot: {e}")


@router.post("/analyze", response_model=HuntPackage)
def analyze_threat_report(
    request: ThreatReportRequest,
    background_tasks: BackgroundTasks,
    current_user: AuthenticatedUser | None = Depends(get_current_user),
) -> HuntPackage:
    request_id = uuid4().hex
    started = time.perf_counter()
    log_analyze_requested(request_id, request)
    try:
        package = analyze_report(request)
        latency_ms = (time.perf_counter() - started) * 1000
        log_generation_completed(request_id, request, package, latency_ms)
    except Exception as exc:
        latency_ms = (time.perf_counter() - started) * 1000
        log_generation_failed(request_id, request, latency_ms, exc)
        raise

    CasesRepository().create_or_update_case(package, request.model_dump(mode="json"), current_user)
    AuditRepository().add_event(package.package_id, "case_analyzed", "hunt_package", user=current_user)
    log_discord_ticket_requested(request_id, package)
    background_tasks.add_task(notify_bot, package, current_user)
    return package


class SupervisorHelpRequest(BaseModel):
    case_id: str
    alert_title: str
    struggle: str
    question: str
    severity: str = ""
    confidence_score: float | None = None
    current_step: str = ""
    completed_steps: list[str] = Field(default_factory=list)
    evidence_available: list[str] = Field(default_factory=list)
    current_warning: str = ""


class WarningEventRequest(BaseModel):
    case_id: str
    alert_title: str
    warning_type: str
    severity: str = ""
    confidence_score: float | None = None
    payload: dict[str, Any] = Field(default_factory=dict)


def notify_bot_warning(request_data: dict):
    body = json.dumps(request_data).encode("utf-8")
    req = urllib.request.Request(
        "http://127.0.0.1:8001/api/warning",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            pass
    except Exception as e:
        print(f"Failed to send Discord warning event: {e}")


def notify_bot_supervisor(request_data: dict):
    body = json.dumps(request_data).encode("utf-8")
    req = urllib.request.Request(
        "http://127.0.0.1:8001/api/supervisor-alert",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            pass
    except Exception as e:
        print(f"Failed to notify Discord bot supervisor: {e}")


@router.post("/ask-supervisor")
def ask_supervisor(
    request: SupervisorHelpRequest,
    background_tasks: BackgroundTasks,
    current_user: AuthenticatedUser | None = Depends(get_current_user),
):
    HelpRequestsRepository().add_help_request(request.case_id, request.dict(), current_user)
    CasesRepository().update_case_status(request.case_id, "needs_help", current_user)
    AuditRepository().add_event(request.case_id, "help_requested", request.current_step, user=current_user)
    background_tasks.add_task(notify_bot_supervisor, request.dict())
    return {"status": "ok"}


@router.post("/warning")
def send_warning_event(
    request: WarningEventRequest,
    background_tasks: BackgroundTasks,
    current_user: AuthenticatedUser | None = Depends(get_current_user),
):
    WarningsRepository().add_warning(request.case_id, request.warning_type, request.dict(), current_user)
    if request.warning_type == "priority_action_warning":
        CasesRepository().update_priority_actions_confirmed(request.case_id, current_user)
    elif request.warning_type == "step_warning":
        CasesRepository().mark_step_started(request.case_id, request.payload.get("current_step") or {}, current_user)
    elif request.warning_type == "escalation_warning":
        CasesRepository().update_case_status(request.case_id, "escalated", current_user)
    if request.warning_type == "final_summary":
        CasesRepository().update_case_status(request.case_id, "ended", current_user)
    AuditRepository().add_event(request.case_id, request.warning_type, "warning", request.payload, current_user)
    background_tasks.add_task(notify_bot_warning, request.dict())
    return {"status": "ok"}

