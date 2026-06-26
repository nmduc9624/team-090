import json
from pathlib import Path

from app.schemas.hunt_package import HuntPackage
from app.schemas.threat_report import ThreatReportRequest
from app.services.runtime_logging.ai_logger import (
    log_analyze_requested,
    log_generation_completed,
)


def test_runtime_logger_writes_jsonl_without_raw_report(monkeypatch, tmp_path):
    monkeypatch.setenv("AI_LOG_DIR", str(tmp_path / ".ai-log"))
    request = ThreatReportRequest(
        title="Sensitive report",
        content="This report contains secret host victim-01 and token abc123.",
    )

    log_analyze_requested("req-1", request)

    log_file = tmp_path / ".ai-log" / "runtime.jsonl"
    lines = log_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])

    assert entry["event"] == "analyze_requested"
    assert entry["request_id"] == "req-1"
    assert entry["report_title"] == "Sensitive report"
    assert entry["report_content_length"] == len(request.content)
    assert len(entry["report_content_hash"]) == 64
    serialized = json.dumps(entry)
    assert "victim-01" not in serialized
    assert "abc123" not in serialized
    assert "content" not in entry


def test_runtime_logger_records_generated_package_metadata(monkeypatch, tmp_path):
    monkeypatch.setenv("AI_LOG_DIR", str(tmp_path / ".ai-log"))
    request = ThreatReportRequest(title="Encoded PowerShell", content="PowerShell encoded command downloads payload")
    package = HuntPackage(
        package_id="pkg-123",
        report_title="Encoded PowerShell",
        threat_summary="Suspicious encoded PowerShell execution.",
        key_behaviors=["Encoded PowerShell"],
        mitre_mapping=["T1059.001 - PowerShell"],
        required_telemetry=["EDR process telemetry"],
        hunt_checklist=["Review process tree"],
        query_drafts=[],
        correlation_logic="Correlate process and network telemetry.",
        escalation_condition="Escalate if confirmed malicious.",
        analyst_notes="",
        confidence_score=0.82,
        confidence_reasons=["Matched encoded command pattern"],
        severity_hint="High",
        risk_explanation="Potential execution.",
    )

    log_generation_completed("req-2", request, package, 123.456)

    log_file = tmp_path / ".ai-log" / "runtime.jsonl"
    entry = json.loads(log_file.read_text(encoding="utf-8").splitlines()[0])
    assert entry["event"] == "ai_generation_completed"
    assert entry["package_id"] == "pkg-123"
    assert entry["severity_hint"] == "High"
    assert entry["confidence_score"] == 0.82
    assert entry["latency_ms"] == 123.46
