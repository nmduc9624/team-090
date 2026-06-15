from pathlib import Path

from app.schemas.threat_report import ThreatReportRequest
from app.services.threat_reports.analyzer import analyze_report


def test_excel_mshta_report_generates_hunt_package():
    repo = Path(__file__).resolve().parents[3]
    report = (repo / "data" / "threat_reports" / "samples" / "excel_mshta_persistence.md").read_text(encoding="utf-8")

    package = analyze_report(ThreatReportRequest(title="Excel mshta", content=report))

    assert package.threat_summary
    assert package.key_behaviors
    assert "edr_process" in package.required_telemetry
    assert package.query_drafts
    assert any("mshta" in item.lower() for item in package.key_behaviors)

def test_hybrid_analyzer_uses_reference_for_identity_alert():
    repo = Path(__file__).resolve().parents[3]
    report = (repo / "data" / "threat_reports" / "samples" / "password_spray_many_users.md").read_text(encoding="utf-8")

    package = analyze_report(ThreatReportRequest(title="Password Spray Against Many Users", content=report))

    assert "auth" in package.required_telemetry
    assert any("T1110" in item for item in package.mitre_mapping)
    assert any("password" in item.lower() for item in package.key_behaviors)
    assert "password_spray_many_users" in package.analyst_notes


def test_hybrid_analyzer_uses_reference_for_cloud_alert():
    repo = Path(__file__).resolve().parents[3]
    report = (repo / "data" / "threat_reports" / "samples" / "cloud_storage_public_bucket.md").read_text(encoding="utf-8")

    package = analyze_report(ThreatReportRequest(title="Cloud Storage Bucket Made Public", content=report))

    assert "cloud_audit" in package.required_telemetry
    assert any("T1530" in item or "T1098" in item for item in package.mitre_mapping)
    assert any("bucket" in item.lower() for item in package.key_behaviors)
