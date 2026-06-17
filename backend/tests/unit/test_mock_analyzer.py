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

def test_saas_oauth_export_custom_report_avoids_endpoint_noise():
    report = """
# Test Report: Suspicious Slack OAuth App Exports Files

## Summary
A user receives a Slack message from an external workspace inviting them to install a productivity OAuth app. Shortly after the user approves the app, audit logs show the app reading channel history and exporting files from multiple private channels. The same user also logs in from a new IP address that has not been seen before.

## Observed Behaviors
- external Slack workspace sends app installation link to internal user
- user grants OAuth permissions to an unverified productivity app
- OAuth app reads channel history and exports files from private channels
- user login occurs from unfamiliar IP address shortly before app activity
- large file export activity occurs outside normal working hours

## Indicators
- domains: slack-productivity-sync.example
- urls: https://slack-productivity-sync.example/install
- ips: 203.0.113.144
- files: private_channel_export.zip
- processes: none
- registry_keys: none
"""

    package = analyze_report(ThreatReportRequest(title="Suspicious Slack OAuth App Exports Files", content=report))
    mitre_text = "\n".join(package.mitre_mapping).lower()
    query_names = "\n".join(query.name.lower() for query in package.query_drafts)

    assert "slack" in package.threat_summary.lower()
    assert "admin policy" not in package.threat_summary.lower()
    assert "cloud_audit" in package.required_telemetry
    assert "auth" in package.required_telemetry
    assert "edr_registry" not in package.required_telemetry
    assert "edr_process" not in package.required_telemetry
    assert any("T1528" in item for item in package.mitre_mapping)
    assert any("T1530" in item or "T1567.002" in item for item in package.mitre_mapping)
    assert "mshta" not in mitre_text
    assert "registry run" not in mitre_text
    assert "lsass" not in mitre_text
    assert "oauth" in query_names or "saas" in query_names
    assert "registry" not in query_names
    assert "process registry" not in query_names

def test_developer_platform_oauth_report_avoids_endpoint_noise():
    report = """
# Test Report: Suspicious GitHub OAuth App Accesses Private Repositories

## Summary
A developer receives a message in a public issue asking them to install a GitHub productivity OAuth app. Shortly after authorization, GitHub audit logs show the app accessing multiple private repositories, reading repository secrets metadata, and creating a new deploy key on one internal project. The developer also logs in from a new IP address during the same time window.

## Observed Behaviors
- public GitHub issue contains link to install an unverified OAuth app
- developer grants repository read permissions to the OAuth app
- OAuth app accesses multiple private repositories
- repository secrets metadata is read shortly after authorization
- new deploy key is created on an internal repository
- developer login occurs from unfamiliar IP address

## Indicators
- domains: github-productivity-review.example
- urls: https://github-productivity-review.example/install
- ips: 203.0.113.188
- files: none
- processes: none
- registry_keys: none
"""

    package = analyze_report(ThreatReportRequest(title="Suspicious GitHub OAuth App Accesses Private Repositories", content=report))
    mitre_text = "\n".join(package.mitre_mapping).lower()
    query_names = "\n".join(query.name.lower() for query in package.query_drafts)
    checklist_text = "\n".join(package.hunt_checklist).lower()

    assert "github" in package.threat_summary.lower()
    assert "cloud_audit" in package.required_telemetry
    assert "auth" in package.required_telemetry
    assert "edr_registry" not in package.required_telemetry
    assert "edr_process" not in package.required_telemetry
    assert any("T1528" in item for item in package.mitre_mapping)
    assert any("T1098" in item for item in package.mitre_mapping)
    assert any("T1552" in item for item in package.mitre_mapping)
    assert any("T1530" in item for item in package.mitre_mapping)
    assert "mshta" not in mitre_text
    assert "registry run" not in mitre_text
    assert "lsass" not in mitre_text
    assert "developer" in query_names
    assert "deploy key" in checklist_text
    assert "repository" in checklist_text