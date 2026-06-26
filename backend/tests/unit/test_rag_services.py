from pathlib import Path

from app.core.config import get_settings
from app.schemas.threat_report import ThreatReportRequest
from app.services.rag.guardrails import classify_intent
from app.services.rag.indexer import rebuild_rag_index
from app.services.rag.models import RagContext
from app.services.rag.cache import get_cached_hunt_package, store_cached_hunt_package
from app.services.rag.retriever import retrieve_context
from app.services.rag.validator import validate_or_repair
from app.services.query_generation.template_loader import find_templates_for_text
from app.services.threat_reports.analyzer import analyze_report as analyze_hybrid
from app.services.threat_reports.dispatcher import analyze_report


def test_rag_index_rebuilds_from_project_data(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "ai_provider", "mock")
    monkeypatch.setattr(settings, "openai_api_key", None)
    result = rebuild_rag_index()

    assert result["document_count"] > 100
    assert Path(str(result["path"])).exists()
    assert result["embedding_provider"]


def test_rag_cache_round_trips_hunt_package(monkeypatch, tmp_path):
    settings = get_settings()
    request = ThreatReportRequest(title="Cached report", content="excel.exe launches mshta.exe")
    package = analyze_hybrid(request)
    monkeypatch.setattr(settings, "rag_cache_enabled", True)
    monkeypatch.setattr(settings, "data_dir", tmp_path)

    assert get_cached_hunt_package(request) is None
    store_cached_hunt_package(request, package)
    cached = get_cached_hunt_package(request)

    assert cached is not None
    assert cached.package_id == package.package_id
    assert "RAG cache" in cached.analyst_notes


def test_retriever_classifies_developer_platform_context():
    settings = get_settings()
    settings.ai_provider = "mock"
    settings.openai_api_key = None
    content = "GitHub OAuth app accesses private repositories, reads repository secrets metadata, and creates a deploy key."
    intent = classify_intent("GitHub OAuth app", content)
    context = retrieve_context("GitHub OAuth app", content)

    assert intent.name == "developer_platform"
    assert context.retrieved
    assert any("developer" in item.document.title.lower() or "github" in item.document.content.lower() for item in context.retrieved)


def test_retriever_uses_keyword_and_rerank_for_cloud_iam():
    title = "Cloud IAM Admin Policy Attached"
    content = "An administrator policy is attached to a user, role or service account using AttachPolicy."
    intent = classify_intent(title, content)
    context = retrieve_context(title, content)
    retrieved_text = "\n".join(f"{item.document.title}\n{item.document.content}" for item in context.retrieved).lower()

    assert intent.name == "cloud_iam"
    assert "cloud iam" in retrieved_text or "attachpolicy" in retrieved_text
    assert "mshta" not in retrieved_text[:1000]


def test_rag_mode_without_api_key_falls_back_to_valid_package(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "analyzer_mode", "rag")
    monkeypatch.setattr(settings, "ai_provider", "openai")
    monkeypatch.setattr(settings, "openai_api_key", None)
    report = """
# Suspicious GitHub OAuth App

An unverified GitHub OAuth app accesses private repositories, reads repository secrets metadata, creates a deploy key, and the developer logs in from a new IP.
"""

    package = analyze_report(ThreatReportRequest(title="Suspicious GitHub OAuth App", content=report))

    assert package.threat_summary
    assert package.key_behaviors
    assert "cloud_audit" in package.required_telemetry
    assert "RAG mode" in package.analyst_notes
    assert "developer_platform" in package.analyst_notes


def test_validator_repairs_openai_cloud_iam_drift_field_by_field():
    report = """
# Alert Report: Cloud IAM Admin Policy Attached

## Summary
An administrator policy is attached to a user, role or service account.

## Observed Behaviors
- cloud control plane setting changes unexpectedly
- actor, key, or workload is unusual for the action
- sensitive resource access or privilege expansion follows
"""
    baseline = analyze_hybrid(ThreatReportRequest(title="Cloud IAM Admin Policy Attached", content=report))
    context = RagContext(intent=classify_intent("Cloud IAM Admin Policy Attached", report), retrieved=())
    bad_openai_payload = baseline.model_dump()
    bad_openai_payload.update(
        {
            "report_title": "Cloud Storage Bucket Made Public",
            "threat_summary": "A cloud storage bucket or object ACL is changed to allow public access.",
            "mitre_mapping": ["T1530 - Data from Cloud Storage Object", "T1098 - Account Manipulation"],
            "query_drafts": [
                {
                    "name": "Cloud Storage Public Access Hunt",
                    "platform": "KQL",
                    "query": "CloudAuditLogs | where TargetResources has_any ('allUsers', 'anonymous')",
                    "purpose": "Wrong storage query.",
                }
            ],
            "correlation_logic": "Correlate bucket public access by user, host, source IP, destination, and time window.",
        }
    )

    package = validate_or_repair(bad_openai_payload, baseline, context)
    text = "\n".join(
        [
            package.report_title,
            package.threat_summary,
            *package.mitre_mapping,
            *(query.name for query in package.query_drafts),
            package.correlation_logic,
        ]
    ).lower()

    assert package.report_title == baseline.report_title
    assert "bucket" not in text
    assert "public access" not in text
    assert "t1530" not in text
    assert any("T1098" in item for item in package.mitre_mapping)
    assert any("cloud iam" in query.name.lower() for query in package.query_drafts)
    assert "actor/principal" in package.correlation_logic.lower()


def test_mfa_disabled_is_not_repaired_to_push_fatigue():
    report = """
# Alert Report: MFA Disabled For User

## Summary
Multi-factor authentication is disabled for a user account.

## Observed Behaviors
- unusual authentication pattern appears for the user
- source IP or device is not part of the user's baseline
- follow-on access occurs after the suspicious login
"""
    intent = classify_intent("MFA Disabled For User", report)
    baseline = analyze_hybrid(ThreatReportRequest(title="MFA Disabled For User", content=report))

    assert intent.name == "mfa_auth_change"
    text = "\n".join(
        [
            *baseline.hunt_checklist,
            *(query.name for query in baseline.query_drafts),
            baseline.correlation_logic,
        ]
    ).lower()
    assert "push fatigue" not in text
    assert "push prompt" not in text
    assert "approved challenge" not in text
    assert any("auth method" in query.name.lower() or "mfa auth" in query.name.lower() for query in baseline.query_drafts)



def test_template_selector_disambiguates_core_categories():
    cases = {
        "Cloud IAM Admin Policy Attached": (
            "administrator policy attached to role using AttachPolicy",
            "cloud_iam_admin_policy_attachment_hunt",
            ["cloud_storage", "metadata", "lsass", "mshta"],
        ),
        "Cloud Storage Bucket Made Public": (
            "storage bucket ACL changed to allUsers public access",
            "cloud_storage_public_access_hunt",
            ["cloud_iam", "metadata", "lsass", "mshta"],
        ),
        "Suspicious Kerberos Ticket Lifetime": (
            "Kerberos TGT TGS ticket lifetime abnormal from domain controller",
            "kerberos_ticket_anomaly_hunt",
            ["cloud_iam", "cloud_storage", "metadata", "mshta"],
        ),
        "MFA Disabled For User": (
            "authentication method removed and strong auth disabled",
            "mfa_auth_method_change_hunt",
            ["mfa_push", "password_spray", "mshta"],
        ),
        "GitHub OAuth Repo Access": (
            "GitHub OAuth app accesses private repositories creates deploy key and reads secrets metadata",
            "developer_oauth_repo_access_hunt",
            ["cloud_metadata", "cloud_iam", "lsass", "registry"],
        ),
    }

    for title, (body, expected_template, blocked_terms) in cases.items():
        templates = find_templates_for_text(f"{title}\n{body}")
        joined = "\n".join(template.name for template in templates).lower()
        assert expected_template in joined
        for blocked in blocked_terms:
            assert blocked not in joined


def test_remote_registry_prefers_specific_service_templates():
    templates = find_templates_for_text(
        "Remote Registry Service Enabled remote administration service started RemoteRegistry by wmic.exe and psexesvc.exe"
    )
    names = [template.name for template in templates]

    assert names[:3] == [
        "remote_registry_service_hunt",
        "remote_registry_service_hunt",
        "remote_registry_service_hunt",
    ]
    assert all("cloud" not in name for name in names[:3])


def test_defender_tampering_does_not_use_remote_registry_checklist():
    report = """
# Alert Report: Defender Real-Time Protection Disabled

## Summary
Microsoft Defender real-time protection is disabled on an endpoint.

## Observed Behaviors
- security tool protection is disabled unexpectedly
- actor or process is not part of normal administration
- suspicious process or follow-on activity appears after protection change
"""
    package = analyze_hybrid(ThreatReportRequest(title="Defender Real-Time Protection Disabled", content=report))
    text = "\n".join([*package.hunt_checklist, *(query.name for query in package.query_drafts)]).lower()

    assert "remote registry" not in text
    assert "security tool" in text or "defender" in text
    assert any("defense" in query.name.lower() for query in package.query_drafts)
