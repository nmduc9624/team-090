import json
import urllib.error
import urllib.request
from typing import Any

from app.core.config import get_settings
from app.schemas.hunt_package import HuntPackage
from app.schemas.threat_report import ThreatReportRequest
from app.services.rag.models import RagContext


def generate_hunt_package_json(request: ThreatReportRequest, context: RagContext, baseline: HuntPackage) -> dict[str, Any] | None:
    settings = get_settings()
    if settings.ai_provider.lower() != "openai" or not settings.openai_api_key:
        return None

    messages = [
        {
            "role": "system",
            "content": (
                "You are a SOC hunt package generator. Return only valid JSON matching the provided schema. "
                "Use retrieved context as grounding, but the user's report and detected intent are the source of truth. "
                "Do not change the alert type. Do not invent telemetry, MITRE techniques, or queries that conflict with guardrails."
            ),
        },
        {
            "role": "user",
            "content": _build_prompt(request, context, baseline),
        },
    ]
    payload = {
        "model": settings.openai_chat_model,
        "messages": messages,
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
    }
    try:
        response = _post_json("https://api.openai.com/v1/chat/completions", payload)
        content = response["choices"][0]["message"]["content"]
        parsed = json.loads(content)
        if isinstance(parsed, dict) and response.get("usage"):
            parsed["_openai_usage"] = response["usage"]
        return parsed
    except (KeyError, json.JSONDecodeError, urllib.error.URLError, TimeoutError, OSError):
        return None


def _build_prompt(request: ThreatReportRequest, context: RagContext, baseline: HuntPackage) -> str:
    schema = {
        "package_id": "string",
        "report_title": "string",
        "threat_summary": "string",
        "key_behaviors": ["string"],
        "ioc": {
            "domains": ["string"],
            "ips": ["string"],
            "hashes": ["string"],
            "files": ["string"],
            "processes": ["string"],
            "registry_keys": ["string"],
        },
        "mitre_mapping": ["Txxxx - technique name"],
        "required_telemetry": ["string"],
        "hunt_checklist": ["string"],
        "query_drafts": [{"name": "string", "platform": "KQL|SPL|Sigma|Generic", "query": "string", "purpose": "string"}],
        "correlation_logic": "string",
        "escalation_condition": "string",
        "analyst_notes": "string",
    }
    retrieved = "\n\n".join(
        f"[{idx}] {item.document.title}\nType: {item.document.source_type}\nPath: {item.document.path}\nMetadata: {item.document.metadata}\nContent:\n{item.document.content[:1800]}"
        for idx, item in enumerate(context.retrieved, start=1)
    )
    return f"""
Report title:
{request.title or ""}

Report content:
{request.content}

Detected intent:
{context.intent.name}

Allowed telemetry:
{", ".join(context.intent.telemetry_allow)}

Allowed MITRE prefixes:
{", ".join(context.intent.mitre_allow_prefixes)}

Blocked context keywords:
{", ".join(context.intent.blocked_keywords)}

Required telemetry:
{", ".join(context.intent.required_telemetry)}

Blocked telemetry:
{", ".join(context.intent.blocked_telemetry)}

Baseline package from deterministic analyzer:
{baseline.model_dump_json(indent=2)}

Retrieved RAG context:
{retrieved}

Required JSON schema:
{json.dumps(schema, ensure_ascii=False, indent=2)}

Rules:
- Keep report_title exactly aligned with the user input: "{baseline.report_title}".
- The detected intent is "{context.intent.name}". Do not generate a different alert scenario.
- Treat baseline package fields as a safety floor; improve wording and analyst usefulness, but do not replace them with another case.
- If retrieved context mentions a similar but different scenario, ignore that conflicting part.
- Never include blocked context keywords in report_title, threat_summary, MITRE mapping, checklist, query names, or correlation logic.
- required_telemetry must only contain allowed telemetry and should include required telemetry.
- mitre_mapping must only contain allowed MITRE prefixes.
- Keep output concise but operational.
- If unsure, preserve the baseline analyzer field.
- Query drafts must be based on retrieved query templates or be marked as draft.
- analyst_notes must mention that analyst validation is required.
"""


def _post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    settings = get_settings()
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": f"Bearer {settings.openai_api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))
