from typing import Any

from app.schemas.hunt_package import HuntPackage, QueryDraft
from app.services.rag.guardrails import apply_output_guardrails
from app.services.rag.models import RagContext


def validate_or_repair(payload: dict[str, Any] | None, baseline: HuntPackage, context: RagContext) -> HuntPackage:
    if not payload:
        return _annotate_baseline(baseline, context, "LLM generation unavailable; returned hybrid baseline with RAG citations.")

    openai_usage = payload.pop("_openai_usage", None)
    merged = _merge_with_baseline(payload, baseline)
    try:
        package = HuntPackage.model_validate(merged)
    except Exception:
        return _annotate_baseline(baseline, context, "LLM output failed schema validation; returned hybrid baseline with RAG citations.")

    package = _semantic_field_repair(package, baseline, context)
    package = apply_output_guardrails(package, context.intent)
    if not _has_required_fields(package):
        repaired = _semantic_field_repair(_copy_package(baseline), baseline, context)
        package = apply_output_guardrails(repaired, context.intent)
    package.analyst_notes = _append_rag_notes(
        package.analyst_notes,
        context,
        _llm_reason_with_usage("LLM/RAG analyzer output with semantic field-level guardrails. Validate before operational use.", openai_usage),
    )
    return package


def _merge_with_baseline(payload: dict[str, Any], baseline: HuntPackage) -> dict[str, Any]:
    base = baseline.model_dump()
    for key, value in payload.items():
        if value not in (None, "", [], {}):
            base[key] = value
    return base


def _has_required_fields(package: HuntPackage) -> bool:
    return all(
        [
            package.threat_summary.strip(),
            package.key_behaviors,
            package.required_telemetry,
            package.hunt_checklist,
            package.correlation_logic.strip(),
            package.escalation_condition.strip(),
        ]
    )


def _semantic_field_repair(package: HuntPackage, baseline: HuntPackage, context: RagContext) -> HuntPackage:
    baseline = apply_output_guardrails(_copy_package(baseline), context.intent)
    blocked = _blocked_output_terms(context)

    package.report_title = baseline.report_title

    if _contains_blocked(package.threat_summary, blocked) or _title_drift(package.threat_summary, baseline.report_title, context.intent.name):
        package.threat_summary = baseline.threat_summary

    package.key_behaviors = _repair_list(package.key_behaviors, baseline.key_behaviors, blocked)
    package.hunt_checklist = _repair_list(package.hunt_checklist, baseline.hunt_checklist, blocked)

    package.mitre_mapping = _repair_list(package.mitre_mapping, baseline.mitre_mapping, blocked)
    if not package.mitre_mapping:
        package.mitre_mapping = list(baseline.mitre_mapping)

    package.required_telemetry = _repair_telemetry(package.required_telemetry, baseline.required_telemetry, context)
    package.query_drafts = _repair_queries(package.query_drafts, baseline.query_drafts, blocked)

    if _contains_blocked(package.correlation_logic, blocked) or _too_generic_for_intent(package.correlation_logic, context.intent.name):
        package.correlation_logic = baseline.correlation_logic
    if _contains_blocked(package.escalation_condition, blocked):
        package.escalation_condition = baseline.escalation_condition

    return package


def _copy_package(package: HuntPackage) -> HuntPackage:
    return HuntPackage.model_validate(package.model_dump())


def _blocked_output_terms(context: RagContext) -> tuple[str, ...]:
    intent_blocks = tuple(item.lower() for item in context.intent.blocked_keywords)
    semantic_blocks = {
        "cloud_iam": ("bucket", "public access", "allusers", "anonymous", "cloud storage", "t1530"),
        "cloud_storage": ("process chain", "persistence changes", "registry run", "mshta", "lsass"),
        "cloud_metadata": ("persistence changes", "registry run", "mshta", "lsass"),
        "mfa_auth_change": ("push prompt", "push fatigue", "approved challenge", "denied mfa", "repeated mfa"),
        "mfa_fatigue": ("registry run", "mshta", "lsass"),
        "kerberos_ad": ("cloud iam", "cloud instance metadata", "metadata api", "bucket", "oauth", "mshta", "registry run"),
        "endpoint_credential": ("cloud instance metadata", "metadata api", "cloud_audit", "mshta", "registry run", "supply chain"),
    }.get(context.intent.name, ())
    return tuple(dict.fromkeys([*intent_blocks, *semantic_blocks]))


def _contains_blocked(value: str, blocked: tuple[str, ...]) -> bool:
    lower = value.lower()
    return any(term and term in lower for term in blocked)


def _title_drift(value: str, baseline_title: str, intent_name: str) -> bool:
    lower = value.lower()
    title = baseline_title.lower()
    if intent_name == "cloud_iam" and any(term in lower for term in ("bucket", "public access", "cloud storage")):
        return True
    if intent_name == "cloud_storage" and any(term in lower for term in ("admin policy", "admin role", "privileged role")):
        return True
    if intent_name == "mfa_auth_change" and any(term in lower for term in ("push fatigue", "push prompt")):
        return True
    title_tokens = {token for token in title.replace(":", " ").split() if len(token) >= 4}
    value_tokens = {token for token in lower.replace(":", " ").split() if len(token) >= 4}
    if title_tokens and value_tokens and len(title_tokens & value_tokens) / len(title_tokens) < 0.25:
        return True
    return False


def _repair_list(items: list[str], baseline_items: list[str], blocked: tuple[str, ...]) -> list[str]:
    repaired = [item for item in items if not _contains_blocked(item, blocked)]
    if not repaired:
        repaired = [item for item in baseline_items if not _contains_blocked(item, blocked)]
    return _merge_unique(repaired, baseline_items)


def _repair_telemetry(items: list[str], baseline_items: list[str], context: RagContext) -> list[str]:
    allowed = set(context.intent.telemetry_allow)
    blocked = set(context.intent.blocked_telemetry)
    repaired = [item for item in items if item in allowed and item not in blocked]
    repaired = _merge_unique(list(context.intent.required_telemetry), repaired, baseline_items)
    return [item for item in repaired if item in allowed and item not in blocked] or list(context.intent.telemetry_allow[:3])


def _repair_queries(queries: list[QueryDraft], baseline_queries: list[QueryDraft], blocked: tuple[str, ...]) -> list[QueryDraft]:
    repaired = []
    for query in queries:
        haystack = f"{query.name}\n{query.purpose}\n{query.query}"
        if not _contains_blocked(haystack, blocked):
            repaired.append(query)
    if not repaired:
        repaired = list(baseline_queries)
    return repaired


def _too_generic_for_intent(value: str, intent_name: str) -> bool:
    lower = value.lower()
    if intent_name.startswith("cloud") and "process chain" in lower:
        return True
    if intent_name in {"cloud_iam", "cloud_storage", "cloud_metadata"} and "same user, host, source ip, destination" in lower:
        return True
    if intent_name == "mfa_auth_change" and "mfa prompt" in lower:
        return True
    return False


def _merge_unique(*groups: list[Any]) -> list[Any]:
    seen = set()
    output = []
    for group in groups:
        for item in group:
            key = item if isinstance(item, str) else repr(item)
            key = key.lower() if isinstance(key, str) else key
            if key not in seen:
                seen.add(key)
                output.append(item)
    return output


def _annotate_baseline(baseline: HuntPackage, context: RagContext, reason: str) -> HuntPackage:
    baseline.analyst_notes = _append_rag_notes(baseline.analyst_notes, context, reason)
    return apply_output_guardrails(baseline, context.intent)


def _append_rag_notes(existing: str, context: RagContext, reason: str) -> str:
    citations = context.citations_text()
    return f"{existing}\n\nRAG mode: {reason}\nIntent: {context.intent.name}\nRetrieved sources:\n{citations}".strip()


def _llm_reason_with_usage(reason: str, usage: Any) -> str:
    if not isinstance(usage, dict):
        return reason
    prompt = usage.get("prompt_tokens")
    completion = usage.get("completion_tokens")
    total = usage.get("total_tokens")
    if total is None:
        return reason
    return f"{reason} OpenAI usage: prompt_tokens={prompt}, completion_tokens={completion}, total_tokens={total}."
