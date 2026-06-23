import re

from app.services.rag.models import IntentContext, RetrievedDocument


def rerank_documents(
    query: str,
    intent: IntentContext,
    semantic_results: list[RetrievedDocument],
    keyword_results: list[RetrievedDocument],
    top_k: int,
) -> list[RetrievedDocument]:
    semantic_scores = _score_by_id(semantic_results)
    keyword_scores = _normalized_scores(keyword_results)
    documents = {item.document.id: item.document for item in [*semantic_results, *keyword_results]}
    query_terms = set(_tokenize(query))
    reranked = []
    for doc_id, document in documents.items():
        score = 0.0
        score += 0.55 * semantic_scores.get(doc_id, 0.0)
        score += 0.35 * keyword_scores.get(doc_id, 0.0)
        score += _metadata_bonus(document.metadata, intent)
        score += _technical_keyword_bonus(query_terms, document.title + "\n" + document.content)
        score -= _blocked_penalty(document.title + "\n" + document.content, intent)
        reranked.append(RetrievedDocument(document=document, score=round(score, 6)))
    reranked.sort(key=lambda item: (_source_priority(item), item.score), reverse=True)
    return _diverse_top_k(reranked, top_k)


def _score_by_id(results: list[RetrievedDocument]) -> dict[str, float]:
    return {item.document.id: max(item.score, 0.0) for item in results}


def _normalized_scores(results: list[RetrievedDocument]) -> dict[str, float]:
    max_score = max((item.score for item in results), default=0.0)
    if max_score <= 0:
        return {}
    return {item.document.id: item.score / max_score for item in results}


def _metadata_bonus(metadata: dict[str, str], intent: IntentContext) -> float:
    bonus = 0.0
    category = metadata.get("category", "").lower()
    telemetry = metadata.get("telemetry", "").lower()
    source_type = metadata.get("source_type", "").lower()
    if category in intent.categories:
        bonus += 0.45
    if telemetry in intent.telemetry_allow:
        bonus += 0.25
    if source_type in {"playbook", "query_template", "guardrail", "schema", "case"}:
        bonus += 0.08
    return bonus


def _technical_keyword_bonus(query_terms: set[str], text: str) -> float:
    text_terms = set(_tokenize(text))
    exact_hits = query_terms & text_terms
    bonus = min(len(exact_hits) * 0.035, 0.35)
    important_terms = {
        "attachpolicy",
        "setiampolicy",
        "administrator",
        "admin",
        "iam",
        "deploy",
        "repository",
        "secrets",
        "mshta.exe",
        "cron",
        "txt",
    }
    bonus += min(len(exact_hits & important_terms) * 0.08, 0.32)
    return bonus


def _blocked_penalty(text: str, intent: IntentContext) -> float:
    lower = text.lower()
    return sum(0.4 for keyword in intent.blocked_keywords if keyword in lower)


def _source_priority(item: RetrievedDocument) -> float:
    priority = {
        "playbook": 0.08,
        "query_template": 0.07,
        "guardrail": 0.06,
        "schema": 0.05,
        "case": 0.04,
        "sample_report": 0.03,
        "mitre": 0.02,
    }
    return priority.get(item.document.source_type, 0.0)


def _diverse_top_k(results: list[RetrievedDocument], top_k: int) -> list[RetrievedDocument]:
    selected: list[RetrievedDocument] = []
    source_counts: dict[str, int] = {}
    for item in results:
        count = source_counts.get(item.document.source_type, 0)
        if count >= 3 and len(selected) < top_k - 2:
            continue
        selected.append(item)
        source_counts[item.document.source_type] = count + 1
        if len(selected) >= top_k:
            break
    return selected


def _tokenize(text: str) -> list[str]:
    return [token for token in re.findall(r"[a-zA-Z0-9_.-]+", text.lower()) if len(token) > 1]
