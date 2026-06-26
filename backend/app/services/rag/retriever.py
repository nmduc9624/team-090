from app.core.config import get_settings
from app.services.rag.guardrails import classify_intent, filter_retrieval_metadata
from app.services.rag.indexer import rebuild_rag_index
from app.services.rag.keyword_retriever import keyword_search
from app.services.rag.models import RagContext, RetrievedDocument
from app.services.rag.reranker import rerank_documents
from app.services.rag.vector_store import indexed_document_count, search_index


def retrieve_context(title: str, content: str) -> RagContext:
    settings = get_settings()
    if indexed_document_count() == 0:
        rebuild_rag_index()

    intent = classify_intent(title, content)
    query = f"{title}\n{content}"
    candidate_count = max(settings.rag_top_k * settings.rag_candidate_multiplier, settings.rag_top_k)
    semantic_candidates = search_index(query, top_k=candidate_count)
    keyword_candidates = keyword_search(query, top_k=candidate_count)
    candidates = rerank_documents(query, intent, semantic_candidates, keyword_candidates, top_k=candidate_count)
    filtered: list[RetrievedDocument] = []
    for candidate in candidates:
        if filter_retrieval_metadata(intent, candidate.document.metadata):
            filtered.append(candidate)
        if len(filtered) >= settings.rag_top_k:
            break
    return RagContext(intent=intent, retrieved=tuple(filtered[: settings.rag_top_k]))
