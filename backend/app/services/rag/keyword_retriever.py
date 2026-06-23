import math
import re
from collections import Counter

from app.services.rag.models import KnowledgeDocument, RetrievedDocument
from app.services.rag.vector_store import load_index


def keyword_search(query: str, top_k: int) -> list[RetrievedDocument]:
    rows = load_index().get("documents", [])
    if not rows:
        return []

    documents = [_doc_from_row(row) for row in rows]
    query_terms = _tokenize(query)
    if not query_terms:
        return []

    doc_term_counts = [Counter(_tokenize(_document_text(document))) for document in documents]
    doc_lengths = [sum(counts.values()) for counts in doc_term_counts]
    avg_doc_len = sum(doc_lengths) / max(len(doc_lengths), 1)
    document_frequency = Counter()
    for counts in doc_term_counts:
        for term in set(counts):
            document_frequency[term] += 1

    scored = []
    for document, counts, doc_len in zip(documents, doc_term_counts, doc_lengths):
        score = _bm25_score(query_terms, counts, doc_len, avg_doc_len, document_frequency, len(documents))
        if score > 0:
            scored.append((score, document))
    scored.sort(key=lambda item: item[0], reverse=True)
    return [RetrievedDocument(document=document, score=round(score, 6)) for score, document in scored[:top_k]]


def _bm25_score(
    query_terms: list[str],
    counts: Counter[str],
    doc_len: int,
    avg_doc_len: float,
    document_frequency: Counter[str],
    total_docs: int,
) -> float:
    k1 = 1.5
    b = 0.75
    score = 0.0
    for term in query_terms:
        tf = counts.get(term, 0)
        if not tf:
            continue
        df = document_frequency.get(term, 0)
        idf = math.log(1 + (total_docs - df + 0.5) / (df + 0.5))
        denominator = tf + k1 * (1 - b + b * doc_len / max(avg_doc_len, 1))
        score += idf * (tf * (k1 + 1)) / denominator
    return score


def _tokenize(text: str) -> list[str]:
    return [token for token in re.findall(r"[a-zA-Z0-9_.-]+", text.lower()) if len(token) > 1]


def _document_text(document: KnowledgeDocument) -> str:
    metadata = " ".join(f"{key}:{value}" for key, value in document.metadata.items() if value)
    return f"{document.title}\n{metadata}\n{document.content}"


def _doc_from_row(row: dict) -> KnowledgeDocument:
    data = row["document"]
    return KnowledgeDocument(
        id=data["id"],
        source_type=data["source_type"],
        title=data["title"],
        path=data["path"],
        content=data["content"],
        metadata=data.get("metadata", {}),
    )
