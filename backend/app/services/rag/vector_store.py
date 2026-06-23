import json
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.services.rag.embeddings import cosine_similarity, embed_text, embed_texts, embedding_provider_name
from app.services.rag.models import KnowledgeDocument, RetrievedDocument


def index_path() -> Path:
    settings = get_settings()
    if settings.rag_index_path:
        return Path(settings.rag_index_path)
    return Path(settings.data_dir) / "rag" / "index" / "local_vector_index.json"


def save_index(documents: list[KnowledgeDocument]) -> dict[str, Any]:
    path = index_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    embedding_inputs = [_embedding_text(document) for document in documents]
    embeddings = _embed_in_batches(embedding_inputs)
    rows = []
    for document, embedding in zip(documents, embeddings):
        rows.append(
            {
                "document": _doc_to_dict(document),
                "embedding": embedding,
            }
        )
    payload = {
        "embedding_provider": embedding_provider_name(),
        "documents": rows,
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {"path": str(path), "document_count": len(rows), "embedding_provider": payload["embedding_provider"]}


def _embed_in_batches(texts: list[str], batch_size: int = 64) -> list[list[float]]:
    vectors: list[list[float]] = []
    for start in range(0, len(texts), batch_size):
        vectors.extend(embed_texts(texts[start : start + batch_size]))
    return vectors


def load_index() -> dict[str, Any]:
    path = index_path()
    if not path.exists():
        return {"embedding_provider": embedding_provider_name(), "documents": []}
    return json.loads(path.read_text(encoding="utf-8"))


def indexed_document_count() -> int:
    return len(load_index().get("documents", []))


def search_index(query: str, top_k: int) -> list[RetrievedDocument]:
    payload = load_index()
    rows = payload.get("documents", [])
    if not rows:
        return []
    query_embedding = embed_text(query)
    scored = []
    for row in rows:
        score = cosine_similarity(query_embedding, row.get("embedding", []))
        scored.append((score, _doc_from_dict(row["document"])))
    scored.sort(key=lambda item: item[0], reverse=True)
    return [RetrievedDocument(document=document, score=round(score, 6)) for score, document in scored[:top_k]]


def _embedding_text(document: KnowledgeDocument) -> str:
    metadata = " ".join(f"{key}:{value}" for key, value in document.metadata.items() if value)
    return f"{document.title}\n{metadata}\n{document.content}"


def _doc_to_dict(document: KnowledgeDocument) -> dict[str, Any]:
    return {
        "id": document.id,
        "source_type": document.source_type,
        "title": document.title,
        "path": document.path,
        "content": document.content,
        "metadata": document.metadata,
    }


def _doc_from_dict(data: dict[str, Any]) -> KnowledgeDocument:
    return KnowledgeDocument(
        id=data["id"],
        source_type=data["source_type"],
        title=data["title"],
        path=data["path"],
        content=data["content"],
        metadata=data.get("metadata", {}),
    )
