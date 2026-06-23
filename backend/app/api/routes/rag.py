from fastapi import APIRouter

from app.core.config import get_settings
from app.schemas.rag import RagReindexResponse, RagStatus
from app.services.rag.embeddings import embedding_provider_name
from app.services.rag.indexer import rebuild_rag_index
from app.services.rag.vector_store import index_path, indexed_document_count

router = APIRouter(prefix="/api/rag", tags=["rag"])


@router.get("/status", response_model=RagStatus)
def get_rag_status() -> RagStatus:
    settings = get_settings()
    return RagStatus(
        enabled=settings.analyzer_mode.lower() in {"rag", "llm"},
        analyzer_mode=settings.analyzer_mode,
        vector_store=settings.vector_store,
        index_path=str(index_path()),
        indexed_documents=indexed_document_count(),
        embedding_provider=embedding_provider_name(),
        llm_provider=settings.ai_provider,
        openai_configured=bool(settings.openai_api_key),
    )


@router.post("/reindex", response_model=RagReindexResponse)
def reindex_rag() -> RagReindexResponse:
    result = rebuild_rag_index()
    status = get_rag_status()
    return RagReindexResponse(
        rebuilt=True,
        enabled=status.enabled,
        analyzer_mode=status.analyzer_mode,
        vector_store=status.vector_store,
        index_path=status.index_path,
        indexed_documents=int(result["document_count"]),
        embedding_provider=str(result["embedding_provider"]),
        llm_provider=status.llm_provider,
        openai_configured=status.openai_configured,
        message=f"Rebuilt RAG index at {result['path']}.",
    )
