from app.services.rag.knowledge_loader import chunk_document, load_knowledge_documents
from app.services.rag.vector_store import save_index


def rebuild_rag_index() -> dict[str, str | int]:
    documents = []
    for document in load_knowledge_documents():
        documents.extend(chunk_document(document))
    result = save_index(documents)
    return {
        "path": result["path"],
        "document_count": result["document_count"],
        "embedding_provider": result["embedding_provider"],
    }
