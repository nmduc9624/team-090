from pydantic import BaseModel, Field


class RagSource(BaseModel):
    id: str
    source_type: str
    title: str
    path: str
    score: float = 0.0
    metadata: dict[str, str] = Field(default_factory=dict)


class RagStatus(BaseModel):
    enabled: bool
    analyzer_mode: str
    vector_store: str
    index_path: str
    indexed_documents: int
    embedding_provider: str
    llm_provider: str
    openai_configured: bool


class RagReindexResponse(RagStatus):
    rebuilt: bool
    message: str
