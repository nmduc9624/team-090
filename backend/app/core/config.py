from functools import lru_cache
from pathlib import Path

try:
    from pydantic_settings import BaseSettings
except Exception:  # pragma: no cover - fallback for minimal local checks
    BaseSettings = object


class Settings(BaseSettings):
    app_name: str = "AI Threat Intel to Hunt Package Assistant"
    app_version: str = "0.1.0"
    ai_provider: str = "mock"
    analyzer_mode: str = "hybrid"
    openai_api_key: str | None = None
    openai_chat_model: str = "gpt-4.1-mini"
    openai_embedding_model: str = "text-embedding-3-small"
    vector_store: str = "local"
    rag_top_k: int = 8
    rag_index_path: Path | None = None
    data_dir: Path = Path(__file__).resolve().parents[3] / "data"
    cors_origins: list[str] = ["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:5173", "http://127.0.0.1:5173"]

    if hasattr(BaseSettings, "model_config"):
        model_config = {"env_file": ".env", "env_prefix": "APP_", "extra": "ignore"}


@lru_cache
def get_settings() -> Settings:
    return Settings()

