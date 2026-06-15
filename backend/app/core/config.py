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
    openai_api_key: str | None = None
    data_dir: Path = Path(__file__).resolve().parents[3] / "data"
    cors_origins: list[str] = ["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:5173", "http://127.0.0.1:5173"]

    if hasattr(BaseSettings, "model_config"):
        model_config = {"env_file": ".env", "env_prefix": "APP_"}


@lru_cache
def get_settings() -> Settings:
    return Settings()

