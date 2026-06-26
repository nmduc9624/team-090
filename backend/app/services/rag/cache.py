import hashlib
import json
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.schemas.hunt_package import HuntPackage
from app.schemas.threat_report import ThreatReportRequest


CACHE_VERSION = "rag-hunt-package-v2"


def get_cached_hunt_package(request: ThreatReportRequest) -> HuntPackage | None:
    settings = get_settings()
    if not settings.rag_cache_enabled:
        return None
    cache = _read_cache()
    payload = cache.get(_cache_key(request))
    if not isinstance(payload, dict):
        return None
    try:
        package = HuntPackage.model_validate(payload)
    except Exception:
        return None
    package.analyst_notes = f"{package.analyst_notes}\n\nRAG cache: returned cached hunt package for identical report input.".strip()
    return package


def store_cached_hunt_package(request: ThreatReportRequest, package: HuntPackage) -> None:
    settings = get_settings()
    if not settings.rag_cache_enabled:
        return
    cache = _read_cache()
    cache[_cache_key(request)] = package.model_dump()
    path = _cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cache, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _cache_key(request: ThreatReportRequest) -> str:
    settings = get_settings()
    payload: dict[str, Any] = {
        "version": CACHE_VERSION,
        "title": request.title or "",
        "content": request.content,
        "provider": settings.ai_provider,
        "mode": settings.analyzer_mode,
        "chat_model": settings.openai_chat_model,
        "top_k": settings.rag_top_k,
        "context_chars": settings.rag_context_chars,
    }
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _cache_path() -> Path:
    settings = get_settings()
    return Path(settings.data_dir) / "rag" / "cache" / "hunt_package_cache.json"


def _read_cache() -> dict[str, Any]:
    path = _cache_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}
