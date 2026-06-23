import hashlib
import json
import math
import re
import urllib.request

from app.core.config import get_settings


LOCAL_EMBEDDING_DIMENSIONS = 384


def embed_text(text: str) -> list[float]:
    settings = get_settings()
    if settings.ai_provider.lower() == "openai" and settings.openai_api_key:
        try:
            return _openai_embedding(text)
        except Exception:
            return _local_embedding(text)
    return _local_embedding(text)


def embed_texts(texts: list[str]) -> list[list[float]]:
    settings = get_settings()
    if settings.ai_provider.lower() == "openai" and settings.openai_api_key:
        try:
            return _openai_embeddings(texts)
        except Exception:
            return [_local_embedding(text) for text in texts]
    return [_local_embedding(text) for text in texts]


def embedding_provider_name() -> str:
    settings = get_settings()
    if settings.ai_provider.lower() == "openai" and settings.openai_api_key:
        return f"openai:{settings.openai_embedding_model}"
    return "local-hash"


def cosine_similarity(left: list[float], right: list[float]) -> float:
    if not left or not right or len(left) != len(right):
        return 0.0
    dot = sum(a * b for a, b in zip(left, right))
    left_norm = math.sqrt(sum(a * a for a in left))
    right_norm = math.sqrt(sum(b * b for b in right))
    if not left_norm or not right_norm:
        return 0.0
    return dot / (left_norm * right_norm)


def _local_embedding(text: str) -> list[float]:
    vector = [0.0] * LOCAL_EMBEDDING_DIMENSIONS
    tokens = re.findall(r"[a-zA-Z0-9_.-]+", text.lower())
    for token in tokens:
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        idx = int.from_bytes(digest[:4], "big") % LOCAL_EMBEDDING_DIMENSIONS
        sign = 1.0 if digest[4] % 2 == 0 else -1.0
        vector[idx] += sign
    norm = math.sqrt(sum(item * item for item in vector)) or 1.0
    return [item / norm for item in vector]


def _openai_embedding(text: str) -> list[float]:
    return _openai_embeddings([text])[0]


def _openai_embeddings(texts: list[str]) -> list[list[float]]:
    settings = get_settings()
    body = json.dumps(
        {
            "model": settings.openai_embedding_model,
            "input": [text[:12000] for text in texts],
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        "https://api.openai.com/v1/embeddings",
        data=body,
        headers={
            "Authorization": f"Bearer {settings.openai_api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.loads(response.read().decode("utf-8"))
    ordered = sorted(payload["data"], key=lambda item: item["index"])
    return [item["embedding"] for item in ordered]
