import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.core.config import get_settings


TOKEN_RE = re.compile(r"[a-z0-9_.-]+")
STOPWORDS = {
    "the", "and", "for", "with", "from", "that", "this", "then", "into", "after",
    "alert", "report", "summary", "observed", "behaviors", "indicators", "analyst",
    "note", "synthetic", "mvp", "none", "data", "type", "case", "source", "severity",
}


@dataclass(frozen=True)
class ReferenceHuntPackage:
    slug: str
    title: str
    content: str
    tokens: frozenset[str]
    expected: dict[str, Any]
    score: float = 0.0


def _project_root() -> Path:
    return Path(__file__).resolve().parents[4]


def _tokenize(text: str) -> set[str]:
    tokens = set()
    for raw in TOKEN_RE.findall(text.lower()):
        token = raw.strip("_.-")
        if len(token) < 3 or token in STOPWORDS:
            continue
        tokens.add(token)
    return tokens


def _title_from_report(content: str, fallback: str) -> str:
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            return stripped.strip("# ")[:160]
    return fallback.replace("_", " ").title()


@lru_cache
def load_reference_hunt_packages() -> tuple[ReferenceHuntPackage, ...]:
    root = _project_root()
    samples_root = Path(get_settings().data_dir) / "threat_reports" / "samples"
    expected_root = root / "evaluation" / "datasets" / "expected_hunt_packages"
    references: list[ReferenceHuntPackage] = []

    for sample_path in sorted(samples_root.glob("*.md")):
        expected_path = expected_root / f"{sample_path.stem}.json"
        if not expected_path.exists():
            continue
        content = sample_path.read_text(encoding="utf-8")
        expected = json.loads(expected_path.read_text(encoding="utf-8"))
        title = _title_from_report(content, sample_path.stem)
        searchable = "\n".join(
            [
                sample_path.stem.replace("_", " "),
                title,
                content,
                expected.get("threat_summary", ""),
                "\n".join(expected.get("key_behaviors", [])),
                "\n".join(expected.get("mitre_mapping", [])),
                "\n".join(expected.get("required_telemetry", [])),
            ]
        )
        references.append(
            ReferenceHuntPackage(
                slug=sample_path.stem,
                title=title,
                content=content,
                tokens=frozenset(_tokenize(searchable)),
                expected=expected,
            )
        )
    return tuple(references)


def _score(query_tokens: set[str], reference: ReferenceHuntPackage, query_text: str) -> float:
    if not query_tokens or not reference.tokens:
        return 0.0
    overlap = len(query_tokens & reference.tokens)
    union = len(query_tokens | reference.tokens)
    jaccard = overlap / union

    slug_tokens = set(reference.slug.split("_"))
    title_tokens = _tokenize(reference.title)
    slug_boost = len(query_tokens & slug_tokens) / max(len(slug_tokens), 1)
    title_boost = len(query_tokens & title_tokens) / max(len(title_tokens), 1)
    exact_boost = 0.0
    normalized_title = reference.title.lower().replace("alert report:", "").strip()
    if normalized_title and normalized_title in query_text.lower():
        exact_boost = 0.35

    return round((jaccard * 0.45) + (slug_boost * 0.20) + (title_boost * 0.30) + exact_boost, 6)


def retrieve_similar_hunt_package(title: str, content: str, min_score: float = 0.08) -> ReferenceHuntPackage | None:
    query_text = f"{title}\n{content}"
    query_tokens = _tokenize(query_text)
    best: ReferenceHuntPackage | None = None
    best_score = 0.0

    for reference in load_reference_hunt_packages():
        score = _score(query_tokens, reference, query_text)
        if score > best_score:
            best = reference
            best_score = score

    if best is None or best_score < min_score:
        return None

    return ReferenceHuntPackage(
        slug=best.slug,
        title=best.title,
        content=best.content,
        tokens=best.tokens,
        expected=best.expected,
        score=best_score,
    )
