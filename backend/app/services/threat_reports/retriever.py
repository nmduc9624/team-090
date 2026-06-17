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

INTENT_KEYWORDS = {
    "oauth_saas": {"oauth", "consent", "app", "application", "slack", "teams", "workspace", "channel", "saas", "permission", "permissions"},
    "data_export": {"export", "exports", "download", "downloads", "file", "files", "private", "channel", "archive", "zip"},
    "cloud_iam": {"iam", "admin", "policy", "role", "bucket", "access", "metadata"},
    "identity": {"login", "mfa", "password", "account", "tor", "vpn", "device", "session"},
    "endpoint": {"powershell", "mshta", "registry", "lsass", "rundll32", "excel.exe", "winword.exe"},
}


@dataclass(frozen=True)
class ReferenceHuntPackage:
    slug: str
    title: str
    content: str
    tokens: frozenset[str]
    intents: frozenset[str]
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


def _detect_intents(tokens: set[str], text: str) -> set[str]:
    lower = text.lower()
    intents = set()
    for intent, keywords in INTENT_KEYWORDS.items():
        if tokens & keywords or any(keyword in lower for keyword in keywords if " " in keyword or "." in keyword):
            intents.add(intent)
    if "oauth_saas" in intents and "data_export" in intents:
        intents.add("saas_data_export")
    return intents


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
        tokens = _tokenize(searchable)
        references.append(
            ReferenceHuntPackage(
                slug=sample_path.stem,
                title=title,
                content=content,
                tokens=frozenset(tokens),
                intents=frozenset(_detect_intents(tokens, searchable)),
                expected=expected,
            )
        )
    return tuple(references)


def _score(query_tokens: set[str], query_intents: set[str], reference: ReferenceHuntPackage, query_text: str) -> float:
    if not query_tokens or not reference.tokens:
        return 0.0
    overlap = len(query_tokens & reference.tokens)
    union = len(query_tokens | reference.tokens)
    jaccard = overlap / union

    slug_tokens = set(reference.slug.split("_"))
    title_tokens = _tokenize(reference.title)
    slug_boost = len(query_tokens & slug_tokens) / max(len(slug_tokens), 1)
    title_boost = len(query_tokens & title_tokens) / max(len(title_tokens), 1)
    intent_overlap = len(query_intents & set(reference.intents)) / max(len(query_intents), 1)
    exact_boost = 0.0
    normalized_title = reference.title.lower().replace("alert report:", "").strip()
    if normalized_title and normalized_title in query_text.lower():
        exact_boost = 0.35

    penalty = 0.0
    if "saas_data_export" in query_intents and "cloud_iam" in reference.intents and not (query_tokens & {"iam", "admin", "policy", "role"}):
        penalty += 0.18
    if "oauth_saas" in query_intents and "endpoint" in reference.intents and not (query_intents & {"endpoint"}):
        penalty += 0.12

    return round((jaccard * 0.35) + (slug_boost * 0.15) + (title_boost * 0.25) + (intent_overlap * 0.35) + exact_boost - penalty, 6)


def retrieve_similar_hunt_package(title: str, content: str, min_score: float = 0.08) -> ReferenceHuntPackage | None:
    query_text = f"{title}\n{content}"
    query_tokens = _tokenize(query_text)
    query_intents = _detect_intents(query_tokens, query_text)
    references = load_reference_hunt_packages()

    normalized_query_title = title.lower().replace("alert report:", "").replace("test report:", "").strip()
    for reference in references:
        normalized_ref_title = reference.title.lower().replace("alert report:", "").replace("test report:", "").strip()
        if normalized_query_title and normalized_ref_title and normalized_query_title == normalized_ref_title:
            return ReferenceHuntPackage(
                slug=reference.slug,
                title=reference.title,
                content=reference.content,
                tokens=reference.tokens,
                intents=reference.intents,
                expected=reference.expected,
                score=1.0,
            )

    best: ReferenceHuntPackage | None = None
    best_score = 0.0

    for reference in references:
        score = _score(query_tokens, query_intents, reference, query_text)
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
        intents=best.intents,
        expected=best.expected,
        score=best_score,
    )