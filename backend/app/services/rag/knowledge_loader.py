import json
from pathlib import Path
from typing import Any

import yaml

from app.core.config import get_settings
from app.services.rag.models import KnowledgeDocument


TEXT_SUFFIXES = {".md", ".txt", ".kql", ".spl", ".yml", ".yaml"}


def load_knowledge_documents() -> list[KnowledgeDocument]:
    settings = get_settings()
    data_dir = Path(settings.data_dir)
    documents: list[KnowledgeDocument] = []
    documents.extend(_load_text_tree(data_dir / "playbooks", "playbook"))
    documents.extend(_load_text_tree(data_dir / "rag" / "reference", "reference"))
    documents.extend(_load_text_tree(data_dir / "mitre", "mitre"))
    documents.extend(_load_text_tree(data_dir / "query_templates", "query_template"))
    documents.extend(_load_text_tree(data_dir / "log_schemas", "schema"))
    documents.extend(_load_text_tree(data_dir / "guardrails", "guardrail"))
    documents.extend(_load_expected_cases(data_dir.parent / "evaluation" / "datasets" / "expected_hunt_packages"))
    documents.extend(_load_sample_reports(data_dir / "threat_reports" / "samples"))
    return documents


def chunk_document(document: KnowledgeDocument, max_chars: int = 1800) -> list[KnowledgeDocument]:
    content = document.content.strip()
    if len(content) <= max_chars:
        return [document]

    chunks = []
    parts = [part.strip() for part in content.split("\n\n") if part.strip()]
    buffer = ""
    idx = 1
    for part in parts:
        if len(buffer) + len(part) + 2 > max_chars and buffer:
            chunks.append(_chunk(document, idx, buffer))
            idx += 1
            buffer = part
        else:
            buffer = f"{buffer}\n\n{part}".strip()
    if buffer:
        chunks.append(_chunk(document, idx, buffer))
    return chunks


def _chunk(document: KnowledgeDocument, idx: int, content: str) -> KnowledgeDocument:
    metadata = dict(document.metadata)
    metadata["chunk"] = str(idx)
    return KnowledgeDocument(
        id=f"{document.id}#chunk-{idx}",
        source_type=document.source_type,
        title=f"{document.title} (chunk {idx})",
        path=document.path,
        content=content,
        metadata=metadata,
    )


def _load_text_tree(root: Path, source_type: str) -> list[KnowledgeDocument]:
    if not root.exists():
        return []
    docs = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        content = path.read_text(encoding="utf-8")
        metadata = _infer_metadata(path, content)
        metadata["source_type"] = source_type
        docs.append(
            KnowledgeDocument(
                id=_doc_id(source_type, path),
                source_type=source_type,
                title=_title_from_path(path),
                path=str(path),
                content=content,
                metadata=metadata,
            )
        )
    return docs


def _load_expected_cases(root: Path) -> list[KnowledgeDocument]:
    if not root.exists():
        return []
    docs = []
    for path in sorted(root.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        title = data.get("report_title") or path.stem.replace("_", " ").title()
        content = json.dumps(data, ensure_ascii=False, indent=2)
        metadata = _infer_metadata(path, content)
        metadata.update(
            {
                "source_type": "case",
                "alert_type": path.stem,
                "category": _category_from_text(content),
                "severity": data.get("severity", ""),
            }
        )
        docs.append(
            KnowledgeDocument(
                id=_doc_id("case", path),
                source_type="case",
                title=title,
                path=str(path),
                content=content,
                metadata=metadata,
            )
        )
    return docs


def _load_sample_reports(root: Path) -> list[KnowledgeDocument]:
    if not root.exists():
        return []
    docs = []
    for path in sorted(root.glob("*.md")):
        content = path.read_text(encoding="utf-8")
        metadata = _infer_metadata(path, content)
        metadata.update({"source_type": "sample_report", "alert_type": path.stem})
        docs.append(
            KnowledgeDocument(
                id=_doc_id("sample_report", path),
                source_type="sample_report",
                title=_title_from_markdown(path.stem, content),
                path=str(path),
                content=content,
                metadata=metadata,
            )
        )
    return docs


def _infer_metadata(path: Path, content: str) -> dict[str, str]:
    lower = f"{path.as_posix()}\n{content}".lower()
    metadata: dict[str, str] = {
        "category": _category_from_text(lower),
        "telemetry": _telemetry_from_text(lower),
        "mitre_id": _mitre_from_text(content),
        "platform": path.parent.name.upper() if path.suffix.lower() in {".kql", ".spl"} else "",
    }
    if path.suffix.lower() in {".yml", ".yaml"}:
        try:
            loaded: Any = yaml.safe_load(content)
            if isinstance(loaded, dict) and "context" in loaded:
                metadata["category"] = str(loaded["context"]).lower()
        except Exception:
            pass
    return metadata


def _category_from_text(text: str) -> str:
    lower = text.lower()
    if any(token in lower for token in ["github", "gitlab", "repository", "deploy key", "secrets metadata"]):
        return "developer_platform"
    if any(token in lower for token in ["oauth", "slack", "saas", "channel", "consent"]):
        return "saas"
    if any(token in lower for token in ["password spray", "brute force", "mfa", "login", "auth"]):
        return "identity"
    if any(token in lower for token in ["linux", "cron", "sudoers", "ssh"]):
        return "linux"
    if any(token in lower for token in ["dns", "nxdomain", "tunneling", "dga"]):
        return "dns"
    if any(token in lower for token in ["cloud", "iam", "bucket", "metadata", "access key"]):
        return "cloud"
    if any(token in lower for token in ["mshta", "registry", "powershell", ".exe", "lsass"]):
        return "endpoint"
    return ""


def _telemetry_from_text(text: str) -> str:
    for telemetry in [
        "edr_process",
        "edr_registry",
        "linux_process",
        "linux_audit",
        "cloud_audit",
        "email_audit",
        "dns",
        "proxy",
        "auth",
        "firewall",
    ]:
        if telemetry in text:
            return telemetry
    return ""


def _mitre_from_text(content: str) -> str:
    import re

    found = re.findall(r"T\d{4}(?:\.\d{3})?", content)
    return ",".join(sorted(set(found))[:8])


def _title_from_path(path: Path) -> str:
    return path.stem.replace("_", " ").replace("-", " ").title()


def _title_from_markdown(slug: str, content: str) -> str:
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            return stripped.strip("# ").strip()
    return slug.replace("_", " ").title()


def _doc_id(source_type: str, path: Path) -> str:
    return f"{source_type}:{path.as_posix()}"
