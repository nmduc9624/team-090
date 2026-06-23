from dataclasses import dataclass, field


@dataclass(frozen=True)
class KnowledgeDocument:
    id: str
    source_type: str
    title: str
    path: str
    content: str
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class RetrievedDocument:
    document: KnowledgeDocument
    score: float


@dataclass(frozen=True)
class IntentContext:
    name: str
    categories: tuple[str, ...]
    telemetry_allow: tuple[str, ...]
    mitre_allow_prefixes: tuple[str, ...]
    query_keywords: tuple[str, ...]
    blocked_keywords: tuple[str, ...]
    required_telemetry: tuple[str, ...] = ()
    blocked_telemetry: tuple[str, ...] = ()
    checklist: tuple[str, ...] = ()
    correlation_logic: str = ""
    escalation_condition: str = ""


@dataclass(frozen=True)
class RagContext:
    intent: IntentContext
    retrieved: tuple[RetrievedDocument, ...]

    def citations_text(self) -> str:
        lines = []
        for item in self.retrieved:
            doc = item.document
            lines.append(f"- {doc.title} ({doc.source_type}, {doc.path}, score={item.score:.3f})")
        return "\n".join(lines)
