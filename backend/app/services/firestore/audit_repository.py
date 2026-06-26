from typing import Any

from app.services.firestore.base import FirestoreRepository, utc_now_iso


class AuditRepository(FirestoreRepository):
    def add_event(
        self,
        case_id: str,
        event: str,
        target: str = "",
        metadata: dict[str, Any] | None = None,
        user: Any | None = None,
    ) -> str | None:
        return self.add_document(
            f"cases/{case_id}/audit_logs",
            {
                "event": event,
                "target": target,
                "metadata": metadata or {},
                "actor_uid": getattr(user, "uid", None),
                "actor_role": getattr(user, "role", ""),
                "created_at": utc_now_iso(),
            },
        )
