from typing import Any

from app.services.firestore.base import FirestoreRepository, utc_now_iso


class WarningsRepository(FirestoreRepository):
    def add_warning(
        self,
        case_id: str,
        warning_type: str,
        data: dict[str, Any],
        user: Any | None = None,
    ) -> str | None:
        return self.add_document(
            f"cases/{case_id}/warnings",
            {
                "type": warning_type,
                "status": "created",
                "created_by": getattr(user, "uid", None),
                "created_at": utc_now_iso(),
                **data,
            },
        )
