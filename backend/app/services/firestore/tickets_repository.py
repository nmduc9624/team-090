from typing import Any

from app.services.firestore.base import FirestoreRepository, utc_now_iso


class TicketsRepository(FirestoreRepository):
    def upsert_ticket(self, case_id: str, data: dict[str, Any], user: Any | None = None) -> bool:
        return self.set_document(
            f"discord_tickets/{case_id}",
            {
                "case_id": case_id,
                "updated_at": utc_now_iso(),
                "updated_by": getattr(user, "uid", None),
                **data,
            },
        )
