from typing import Any

from app.services.firestore.base import FirestoreRepository, utc_now_iso


class HelpRequestsRepository(FirestoreRepository):
    def add_help_request(self, case_id: str, data: dict[str, Any], user: Any | None = None) -> str | None:
        return self.add_document(
            f"cases/{case_id}/help_requests",
            {
                "status": "open",
                "created_by": getattr(user, "uid", None),
                "created_at": utc_now_iso(),
                **data,
            },
        )

    def add_reply(
        self,
        case_id: str,
        help_request_id: str,
        data: dict[str, Any],
        user: Any | None = None,
    ) -> str | None:
        return self.add_document(
            f"cases/{case_id}/help_requests/{help_request_id}/replies",
            {
                "author_uid": getattr(user, "uid", None),
                "created_at": utc_now_iso(),
                **data,
            },
        )
