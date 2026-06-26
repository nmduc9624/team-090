from typing import Any

from google.cloud import firestore

from app.services.firestore.base import FirestoreRepository, utc_now_iso


class NotificationsRepository(FirestoreRepository):
    def add_discord_reply_notification(
        self,
        case_id: str,
        data: dict[str, Any],
    ) -> str | None:
        if not self.enabled:
            return None

        case_doc = self.db.document(f"cases/{case_id}").get()
        case_data = case_doc.to_dict() or {}
        owner_user_id = case_data.get("owner_user_id") or case_data.get("created_by")
        if not owner_user_id:
            return None

        payload = {
            "type": "discord_supervisor_reply",
            "case_id": case_id,
            "case_title": case_data.get("title", data.get("alert_title", "")),
            "message": data.get("message", ""),
            "author_name": data.get("author_name", ""),
            "author_id": data.get("author_id", ""),
            "channel_id": data.get("channel_id", ""),
            "channel_name": data.get("channel_name", ""),
            "message_url": data.get("message_url", ""),
            "source": "discord",
            "read": False,
            "created_at": utc_now_iso(),
        }
        notification_id = self.add_document(f"users/{owner_user_id}/notifications", payload)
        if notification_id:
            self.set_document(
                f"cases/{case_id}/notifications/{notification_id}",
                {
                    **payload,
                    "notification_id": notification_id,
                    "owner_user_id": owner_user_id,
                },
            )
        return notification_id

    def list_user_notifications(self, user_id: str, limit: int = 20) -> list[dict[str, Any]]:
        if not self.enabled:
            return []

        query = (
            self.db.collection(f"users/{user_id}/notifications")
            .order_by("created_at", direction=firestore.Query.DESCENDING)
            .limit(limit)
        )
        notifications: list[dict[str, Any]] = []
        for doc in query.stream():
            data = doc.to_dict() or {}
            notifications.append({"notification_id": doc.id, **data})
        return notifications

    def mark_user_notification_read(self, user_id: str, notification_id: str) -> bool:
        return self.set_document(
            f"users/{user_id}/notifications/{notification_id}",
            {
                "read": True,
                "read_at": utc_now_iso(),
            },
        )
