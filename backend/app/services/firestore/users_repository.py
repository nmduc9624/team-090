from typing import Any

from app.services.firestore.base import FirestoreRepository, utc_now_iso


class UsersRepository(FirestoreRepository):
    def upsert_user(self, uid: str, data: dict[str, Any]) -> bool:
        payload = {
            "uid": uid,
            "updated_at": utc_now_iso(),
            **data,
        }
        return self.set_document(f"users/{uid}", payload)
