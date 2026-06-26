from datetime import UTC, datetime
from typing import Any

from app.core.config import get_settings
from app.core.firebase import get_firestore_client


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


class FirestoreRepository:
    def __init__(self):
        self.settings = get_settings()

    @property
    def enabled(self) -> bool:
        return bool(self.settings.firestore_enabled)

    @property
    def db(self):
        if not self.enabled:
            return None
        return get_firestore_client()

    def set_document(self, path: str, data: dict[str, Any], merge: bool = True) -> bool:
        if not self.enabled:
            return False
        self.db.document(path).set(data, merge=merge)
        return True

    def add_document(self, collection_path: str, data: dict[str, Any]) -> str | None:
        if not self.enabled:
            return None
        _, ref = self.db.collection(collection_path).add(data)
        return ref.id
