from functools import lru_cache
import os
from pathlib import Path

import firebase_admin
from firebase_admin import credentials, firestore
from dotenv import load_dotenv

from app.core.config import get_settings


@lru_cache
def get_firebase_app():
    settings = get_settings()
    if firebase_admin._apps:
        return firebase_admin.get_app()

    backend_env = Path(__file__).resolve().parents[2] / ".env"
    load_dotenv(backend_env)
    credential_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")

    if credential_path and Path(credential_path).exists():
        return firebase_admin.initialize_app(
            credentials.Certificate(credential_path),
            {"projectId": settings.firebase_project_id} if settings.firebase_project_id else None,
        )

    if settings.firebase_project_id:
        try:
            return firebase_admin.initialize_app(
                credentials.ApplicationDefault(),
                {"projectId": settings.firebase_project_id},
            )
        except Exception:
            # Fall back to default initialization. This still respects
            # GOOGLE_APPLICATION_CREDENTIALS when it is configured.
            return firebase_admin.initialize_app()

    return firebase_admin.initialize_app()


@lru_cache
def get_firestore_client():
    get_firebase_app()
    return firestore.client()
