from fastapi import APIRouter, Depends

from app.core.auth import AuthenticatedUser, get_current_user
from app.core.config import get_settings

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.get("/me")
def get_me(current_user: AuthenticatedUser | None = Depends(get_current_user)):
    settings = get_settings()
    return {
        "authenticated": current_user is not None,
        "firebase_require_auth": settings.firebase_require_auth,
        "firestore_enabled": settings.firestore_enabled,
        "firebase_project_id": settings.firebase_project_id,
        "user": current_user.__dict__ if current_user else None,
    }
