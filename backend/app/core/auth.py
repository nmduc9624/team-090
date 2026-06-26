from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, status
from firebase_admin import auth as firebase_auth

from app.core.config import get_settings
from app.core.firebase import get_firebase_app, get_firestore_client


@dataclass
class AuthenticatedUser:
    uid: str
    email: str = ""
    role: str = "anonymous"
    display_name: str = ""
    team_id: str = ""


def _extract_bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    prefix = "Bearer "
    if not authorization.startswith(prefix):
        return None
    return authorization[len(prefix):].strip() or None


def _load_user_profile(uid: str) -> dict:
    settings = get_settings()
    if not settings.firestore_enabled:
        return {}
    try:
        snapshot = get_firestore_client().collection("users").document(uid).get()
        return snapshot.to_dict() or {}
    except Exception:
        return {}


def get_current_user(authorization: str | None = Header(default=None)) -> AuthenticatedUser | None:
    settings = get_settings()
    token = _extract_bearer_token(authorization)

    if not token:
        if settings.firebase_require_auth:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing Firebase bearer token.",
            )
        return None

    try:
        get_firebase_app()
        decoded = firebase_auth.verify_id_token(token)
    except Exception as exc:
        if settings.firebase_require_auth:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid Firebase token: {exc}",
            ) from exc
        return None

    uid = decoded.get("uid", "")
    profile = _load_user_profile(uid)
    return AuthenticatedUser(
        uid=uid,
        email=profile.get("email") or decoded.get("email", ""),
        role=profile.get("role", "unknown"),
        display_name=profile.get("display_name") or decoded.get("name", ""),
        team_id=profile.get("team_id", ""),
    )


CurrentUser = Depends(get_current_user)
