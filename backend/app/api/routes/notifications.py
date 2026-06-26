from fastapi import APIRouter, Depends, HTTPException, status

from app.core.auth import AuthenticatedUser, get_current_user
from app.services.firestore.notifications_repository import NotificationsRepository

router = APIRouter(prefix="/api/notifications", tags=["notifications"])


@router.get("")
def list_notifications(
    current_user: AuthenticatedUser | None = Depends(get_current_user),
):
    if not current_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required.")

    return {
        "notifications": NotificationsRepository().list_user_notifications(current_user.uid),
    }


@router.post("/{notification_id}/read")
def mark_notification_read(
    notification_id: str,
    current_user: AuthenticatedUser | None = Depends(get_current_user),
):
    if not current_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required.")

    NotificationsRepository().mark_user_notification_read(current_user.uid, notification_id)
    return {"status": "ok"}
