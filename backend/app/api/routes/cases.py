from fastapi import APIRouter, Depends, HTTPException, status

from app.core.auth import AuthenticatedUser, get_current_user
from app.services.firestore.cases_repository import CasesRepository

router = APIRouter(prefix="/api/cases", tags=["cases"])


@router.get("")
def list_cases(current_user: AuthenticatedUser | None = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required.")
    return {"cases": CasesRepository().list_user_cases(current_user.uid)}


@router.get("/{case_id}")
def get_case_detail(case_id: str, current_user: AuthenticatedUser | None = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required.")

    detail = CasesRepository().get_user_case_detail(case_id, current_user.uid)
    if not detail:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found.")
    return detail
