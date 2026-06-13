from fastapi import APIRouter, HTTPException

from app.schemas.hunt_package import HuntPackage, HuntPackageListItem
from app.services.hunt_packages.store import get_hunt_package, list_hunt_packages

router = APIRouter(prefix="/api/hunt-packages", tags=["hunt-packages"])


@router.get("", response_model=list[HuntPackageListItem])
def list_packages() -> list[HuntPackageListItem]:
    return list_hunt_packages()


@router.get("/{package_id}", response_model=HuntPackage)
def get_package(package_id: str) -> HuntPackage:
    package = get_hunt_package(package_id)
    if package is None:
        raise HTTPException(status_code=404, detail="Hunt package not found in in-memory MVP store.")
    return package
