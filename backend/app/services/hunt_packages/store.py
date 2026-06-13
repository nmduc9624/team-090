from app.schemas.hunt_package import HuntPackage, HuntPackageListItem


_STORE: dict[str, HuntPackage] = {}


def save_hunt_package(package: HuntPackage) -> HuntPackage:
    _STORE[package.package_id] = package
    return package


def get_hunt_package(package_id: str) -> HuntPackage | None:
    return _STORE.get(package_id)


def list_hunt_packages() -> list[HuntPackageListItem]:
    return [
        HuntPackageListItem(
            package_id=item.package_id,
            report_title=item.report_title,
            threat_summary=item.threat_summary,
        )
        for item in _STORE.values()
    ]
