import json
from pathlib import Path

from fastapi import HTTPException

from app.core.config import get_settings
from app.schemas.data import AlertCatalogItem, SampleReport


def _catalog_path() -> Path:
    return Path(get_settings().data_dir) / "alert_catalog" / "alert_types_100.json"


def _samples_root() -> Path:
    return Path(get_settings().data_dir) / "threat_reports" / "samples"


def list_sample_reports() -> list[AlertCatalogItem]:
    path = _catalog_path()
    if not path.exists():
        return []
    raw = json.loads(path.read_text(encoding="utf-8"))
    return [AlertCatalogItem(**item) for item in raw]


def get_sample_report(slug: str) -> SampleReport:
    catalog = {item.slug: item for item in list_sample_reports()}
    if slug not in catalog:
        raise HTTPException(status_code=404, detail="Sample report not found")

    report_path = _samples_root() / f"{slug}.md"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Sample report content not found")

    item = catalog[slug]
    return SampleReport(
        slug=item.slug,
        alert_name=item.alert_name,
        alert_source=item.alert_source,
        severity=item.severity,
        category=item.category,
        content=report_path.read_text(encoding="utf-8"),
    )
