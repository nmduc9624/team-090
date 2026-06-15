from fastapi import APIRouter

from app.services.query_generation.template_loader import list_query_templates
from app.services.telemetry_schemas.loader import load_log_schema
from app.services.threat_reports.sample_loader import get_sample_report, list_sample_reports
from app.services.ttp_mapping.mapper import load_mitre_mapping_text

router = APIRouter(prefix="/api/data", tags=["data"])


@router.get("/log-schema")
def get_log_schema():
    return load_log_schema()


@router.get("/query-templates")
def get_query_templates():
    return list_query_templates()


@router.get("/mitre-mapping")
def get_mitre_mapping():
    return {"content": load_mitre_mapping_text()}


@router.get("/sample-reports")
def get_sample_reports():
    return list_sample_reports()


@router.get("/sample-reports/{slug}")
def get_sample_report_by_slug(slug: str):
    return get_sample_report(slug)
