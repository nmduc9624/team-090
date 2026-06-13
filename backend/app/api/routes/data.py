from fastapi import APIRouter

from app.services.query_generation.template_loader import list_query_templates
from app.services.telemetry_schemas.loader import load_log_schema
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
