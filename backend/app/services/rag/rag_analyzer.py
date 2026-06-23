from app.schemas.hunt_package import HuntPackage
from app.schemas.threat_report import ThreatReportRequest
from app.services.hunt_packages.store import save_hunt_package
from app.services.rag.llm_client import generate_hunt_package_json
from app.services.rag.retriever import retrieve_context
from app.services.rag.validator import validate_or_repair
from app.services.threat_reports.analyzer import analyze_report as analyze_hybrid


def analyze_report_with_rag(request: ThreatReportRequest) -> HuntPackage:
    baseline = analyze_hybrid(request)
    context = retrieve_context(baseline.report_title, request.content)
    llm_payload = generate_hunt_package_json(request, context, baseline)
    package = validate_or_repair(llm_payload, baseline, context)
    return save_hunt_package(package)
