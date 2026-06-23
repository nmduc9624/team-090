from app.core.config import get_settings
from app.schemas.hunt_package import HuntPackage
from app.schemas.threat_report import ThreatReportRequest
from app.services.rag.rag_analyzer import analyze_report_with_rag
from app.services.threat_reports.analyzer import analyze_report as analyze_hybrid


def analyze_report(request: ThreatReportRequest) -> HuntPackage:
    settings = get_settings()
    mode = settings.analyzer_mode.lower()
    if mode in {"rag", "llm"}:
        return analyze_report_with_rag(request)
    return analyze_hybrid(request)
