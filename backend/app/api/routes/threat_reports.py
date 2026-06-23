from fastapi import APIRouter

from app.schemas.hunt_package import HuntPackage
from app.schemas.threat_report import ThreatReportRequest
from app.services.threat_reports.dispatcher import analyze_report

router = APIRouter(prefix="/api/threat-reports", tags=["threat-reports"])


@router.post("/analyze", response_model=HuntPackage)
def analyze_threat_report(request: ThreatReportRequest) -> HuntPackage:
    return analyze_report(request)
