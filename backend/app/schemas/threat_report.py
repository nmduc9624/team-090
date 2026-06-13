from pydantic import BaseModel, Field


class ThreatReportRequest(BaseModel):
    title: str | None = Field(default=None, description="Optional report title.")
    content: str = Field(min_length=10, description="Threat report text or markdown.")
    source_name: str | None = Field(default=None, description="Optional source/vendor name.")


class ThreatReportSummary(BaseModel):
    id: str
    title: str
    path: str
