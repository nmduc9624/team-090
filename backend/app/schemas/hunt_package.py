from pydantic import BaseModel, Field


class IOC(BaseModel):
    domains: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    hashes: list[str] = Field(default_factory=list)
    files: list[str] = Field(default_factory=list)
    processes: list[str] = Field(default_factory=list)
    registry_keys: list[str] = Field(default_factory=list)


class QueryDraft(BaseModel):
    name: str
    platform: str
    query: str
    purpose: str


class HuntPackage(BaseModel):
    package_id: str
    report_title: str
    threat_summary: str
    key_behaviors: list[str] = Field(default_factory=list)
    ioc: IOC = Field(default_factory=IOC)
    mitre_mapping: list[str] = Field(default_factory=list)
    required_telemetry: list[str] = Field(default_factory=list)
    hunt_checklist: list[str] = Field(default_factory=list)
    query_drafts: list[QueryDraft] = Field(default_factory=list)
    correlation_logic: str
    escalation_condition: str
    analyst_notes: str


class HuntPackageListItem(BaseModel):
    package_id: str
    report_title: str
    threat_summary: str
