from pydantic import BaseModel, Field, model_validator


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
    telemetry: list[str] = Field(default_factory=list)


class InvestigationStep(BaseModel):
    step_id: str
    title: str
    description: str
    expected_evidence: list[str] = Field(default_factory=list)
    status: str = "pending"
    can_ask_for_help: bool = True


class PriorityAction(BaseModel):
    action_id: str
    title: str
    why_it_matters: str
    recommended_time: str = "first_30_minutes"
    requires_approval: bool = False
    status: str = "pending"


class TimelineEvent(BaseModel):
    order: int
    stage: str
    description: str
    evidence_needed: list[str] = Field(default_factory=list)


class WarningPreview(BaseModel):
    should_send: bool = False
    recipient_role: str = "soc_channel"
    message: str = ""
    requires_confirmation: bool = True


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
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    confidence_reasons: list[str] = Field(default_factory=list)
    severity_hint: str = ""
    risk_explanation: str = ""
    investigation_flow: list[InvestigationStep] = Field(default_factory=list)
    priority_actions: list[PriorityAction] = Field(default_factory=list)
    timeline_or_attack_path: list[TimelineEvent] = Field(default_factory=list)
    false_positive_checks: list[str] = Field(default_factory=list)
    recommended_response: list[str] = Field(default_factory=list)
    warning_preview: WarningPreview = Field(default_factory=WarningPreview)

    @model_validator(mode="after")
    def populate_workflow_fields(self) -> "HuntPackage":
        if not self.risk_explanation:
            self.risk_explanation = _default_risk_explanation(self)
        if not self.investigation_flow:
            self.investigation_flow = _default_investigation_flow(self)
        if not self.priority_actions:
            self.priority_actions = _default_priority_actions(self)
        if not self.timeline_or_attack_path:
            self.timeline_or_attack_path = _default_timeline(self)
        if not self.false_positive_checks:
            self.false_positive_checks = _default_false_positive_checks()
        if not self.recommended_response:
            self.recommended_response = _default_recommended_response(self)
        if not self.warning_preview.message or (
            _severity_is_high(self.severity_hint) and not self.warning_preview.should_send
        ):
            self.warning_preview = _default_warning_preview(self)
        return self


class HuntPackageListItem(BaseModel):
    package_id: str
    report_title: str
    threat_summary: str


def _severity_is_high(severity: str) -> bool:
    return severity.lower() in {"critical", "high", "medium/high"}


def _default_risk_explanation(package: HuntPackage) -> str:
    behavior = package.key_behaviors[0] if package.key_behaviors else "the reported behavior"
    return (
        f"{package.report_title} needs review because {behavior} may indicate suspicious activity. "
        "The analyst should validate the evidence before treating the case as confirmed malicious."
    )


def _default_investigation_flow(package: HuntPackage) -> list[InvestigationStep]:
    telemetry = ", ".join(package.required_telemetry[:4]) or "relevant telemetry"
    return [
        InvestigationStep(
            step_id="confirm-alert-context",
            title="Confirm alert context",
            description="Review the report title, severity, affected entities, and observed behaviors.",
            expected_evidence=["alert metadata", "affected user/host/resource", "event time window"],
        ),
        InvestigationStep(
            step_id="validate-primary-evidence",
            title="Validate primary evidence",
            description=f"Search {telemetry} for the core behaviors and indicators listed in the hunt package.",
            expected_evidence=package.key_behaviors[:3] or ["matching telemetry evidence"],
        ),
        InvestigationStep(
            step_id="correlate-follow-on-activity",
            title="Correlate follow-on activity",
            description=package.correlation_logic,
            expected_evidence=["same user/host/resource", "source IP or session", "nearby follow-on events"],
        ),
        InvestigationStep(
            step_id="decide-escalation-or-close",
            title="Decide escalation or closure",
            description=package.escalation_condition,
            expected_evidence=["business justification", "false positive check", "escalation evidence"],
        ),
    ]


def _default_priority_actions(package: HuntPackage) -> list[PriorityAction]:
    severity = package.severity_hint or "Medium/High"
    return [
        PriorityAction(
            action_id="identify-scope",
            title="Identify affected user, host, workload, or resource",
            why_it_matters="Scoping first keeps the investigation focused and helps decide who needs to respond.",
            recommended_time="first_15_minutes" if _severity_is_high(severity) else "first_30_minutes",
        ),
        PriorityAction(
            action_id="validate-core-behavior",
            title="Validate the core suspicious behavior in telemetry",
            why_it_matters="The alert should not be escalated until the primary evidence is confirmed.",
            recommended_time="first_15_minutes" if _severity_is_high(severity) else "first_30_minutes",
        ),
        PriorityAction(
            action_id="check-approved-activity",
            title="Check for approved business or administrative activity",
            why_it_matters="This reduces false positives before warning or escalation.",
            recommended_time="first_30_minutes",
        ),
    ]


def _default_timeline(package: HuntPackage) -> list[TimelineEvent]:
    first_behavior = package.key_behaviors[0] if package.key_behaviors else "Suspicious behavior is reported"
    return [
        TimelineEvent(order=1, stage="Initial signal", description=first_behavior, evidence_needed=package.required_telemetry[:2]),
        TimelineEvent(order=2, stage="Validation", description="Analyst validates the behavior against telemetry and indicators.", evidence_needed=package.hunt_checklist[:2]),
        TimelineEvent(order=3, stage="Decision", description="Analyst decides whether to escalate, ask for help, or close as benign.", evidence_needed=[package.escalation_condition]),
    ]


def _default_false_positive_checks() -> list[str]:
    return [
        "Check whether the activity matches an approved change, maintenance window, security tool, or administrator workflow.",
        "Confirm whether the affected user, host, workload, or resource is expected to perform this action.",
        "Review nearby events before escalation to avoid treating isolated benign activity as confirmed malicious.",
    ]


def _default_recommended_response(package: HuntPackage) -> list[str]:
    responses = [
        "Preserve relevant telemetry, query results, and analyst notes as evidence.",
        "Escalate to a senior analyst or supervisor if primary evidence confirms suspicious activity.",
    ]
    if _severity_is_high(package.severity_hint):
        responses.insert(1, "Prepare containment or credential protection steps, but require analyst approval before disruptive action.")
    return responses


def _default_warning_preview(package: HuntPackage) -> WarningPreview:
    should_send = _severity_is_high(package.severity_hint)
    role = "supervisor" if package.severity_hint.lower() == "critical" else "soc_channel"
    message = (
        f"[{package.severity_hint or 'Review'}] {package.report_title}\n"
        f"Summary: {package.threat_summary}\n"
        "Priority: validate primary evidence and scope affected entities before escalation.\n"
        "Status: Hunt package generated; analyst confirmation required before sending."
    )
    return WarningPreview(should_send=should_send, recipient_role=role, message=message, requires_confirmation=True)
