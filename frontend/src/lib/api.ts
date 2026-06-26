const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000";

let authTokenProvider: (() => Promise<string | null>) | null = null;

export function setAuthTokenProvider(provider: (() => Promise<string | null>) | null) {
  authTokenProvider = provider;
}

export type AlertCatalogItem = {
  slug: string;
  alert_name: string;
  alert_source: string;
  severity: string;
  category: string;
  status: string;
};

export type SampleReport = AlertCatalogItem & {
  content: string;
};

export type QueryDraft = {
  name: string;
  platform: string;
  telemetry?: string[];
  query: string;
  purpose: string;
};

export type InvestigationStep = {
  step_id: string;
  title: string;
  description: string;
  expected_evidence: string[];
  status: string;
  can_ask_for_help: boolean;
};

export type PriorityAction = {
  action_id: string;
  title: string;
  why_it_matters: string;
  recommended_time: string;
  requires_approval: boolean;
  status: string;
};

export type TimelineEvent = {
  order: number;
  stage: string;
  description: string;
  evidence_needed: string[];
};

export type WarningPreview = {
  should_send: boolean;
  recipient_role: string;
  message: string;
  requires_confirmation: boolean;
};

export type HuntPackage = {
  package_id: string;
  report_title: string;
  threat_summary: string;
  key_behaviors: string[];
  ioc: {
    domains: string[];
    ips: string[];
    hashes: string[];
    files: string[];
    processes: string[];
    registry_keys: string[];
  };
  mitre_mapping: string[];
  required_telemetry: string[];
  hunt_checklist: string[];
  query_drafts: QueryDraft[];
  correlation_logic: string;
  escalation_condition: string;
  analyst_notes: string;
  confidence_score: number;
  confidence_reasons: string[];
  severity_hint: string;
  risk_explanation: string;
  investigation_flow: InvestigationStep[];
  priority_actions: PriorityAction[];
  timeline_or_attack_path: TimelineEvent[];
  false_positive_checks: string[];
  recommended_response: string[];
  warning_preview: WarningPreview;
};

export type AppNotification = {
  notification_id: string;
  type: string;
  case_id: string;
  case_title?: string;
  message: string;
  author_name?: string;
  channel_name?: string;
  message_url?: string;
  read: boolean;
  created_at: string;
};

export type CaseSummary = {
  case_id: string;
  title: string;
  severity?: string;
  status?: string;
  created_at?: string;
  updated_at?: string;
  unread_notifications?: number;
};

export type CaseTimelineEvent = {
  type: string;
  label: string;
  timestamp: string;
  detail?: string;
};

export type CaseDetail = {
  case: CaseSummary & Record<string, unknown>;
  hunt_package: HuntPackage | null;
  steps: InvestigationStep[];
  warnings: Record<string, unknown>[];
  help_requests: Record<string, unknown>[];
  notifications: AppNotification[];
  timeline: CaseTimelineEvent[];
};

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const token = authTokenProvider ? await authTokenProvider() : null;
  const response = await fetch(`${API_BASE_URL}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(options?.headers ?? {}),
    },
    ...options,
  });

  if (!response.ok) {
    const detail = await response.text();
    throw new Error(detail || `Request failed with status ${response.status}`);
  }

  return response.json() as Promise<T>;
}

export function getSampleReports() {
  return request<AlertCatalogItem[]>("/api/data/sample-reports");
}

export function getSampleReport(slug: string) {
  return request<SampleReport>(`/api/data/sample-reports/${slug}`);
}

export function analyzeThreatReport(title: string, content: string) {
  return request<HuntPackage>("/api/threat-reports/analyze", {
    method: "POST",
    body: JSON.stringify({ title, content }),
  });
}

export type SupervisorHelpContext = {
  severity?: string;
  confidence_score?: number;
  current_step?: string;
  completed_steps?: string[];
  evidence_available?: string[];
  current_warning?: string;
};

export type WarningEventType =
  | "priority_action_warning"
  | "step_warning"
  | "escalation_warning"
  | "final_summary";

export function sendWarningEvent(
  caseId: string,
  alertTitle: string,
  warningType: WarningEventType,
  severity: string,
  confidenceScore: number,
  payload: Record<string, unknown>
) {
  return request<{ status: string }>("/api/threat-reports/warning", {
    method: "POST",
    body: JSON.stringify({
      case_id: caseId,
      alert_title: alertTitle,
      warning_type: warningType,
      severity,
      confidence_score: confidenceScore,
      payload,
    }),
  });
}

export function askSupervisor(
  caseId: string,
  alertTitle: string,
  struggle: string,
  question: string,
  context: SupervisorHelpContext = {}
) {
  return request<{ status: string }>("/api/threat-reports/ask-supervisor", {
    method: "POST",
    body: JSON.stringify({
      case_id: caseId,
      alert_title: alertTitle,
      struggle,
      question,
      ...context,
    }),
  });
}

export function getNotifications() {
  return request<{ notifications: AppNotification[] }>("/api/notifications");
}

export function markNotificationRead(notificationId: string) {
  return request<{ status: string }>(`/api/notifications/${notificationId}/read`, {
    method: "POST",
  });
}

export function getCases() {
  return request<{ cases: CaseSummary[] }>("/api/cases");
}

export function getCaseDetail(caseId: string) {
  return request<CaseDetail>(`/api/cases/${caseId}`);
}

