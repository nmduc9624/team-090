const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000";

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
  query: string;
  purpose: string;
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
};

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    headers: {
      "Content-Type": "application/json",
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
