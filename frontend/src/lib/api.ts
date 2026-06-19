const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export interface HealthStatus {
  status: string;
  service: string;
}

export interface PipelineStatus {
  running: boolean;
  alerts_queued: number;
  reports_generated: number;
  audit_entries: number;
  intel_patterns: number;
}

export interface AuditEntry {
  id: string;
  agent: string;
  action: string;
  details: string;
  timestamp: string;
}

export interface ThreatIntel {
  id: string;
  pattern: string;
  attack_type: string;
  mitre_id: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  remediation: string;
}

export interface RawAlert {
  id: string;
  source: string;
  message: string;
  severity: string;
  timestamp: string;
  raw_data: Record<string, unknown>;
}

export interface AnalysisResult {
  alert_id: string;
  matched_patterns: ThreatIntel[];
  similarity_score: number;
  risk_level: string;
  summary: string;
}

export interface IncidentReport {
  alert: RawAlert;
  analysis: AnalysisResult;
  report_id: string;
  generated_at: string;
  recommendations: string[];
  compliance_notes: string;
  status: string;
}

async function fetchJson<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${url}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
  });
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export const api = {
  health: () => fetchJson<HealthStatus>("/api/health"),

  status: () => fetchJson<PipelineStatus>("/api/status"),

  runPipeline: () =>
    fetchJson<{ status: string }>("/api/run", { method: "POST" }),

  getAuditLog: () => fetchJson<AuditEntry[]>("/api/audit"),

  getReports: () => fetchJson<IncidentReport[]>("/api/reports"),

  getReport: (id: string) => fetchJson<IncidentReport>(`/api/reports/${id}`),

  getIntelSummary: () => fetchJson<{ total_patterns: number }>("/api/intel"),

  searchIntel: (query: string) =>
    fetchJson<ThreatIntel[]>(`/api/intel/search?query=${encodeURIComponent(query)}`, {
      method: "POST",
    }),
};
