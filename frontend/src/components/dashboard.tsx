"use client";

import { useEffect, useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { Toaster, toast } from "sonner";
import { api, type AuditEntry, type IncidentReport, type PipelineStatus, type ThreatIntel } from "@/lib/api";
import { formatTimestamp, severityColor } from "@/lib/utils";

export default function Dashboard() {
  const [status, setStatus] = useState<PipelineStatus | null>(null);
  const [auditLog, setAuditLog] = useState<AuditEntry[]>([]);
  const [reports, setReports] = useState<IncidentReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [pipelineRunning, setPipelineRunning] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<ThreatIntel[] | null>(null);
  const [selectedReport, setSelectedReport] = useState<IncidentReport | null>(null);

  const fetchAll = useCallback(async () => {
    try {
      const [s, a, r] = await Promise.all([
        api.status(),
        api.getAuditLog(),
        api.getReports(),
      ]);
      setStatus(s);
      setAuditLog(a);
      setReports(r);
    } catch (e) {
      toast.error("Failed to fetch data from backend");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
    const interval = setInterval(fetchAll, 5000);
    return () => clearInterval(interval);
  }, [fetchAll]);

  const handleRunPipeline = async () => {
    setPipelineRunning(true);
    try {
      const result = await api.runPipeline();
      toast.success(result.status);
      setTimeout(fetchAll, 2000);
    } catch {
      toast.error("Failed to start pipeline");
    } finally {
      setTimeout(() => setPipelineRunning(false), 3000);
    }
  };

  const handleSearch = async () => {
    if (!searchQuery.trim()) return;
    try {
      const results = await api.searchIntel(searchQuery);
      setSearchResults(results);
    } catch {
      toast.error("Search failed");
    }
  };

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-zinc-950">
        <div className="text-zinc-400 text-lg animate-pulse">Connecting to threat desk...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      <Toaster position="top-right" theme="dark" />
      <header className="border-b border-zinc-800 px-6 py-4">
        <div className="mx-auto max-w-7xl flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold text-emerald-400">Threat Intelligence Desk</h1>
            <p className="text-sm text-zinc-500">Multi-Agent Cyber Incident Triage Squad</p>
          </div>
          <div className="flex items-center gap-3">
            <Badge variant={status?.running ? "default" : "secondary"} className={status?.running ? "bg-emerald-600" : ""}>
              {status?.running ? "Pipeline Active" : "Idle"}
            </Badge>
            <Button onClick={handleRunPipeline} disabled={pipelineRunning || status?.running} className="bg-emerald-600 hover:bg-emerald-500">
              {pipelineRunning ? "Starting..." : "Run Pipeline"}
            </Button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-6 py-6 space-y-6">
        {/* Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Card className="bg-zinc-900 border-zinc-800">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-zinc-400">Alerts Processed</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-bold text-zinc-100">{reports.length}</div>
            </CardContent>
          </Card>
          <Card className="bg-zinc-900 border-zinc-800">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-zinc-400">Reports Generated</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-bold text-zinc-100">{status?.reports_generated ?? 0}</div>
            </CardContent>
          </Card>
          <Card className="bg-zinc-900 border-zinc-800">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-zinc-400">Intel Patterns</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-bold text-zinc-100">{status?.intel_patterns ?? 0}</div>
            </CardContent>
          </Card>
          <Card className="bg-zinc-900 border-zinc-800">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-zinc-400">Audit Entries</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-bold text-zinc-100">{status?.audit_entries ?? 0}</div>
            </CardContent>
          </Card>
        </div>

        {/* Intel Search */}
        <Card className="bg-zinc-900 border-zinc-800">
          <CardHeader>
            <CardTitle className="text-sm font-medium text-zinc-400">Threat Intelligence Search</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex gap-2">
              <Input
                placeholder="Search threat patterns..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleSearch()}
                className="bg-zinc-800 border-zinc-700 text-zinc-100"
              />
              <Button onClick={handleSearch} variant="secondary">Search</Button>
            </div>
            {searchResults && (
              <div className="mt-4 space-y-2">
                {searchResults.map((r) => (
                  <div key={r.id} className="p-3 rounded bg-zinc-800 border border-zinc-700">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-medium text-zinc-100">{r.attack_type}</span>
                      <Badge className={severityColor(r.severity)}>{r.severity}</Badge>
                      {r.mitre_id && <span className="text-xs text-zinc-500">{r.mitre_id}</span>}
                    </div>
                    <p className="text-sm text-zinc-400">{r.description}</p>
                    <p className="text-xs text-emerald-500 mt-1">{r.remediation}</p>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Audit Log */}
          <Card className="bg-zinc-900 border-zinc-800">
            <CardHeader>
              <CardTitle className="text-sm font-medium text-zinc-400">Agent Audit Trail</CardTitle>
            </CardHeader>
            <CardContent className="max-h-96 overflow-y-auto">
              {auditLog.length === 0 ? (
                <p className="text-zinc-500 text-sm">Run the pipeline to see agent activity.</p>
              ) : (
                <div className="space-y-2">
                  {auditLog.slice(0, 30).map((entry) => (
                    <div key={entry.id} className="text-sm border-l-2 border-zinc-700 pl-3 py-1">
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className="text-xs bg-zinc-800 text-zinc-300">{entry.agent}</Badge>
                        <span className="text-xs text-zinc-500">{formatTimestamp(entry.timestamp)}</span>
                      </div>
                      <p className="text-zinc-300 mt-0.5">{entry.details.slice(0, 120)}</p>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Reports */}
          <Card className="bg-zinc-900 border-zinc-800">
            <CardHeader>
              <CardTitle className="text-sm font-medium text-zinc-400">Incident Reports</CardTitle>
            </CardHeader>
            <CardContent className="max-h-96 overflow-y-auto">
              {reports.length === 0 ? (
                <p className="text-zinc-500 text-sm">No reports yet. Run the pipeline.</p>
              ) : selectedReport ? (
                <div>
                  <Button variant="ghost" size="sm" onClick={() => setSelectedReport(null)} className="mb-3 text-zinc-400">
                    &larr; Back to list
                  </Button>
                  <div className="space-y-3">
                    <div>
                      <span className="text-xs text-zinc-500">Alert Source</span>
                      <p className="text-sm font-medium text-zinc-100">{selectedReport.alert.source}: {selectedReport.alert.message}</p>
                    </div>
                    <Separator className="bg-zinc-800" />
                    <div>
                      <span className="text-xs text-zinc-500">Risk Level</span>
                      <Badge className={`ml-2 ${severityColor(selectedReport.analysis.risk_level)}`}>
                        {selectedReport.analysis.risk_level}
                      </Badge>
                    </div>
                    <div>
                      <span className="text-xs text-zinc-500">Matched Patterns</span>
                      {selectedReport.analysis.matched_patterns.map((p) => (
                        <div key={p.id} className="mt-1 p-2 rounded bg-zinc-800">
                          <p className="text-sm text-zinc-200">{p.attack_type} ({p.mitre_id})</p>
                          <p className="text-xs text-zinc-400">{p.description}</p>
                        </div>
                      ))}
                    </div>
                    <div>
                      <span className="text-xs text-zinc-500">Recommendations</span>
                      <ul className="mt-1 list-disc list-inside text-sm text-zinc-300">
                        {selectedReport.recommendations.map((r, i) => (
                          <li key={i}>{r}</li>
                        ))}
                      </ul>
                    </div>
                    {selectedReport.compliance_notes && (
                      <div>
                        <span className="text-xs text-zinc-500">Compliance</span>
                        <p className="text-sm text-zinc-300 whitespace-pre-wrap">{selectedReport.compliance_notes}</p>
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div className="space-y-2">
                  {reports.map((r) => (
                    <div
                      key={r.report_id}
                      className="p-3 rounded bg-zinc-800 border border-zinc-700 cursor-pointer hover:border-zinc-500 transition-colors"
                      onClick={() => setSelectedReport(r)}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-sm font-medium text-zinc-200">{r.alert.source}</span>
                        <Badge className={severityColor(r.analysis.risk_level)}>{r.analysis.risk_level}</Badge>
                      </div>
                      <p className="text-xs text-zinc-400 mt-1">{r.alert.message.slice(0, 80)}...</p>
                      <p className="text-xs text-zinc-500 mt-1">{formatTimestamp(r.generated_at)}</p>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  );
}
