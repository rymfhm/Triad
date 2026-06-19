import asyncio
import logging
import uuid
from datetime import datetime, timezone

from agents.analyst_agent import AnalysisResult
from agents.ingest_agent import RawAlert
from models.schemas import (
    AlertStatus,
    AuditEntry,
    IncidentReport,
    Severity,
)

logger = logging.getLogger(__name__)


class ManagerAgent:
    def __init__(self, audit_log: list[AuditEntry]):
        self.audit_log = audit_log
        self.reports: list[IncidentReport] = []

    async def generate_report(self, alert: RawAlert, analysis: AnalysisResult) -> IncidentReport:
        self._audit("generating_report", f"Generating incident report for alert {alert.id}")

        recommendations = self._build_recommendations(analysis)
        compliance_notes = self._build_compliance_notes(analysis)

        report = IncidentReport(
            alert=alert,
            analysis=analysis,
            report_id=str(uuid.uuid4()),
            generated_at=datetime.now(timezone.utc),
            recommendations=recommendations,
            compliance_notes=compliance_notes,
            status=AlertStatus.REPORTED,
        )

        self.reports.append(report)
        self._audit(
            "report_generated",
            f"Report {report.report_id}: {len(recommendations)} recommendations, "
            f"risk={analysis.risk_level.value}",
        )
        logger.info(f"Incident report {report.report_id} generated for alert {alert.id}")
        return report

    def _build_recommendations(self, analysis: AnalysisResult) -> list[str]:
        recs = []
        for pattern in analysis.matched_patterns:
            if pattern.remediation:
                recs.append(pattern.remediation)
        if analysis.risk_level in (Severity.HIGH, Severity.CRITICAL):
            recs.append("Escalate to senior security team for immediate review.")
            recs.append("Preserve forensic evidence for potential legal proceedings.")
        recs.append(f"Log retention: preserve all artifacts related to {analysis.alert_id} for 90 days.")
        return recs

    def _build_compliance_notes(self, analysis: AnalysisResult) -> str:
        notes = []
        if analysis.risk_level == Severity.CRITICAL:
            notes.append("CRITICAL: Mandatory reporting under breach notification regulations may apply.")
        mitre_ids = [p.mitre_id for p in analysis.matched_patterns if p.mitre_id]
        if mitre_ids:
            notes.append(f"MITRE ATT&CK mappings: {', '.join(mitre_ids)}")
        if any(p.attack_type == "Ransomware" for p in analysis.matched_patterns):
            notes.append("Ransomware incident: CISA reporting guidelines apply.")
        return "\n".join(notes)

    def _audit(self, action: str, details: str):
        entry = AuditEntry(
            id=str(uuid.uuid4()),
            agent="manager",
            action=action,
            details=details,
        )
        self.audit_log.append(entry)
