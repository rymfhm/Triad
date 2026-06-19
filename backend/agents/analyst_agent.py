import asyncio
import logging
import uuid
from datetime import datetime, timezone

from agents.ingest_agent import IngestAgent
from db.chroma_wrapper import ThreatIntelStore
from models.schemas import (
    AlertStatus,
    AnalysisResult,
    AuditEntry,
    RawAlert,
    Severity,
    ThreatIntel,
)

logger = logging.getLogger(__name__)


class AnalystAgent:
    def __init__(
        self,
        intel_store: ThreatIntelStore,
        analysis_queue: asyncio.Queue,
        audit_log: list[AuditEntry],
    ):
        self.intel_store = intel_store
        self.analysis_queue = analysis_queue
        self.audit_log = audit_log

    async def run(self):
        logger.info("AnalystAgent started. Waiting for alerts to analyze...")

        while True:
            alert = await self.analysis_queue.get()
            self._audit("started_analysis", f"Analyzing alert {alert.id}")
            result = await self._analyze(alert)
            logger.info(f"Analysis complete for {alert.id}: risk={result.risk_level.value}, matches={len(result.matched_patterns)}")
            self._audit(
                "completed_analysis",
                f"Alert {alert.id}: {len(result.matched_patterns)} patterns matched, "
                f"risk={result.risk_level.value}",
            )
            analysis_queue.task_done()

    async def _analyze(self, alert: RawAlert) -> AnalysisResult:
        query = f"{alert.message} {alert.source} {' '.join(str(v) for v in alert.raw_data.values())}"
        matches = self.intel_store.search(query, n_results=3)

        if not matches:
            return AnalysisResult(
                alert_id=alert.id,
                risk_level=Severity.LOW,
                summary=f"No known threat patterns matched for alert from {alert.source}.",
            )

        severity_scores = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        max_severity = max(m.severity for m in matches)
        avg_score = sum(severity_scores.get(m.severity.value, 0) for m in matches) / len(matches)

        overall_severity = Severity.CRITICAL if avg_score >= 3.5 else Severity.HIGH if avg_score >= 2.5 else Severity.MEDIUM if avg_score >= 1.5 else Severity.LOW
        if alert.severity.value == "critical":
            overall_severity = Severity.CRITICAL

        attack_types = list({m.attack_type for m in matches})
        summary = (
            f"Alert matches {len(matches)} threat pattern(s): {', '.join(attack_types)}. "
            f"Highest severity match: {max_severity.value}. "
            f"Alert source: {alert.source}."
        )

        return AnalysisResult(
            alert_id=alert.id,
            matched_patterns=matches,
            similarity_score=avg_score / 4.0,
            risk_level=overall_severity,
            summary=summary,
        )

    def _audit(self, action: str, details: str):
        entry = AuditEntry(
            id=str(uuid.uuid4()),
            agent="analyst",
            action=action,
            details=details,
        )
        self.audit_log.append(entry)
