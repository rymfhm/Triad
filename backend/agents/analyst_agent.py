import asyncio
import json
import logging
import os
import uuid
from datetime import datetime, timezone

from db.chroma_wrapper import ThreatIntelStore
from models.schemas import (
    AnalysisResult,
    AuditEntry,
    RawAlert,
    Severity,
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

        llm_analysis = await self._llm_analyze(alert, matches)
        return llm_analysis

    async def _llm_analyze(self, alert: RawAlert, matches) -> AnalysisResult:
        gemini_key = os.getenv("GEMINI_API_KEY")
        if not gemini_key:
            return self._heuristic_fallback(alert, matches)

        try:
            import google.genai as genai

            client = genai.Client(api_key=gemini_key)
            matches_text = "\n".join(
                f"- {m.attack_type} ({m.mitre_id}): {m.description} [severity={m.severity.value}]"
                for m in matches
            )

            prompt = f"""You are a Senior Threat Intelligence Analyst. Analyze this security alert.

ALERT:
Source: {alert.source}
Message: {alert.message}
Raw Data: {json.dumps(alert.raw_data, default=str)}
Severity: {alert.severity.value}

MATCHED THREAT PATTERNS (from ChromaDB vector search):
{matches_text}

Respond in this exact JSON format:
{{
    "risk_level": "low/medium/high/critical",
    "summary": "concise analysis summary",
    "attack_stage": "the MITRE ATT&CK tactic",
    "key_findings": ["finding 1", "finding 2"],
    "recommended_actions": ["action 1", "action 2"]
}}"""

            response = client.models.generate_content(
                model="gemini-2.5-flash-lite",
                contents=prompt,
            )

            text = response.text.strip()
            if text.startswith("```json"):
                text = text[7:]
            if text.startswith("```"):
                text = text[3:]
            if text.endswith("```"):
                text = text[:-3]
            text = text.strip()

            parsed = json.loads(text)
            risk = Severity(parsed.get("risk_level", alert.severity.value))
            summary = parsed.get("summary", "")

            return AnalysisResult(
                alert_id=alert.id,
                matched_patterns=matches,
                similarity_score=0.85,
                risk_level=risk,
                summary=f"[Gemini Analysis] {summary}",
            )

        except Exception as e:
            logger.warning(f"Gemini analysis failed, falling back to heuristic: {e}")
            return self._heuristic_fallback(alert, matches)

    def _heuristic_fallback(self, alert: RawAlert, matches) -> AnalysisResult:
        severity_scores = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        avg_score = sum(severity_scores.get(m.severity.value, 0) for m in matches) / len(matches)

        overall_severity = (
            Severity.CRITICAL if avg_score >= 3.5 else
            Severity.HIGH if avg_score >= 2.5 else
            Severity.MEDIUM if avg_score >= 1.5 else
            Severity.LOW
        )
        if alert.severity.value == "critical":
            overall_severity = Severity.CRITICAL

        attack_types = list({m.attack_type for m in matches})
        summary = (
            f"Alert matches {len(matches)} threat pattern(s): {', '.join(attack_types)}. "
            f"Highest severity match: {max(m.severity for m in matches).value}. "
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
