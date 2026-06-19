import asyncio
import logging
import uuid
from datetime import datetime, timezone

from agents.analyst_agent import AnalystAgent
from agents.ingest_agent import IngestAgent
from agents.manager_agent import ManagerAgent
from db.chroma_wrapper import ThreatIntelStore
from models.schemas import AuditEntry, IncidentReport

logger = logging.getLogger(__name__)


class AgentOrchestrator:
    def __init__(self, intel_store: ThreatIntelStore):
        self.intel_store = intel_store
        self.alert_queue: asyncio.Queue = asyncio.Queue()
        self.analysis_queue: asyncio.Queue = asyncio.Queue()
        self.audit_log: list[AuditEntry] = []
        self.reports: list[IncidentReport] = []
        self.manager = ManagerAgent(self.audit_log)
        self.ingest = IngestAgent(self.alert_queue, self.audit_log)
        self.analyst = AnalystAgent(self.intel_store, self.analysis_queue, self.audit_log)
        self._running = False

    async def start(self):
        self._running = True
        ingest_task = asyncio.create_task(self.ingest.run())
        analyst_task = asyncio.create_task(self._analyst_loop())
        logger.info("Orchestrator started.")

        await ingest_task
        logger.info("Ingest phase complete. Waiting for analysis to finish...")
        await self.alert_queue.join()
        self._running = False

    async def _analyst_loop(self):
        while True:
            alert = await self.alert_queue.get()
            analysis = await self.analyst._analyze(alert)
            report = await self.manager.generate_report(alert, analysis)
            self.reports.append(report)
            self._audit("orchestrator", f"Pipeline complete for alert {alert.id} -> report {report.report_id}")
            self.alert_queue.task_done()

    def _audit(self, agent: str, details: str):
        self.audit_log.append(
            AuditEntry(
                id=str(uuid.uuid4()),
                agent=agent,
                action="pipeline_event",
                details=details,
                timestamp=datetime.now(timezone.utc),
            )
        )

    def get_audit_log(self) -> list[AuditEntry]:
        return sorted(self.audit_log, key=lambda x: x.timestamp, reverse=True)

    def get_reports(self) -> list[IncidentReport]:
        return sorted(self.reports, key=lambda x: x.generated_at, reverse=True)
