import logging

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from agents.orchestrator import AgentOrchestrator
from models.schemas import AuditEntry, IncidentReport, RawAlert, Severity, ThreatIntel

logger = logging.getLogger(__name__)


def build_router(orchestrator: AgentOrchestrator) -> APIRouter:
    router = APIRouter(prefix="/api")

    @router.get("/health")
    async def health():
        return {"status": "ok", "service": "threat-intel-desk"}

    @router.get("/audit")
    async def get_audit_log():
        return orchestrator.get_audit_log()

    @router.get("/reports")
    async def get_reports():
        return orchestrator.get_reports()

    @router.get("/reports/{report_id}")
    async def get_report(report_id: str):
        for report in orchestrator.reports:
            if report.report_id == report_id:
                return report
        raise HTTPException(status_code=404, detail="Report not found")

    @router.get("/intel")
    async def get_intel():
        count = orchestrator.intel_store.count()
        return {"total_patterns": count}

    @router.post("/intel/search")
    async def search_intel(query: str):
        results = orchestrator.intel_store.search(query)
        return results

    @router.post("/intel")
    async def add_intel(intel: ThreatIntel):
        intel_id = orchestrator.intel_store.add_intel(intel)
        return {"id": intel_id, "status": "added"}

    @router.post("/run")
    async def run_pipeline():
        if orchestrator._running:
            return JSONResponse(
                status_code=409,
                content={"status": "pipeline already running"},
            )
        import asyncio
        asyncio.create_task(orchestrator.start())
        return {"status": "pipeline started"}

    @router.get("/status")
    async def status():
        return {
            "running": orchestrator._running,
            "alerts_queued": orchestrator.alert_queue.qsize(),
            "reports_generated": len(orchestrator.reports),
            "audit_entries": len(orchestrator.audit_log),
            "intel_patterns": orchestrator.intel_store.count(),
        }

    return router
