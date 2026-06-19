import json
import logging
import os

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

from agents.orchestrator import AgentOrchestrator
from models.schemas import IncidentReport, Severity, ThreatIntel
from services.band_bridge import BandBridge
from services.google_drive import GoogleDriveBackup
from services.message_store import MessageStore

logger = logging.getLogger(__name__)

API_KEY = os.getenv("API_KEY", "")


def verify_key(key: str = "") -> bool:
    if not API_KEY:
        return True
    return key == API_KEY


class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        self.active.remove(ws)

    async def broadcast(self, message: dict):
        for ws in self.active:
            try:
                await ws.send_json(message)
            except Exception:
                pass


manager = ConnectionManager()


def build_router(
    orchestrator: AgentOrchestrator,
    band_bridge: BandBridge | None = None,
    message_store: MessageStore | None = None,
    google_drive: GoogleDriveBackup | None = None,
) -> APIRouter:
    router = APIRouter(prefix="/api")

    def _check_auth(auth_key: str = ""):
        if API_KEY and auth_key != API_KEY:
            raise HTTPException(status_code=401, detail="Invalid API key")
        return True

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
        return {"total_patterns": orchestrator.intel_store.count()}

    @router.post("/intel/search")
    async def search_intel(query: str):
        results = orchestrator.intel_store.search(query)
        return results

    @router.post("/intel")
    async def add_intel(intel: ThreatIntel):
        intel_id = orchestrator.intel_store.add_intel(intel)
        return {"id": intel_id, "status": "added"}

    @router.post("/run")
    async def run_pipeline(auth_key: str = ""):
        _check_auth(auth_key)
        if orchestrator._running:
            return JSONResponse(
                status_code=409,
                content={"status": "pipeline already running"},
            )
        import asyncio

        async def _run_and_bridge():
            await orchestrator.start()
            await orchestrator.post_to_band(band_bridge)
            await _broadcast_update()

        asyncio.create_task(_run_and_bridge())
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

    @router.get("/band/messages")
    async def get_band_messages(agent: str = "", limit: int = 50):
        if not message_store:
            return []
        if agent:
            return message_store.get_by_agent(agent, limit)
        return message_store.get_all(limit)

    @router.post("/band/send")
    async def send_band_message(agent: str, content: str, auth_key: str = ""):
        _check_auth(auth_key)
        if not band_bridge:
            raise HTTPException(status_code=503, detail="Band bridge not available")
        success = await band_bridge.send_message(agent, content)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to send message")
        return {"status": "sent"}

    @router.post("/drive/export-all")
    async def export_all_to_drive(auth_key: str = ""):
        _check_auth(auth_key)
        links = []
        for report in orchestrator.reports:
            link = await google_drive.export_report(report)
            if link:
                links.append(link)
        drive_note = ""
        if not google_drive or not google_drive._enabled:
            drive_note = "Drive API not available — saved locally (check exports/ folder)"
        return {"exported": len(links), "links": links, "note": drive_note}

    @router.get("/drive/backups")
    async def list_drive_backups():
        files = await google_drive.list_backups()
        return {"enabled": google_drive._enabled if google_drive else False, "files": files}

    @router.websocket("/ws")
    async def websocket_endpoint(ws: WebSocket):
        await manager.connect(ws)
        try:
            while True:
                data = await ws.receive_text()
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await ws.send_json({"type": "pong"})
        except WebSocketDisconnect:
            manager.disconnect(ws)
        except Exception:
            manager.disconnect(ws)

    async def _broadcast_update():
        await manager.broadcast({
            "type": "update",
            "status": {
                "running": orchestrator._running,
                "reports_generated": len(orchestrator.reports),
                "audit_entries": len(orchestrator.audit_log),
            },
            "reports_count": len(orchestrator.reports),
            "audit_count": len(orchestrator.audit_log),
        })

    return router
