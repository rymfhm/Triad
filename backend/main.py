import asyncio
import logging
import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv

load_dotenv()

gemini_key = os.getenv("GEMINI_API_KEY", "")
if gemini_key:
    os.environ["GOOGLE_API_KEY"] = gemini_key

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import build_router
from db.chroma_wrapper import ThreatIntelStore
from services.message_store import MessageStore
from services.band_bridge import BandBridge
from services.google_drive import GoogleDriveBackup

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger(__name__)

intel_store = ThreatIntelStore(persist_dir="./chroma_data")
message_store = MessageStore()
band_bridge = BandBridge(message_store)
google_drive = GoogleDriveBackup()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Threat Intel DB seeded with {intel_store.count()} patterns")

    await google_drive.initialize()

    band_tasks = []
    try:
        from agents.band_agents import get_band_agents, run_band_agent
        band_agents = get_band_agents(intel_store, band_bridge, message_store)
        for name, agent in band_agents:
            task = asyncio.create_task(run_band_agent(name, agent))
            band_tasks.append(task)
            logger.info(f"Scheduled Band agent: {name}")

        bridge_task = asyncio.create_task(band_bridge.start())
        band_tasks.append(bridge_task)
    except Exception as e:
        logger.warning(f"Band agents not started: {e}")

    yield

    await band_bridge.stop()
    for task in band_tasks:
        task.cancel()
    logger.info("Shutting down.")


def create_app() -> FastAPI:
    app = FastAPI(
        title="Multi-Agent Threat Intelligence Desk",
        description="Automated Cyber Incident Triage Squad - Band of Agents Hackathon 2026",
        version="2.0.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    from agents.orchestrator import AgentOrchestrator
    orchestrator = AgentOrchestrator(intel_store)

    router = build_router(
        orchestrator=orchestrator,
        band_bridge=band_bridge,
        message_store=message_store,
        google_drive=google_drive,
    )
    app.include_router(router)

    @app.get("/")
    async def root():
        return {
            "service": "Multi-Agent Threat Intelligence Desk",
            "version": "2.0.0",
            "status": "operational",
            "endpoints": {
                "health": "GET /api/health",
                "audit_log": "GET /api/audit",
                "reports": "GET /api/reports",
                "report_detail": "GET /api/reports/{report_id}",
                "intel": "GET /api/intel",
                "search_intel": "POST /api/intel/search?query=...",
                "add_intel": "POST /api/intel",
                "run_pipeline": "POST /api/run",
                "status": "GET /api/status",
                "band_messages": "GET /api/band/messages",
                "band_send": "POST /api/band/send",
                "drive_export": "POST /api/drive/export-all",
                "drive_backups": "GET /api/drive/backups",
                "websocket": "WS /api/ws",
            },
        }

    return app


app = create_app()

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
