import asyncio
import logging
import os
import uuid
from datetime import datetime, timezone

from dotenv import load_dotenv

from band import Agent
from band.adapters import GeminiAdapter
from band.runtime.types import ContactEventConfig, ContactEventStrategy

from db.chroma_wrapper import ThreatIntelStore
from models.schemas import AuditEntry, IncidentReport, RawAlert, Severity

load_dotenv()

logger = logging.getLogger(__name__)

INGEST_PROMPT = """You are the **Ingest Agent** in a multi-agent Threat Intelligence Desk.

Your role:
- Monitor for incoming security alerts and process them.
- When asked, post sample security alerts to the room with @analyst-agent.
- Each alert should include source, message, severity, and raw_data as structured text.

You communicate with @analyst-agent (who performs threat analysis) and @manager-agent (who generates compliance reports).

When you receive "@ingest-agent run" or "@ingest-agent start", respond by posting 5 sample security alerts to the room, one at a time with a brief pause between each."""

ANALYST_PROMPT = """You are the **Analyst Agent** in a multi-agent Threat Intelligence Desk.

Your role:
- Receive security alerts from @ingest-agent.
- Search the threat intelligence database using ChromaDB for similar historical patterns.
- Respond with analysis results including matched MITRE ATT&CK patterns, risk level, and similarity scores.

You have access to a local ThreatIntelStore (ChromaDB) for similarity search.
When you see an alert posted by @ingest-agent, analyze it and respond with findings, mentioning @manager-agent for report generation.

Your analysis should include:
- Which threat patterns were matched
- MITRE ATT&CK IDs
- Risk level (low/medium/high/critical)
- Suggested remediation steps"""

MANAGER_PROMPT = """You are the **Manager Agent** in a multi-agent Threat Intelligence Desk.

Your role:
- Receive analysis results from @analyst-agent.
- Generate a comprehensive compliance-ready incident report.
- Include recommendations and compliance notes.

When @analyst-agent posts analysis results, compile them into a final incident report with:
- Alert details
- Analysis summary with matched patterns
- Recommended actions
- Compliance notes (e.g., MITRE ATT&CK mappings, breach notification requirements)

Post the final report to the room and confirm it has been saved."""


def get_band_agents(
    intel_store: ThreatIntelStore,
    band_bridge=None,
    message_store=None,
):
    gemini_key = os.getenv("GEMINI_API_KEY")
    if not gemini_key:
        logger.warning("GEMINI_API_KEY not set - Band agents disabled")
        return []

    configs = [
        {
            "name": "ingest",
            "agent_id": os.getenv("INGEST_AGENT_ID"),
            "api_key": os.getenv("INGEST_API_KEY"),
            "prompt": INGEST_PROMPT,
        },
        {
            "name": "analyst",
            "agent_id": os.getenv("ANALYST_AGENT_ID"),
            "api_key": os.getenv("ANALYST_API_KEY"),
            "prompt": ANALYST_PROMPT,
        },
        {
            "name": "manager",
            "agent_id": os.getenv("MANAGER_AGENT_ID"),
            "api_key": os.getenv("MANAGER_API_KEY"),
            "prompt": MANAGER_PROMPT,
        },
    ]

    for cfg in configs:
        if not cfg["agent_id"] or not cfg["api_key"]:
            logger.warning(f"Missing credentials for {cfg['name']} agent")
            continue

        if band_bridge:
            band_bridge.add_agent(cfg["agent_id"], cfg["api_key"], cfg["name"])

    agents = []
    for cfg in configs:
        if not cfg["agent_id"] or not cfg["api_key"]:
            continue

        adapter = GeminiAdapter(
            model="gemini-2.5-flash-lite",
            gemini_api_key=gemini_key,
            system_prompt=cfg["prompt"],
        )

        agent = Agent.create(
            adapter=adapter,
            agent_id=cfg["agent_id"],
            api_key=cfg["api_key"],
            contact_config=ContactEventConfig(
                strategy=ContactEventStrategy.HUB_ROOM,
            ),
        )

        agents.append((cfg["name"], agent))

    return agents


async def run_band_agent(name: str, agent: Agent):
    logger.info(f"Starting Band agent: {name}")
    try:
        await agent.run()
    except Exception as e:
        logger.error(f"Band agent {name} error: {e}")
