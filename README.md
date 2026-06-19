# Triad
# TRiaD — Threat intelligence & automated defense

Automated cyber incident triage squad built with **ChromaDB × Gemini × Streamlit** — a submission for the **Band of Agents Hackathon 2026**.

Three AI agents (Ingest, Analyst, Manager) collaborate to ingest security alerts, analyze them against a threat intel database (via vector search + Gemini LLM), and generate compliance-ready incident reports — all surfaced through a dark-themed Streamlit dashboard.

---

## Architecture

```
                    ┌─────────────┐
                    │  Frontend   │  Next.js + Tailwind + shadcn/ui
                    │  :3000      │  Dark theme dashboard
                    └──────┬──────┘
                           │ REST + WebSocket (auto-reconnect, 15s ping)
                    ┌──────▼──────┐
                    │  Backend    │  FastAPI + Uvicorn
                    │  :8000      │  14 REST endpoints + WS + auth
                    └──────┬──────┘
           ┌───────────────┼───────────────┐
           ▼               ▼               ▼
    ┌──────────┐   ┌────────────┐   ┌──────────┐
    │  Ingest  │   │  Analyst   │   │  Manager │  Local Pipeline
    │  Agent   │──▶│  Agent     │──▶│  Agent   │  (asyncio.Queue)
    └──────────┘   └─────┬──────┘   └──────────┘
                         │ ChromaDB search
                    ┌────▼────┐
                    │ChromaDB │  8 MITRE ATT&CK seed patterns
                    │         │  Persistent vector store
                    └─────────┘
    ┌──────────┐   ┌────────────┐   ┌──────────┐
    │  Ingest  │   │  Analyst   │   │  Manager │  Band Cloud
    │  Band    │   │  Band      │   │  Band    │  (GeminiAdapter)
    └──────────┘   └────────────┘   └──────────┘
                         │
                    ┌────▼────┐
                    │  Band   │  Shared room bridge
                    │  Bridge │  Messages stored locally
                    └─────────┘

                    ┌──────────────┐
                    │  Google Drive│  Optional backup
                    │  (Service Acct)│  Export reports as JSON
                    └──────────────┘

                    ┌──────────────┐
                    │  WebSocket   │  Real-time dashboard updates
                    │  Connection  │  Broadcasts on pipeline complete
                    │  Manager     │
                    └──────────────┘
```

### Data Flow

1. **Trigger** → `POST /api/run` starts the pipeline (or click "Run Pipeline" on the dashboard)
2. **IngestAgent** → Generates 5 sample alerts (WAF, EDR, SIEM, AV sources) pushed to `asyncio.Queue`
3. **AnalystAgent** → For each alert:
   - Searches ChromaDB for similar threat patterns (cosine similarity, top 3 matches)
   - Sends alert + matched patterns to **Gemini 2.5 Flash Lite** for LLM reasoning with structured JSON response
   - Falls back to heuristic severity scoring if Gemini is rate-limited (429)
4. **ManagerAgent** → Compiles compliance report with:
   - Alert details and analysis summary
   - Matched MITRE ATT&CK patterns (e.g., T1486 ransomware, T1110 brute force)
   - Remediation recommendations
   - Compliance notes (CISA, breach notification)
5. **Post-pipeline**:
   - Orchestrator pushes report summaries to Band cloud (if bridge is active)
   - WebSocket broadcasts update to all connected dashboard clients
6. **Frontend** → Auto-refreshes via WebSocket (no polling), shows audit trail + reports in real-time

### Agent Roles

| Agent | Role | Tools |
|-------|------|-------|
| **Ingest** | Simulates security alert sources (WAF, EDR, SIEM, AV) | `asyncio.Queue` + Band SDK (cloud) |
| **Analyst** | Threat pattern matching + LLM reasoning | ChromaDB + google-genai SDK + heuristic fallback |
| **Manager** | Compliance report generation | Pydantic models + Band SDK (cloud) |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python 3.14, FastAPI, Uvicorn, python-dotenv |
| **Agents** | Band SDK (v1.0.0) with GeminiAdapter |
| **Vector Store** | ChromaDB (all-MiniLM-L6-v2, persistent, no external API) |
| **LLM** | Gemini 2.5 Flash Lite (via google-genai SDK; heuristic fallback if rate-limited) |
| **Frontend** | Next.js 16.2.9, React 19, Tailwind CSS v4, shadcn/ui |
| **Cloud** | Band of Agents (agent orchestration + shared rooms) |
| **Backup** | Google Drive (service account) with local fallback to `exports/` |
| **Real-time** | WebSocket (auto-reconnect, 15s keepalive ping) |
| **Auth** | Optional API key header for pipeline + export endpoints |

---

## Getting Started

### Prerequisites

- Python 3.14+
- Node.js 24+
- A Gemini API key ([get one free](https://aistudio.google.com/apikey)) — only the `GEMINI_API_KEY` is strictly required
- Band of Agents credentials (agent IDs + API keys) — optional, for cloud sync
- Google Drive service account JSON key — optional, for cloud backup

### Setup — Streamlit (easiest, for hackathon)

```bash
# 1. Clone the repo
git clone <repo-url> && cd Triad

# 2. Install deps
pip install -r requirements.txt

# 3. Set your Gemini API key
# Option A: export GEMINI_API_KEY=your_key_here
# Option B: create .env file with: GEMINI_API_KEY=your_key_here

# 4. Launch
streamlit run streamlit_app.py   # → http://localhost:8501
```

### Setup — Backend + Frontend (full stack)

```bash
# 1. Clone the repo
git clone <repo-url> && cd Triad

# 2. Backend setup
cd backend
python -m venv venv
# Windows: .\venv\Scripts\activate
# Mac/Linux: source venv/bin/activate
pip install -r requirements.txt

# 3. Configure environment
cp .env.example .env
# Edit .env with your API keys:
#   GEMINI_API_KEY=your_gemini_key          (required for LLM analysis)
#   INGEST_AGENT_ID, INGEST_API_KEY          (for Band cloud, optional)
#   ANALYST_AGENT_ID, ANALYST_API_KEY        (for Band cloud, optional)
#   MANAGER_AGENT_ID, MANAGER_API_KEY        (for Band cloud, optional)
#   GOOGLE_DRIVE_CREDENTIALS=path/to/key.json (for Drive export, optional)
#   GOOGLE_DRIVE_FOLDER_ID=your_folder_id    (for Drive export, optional)
#   API_KEY=your_secret                      (optional auth for endpoints)

# 4. Start backend
python main.py   # → http://localhost:8000

# 5. Frontend setup (new terminal)
cd frontend
npm install
cp .env.local.example .env.local  # already configured for :8000
npm run dev       # → http://localhost:3000
```

### Run the Pipeline (Streamlit)

1. Open `http://localhost:8501` in your browser
2. Click **"Run Pipeline"**
3. Watch the audit trail populate and reports appear
4. Expand any incident report to see full Gemini analysis, matched MITRE patterns, and recommendations
5. Use the **Threat Intelligence Search** bar to query the intel DB (ChromaDB semantic search)

### Run the Pipeline (Web Dashboard)

1. Open `http://localhost:3000` in your browser
2. Click **"Run Pipeline"**
3. Watch the audit trail populate in real-time (WebSocket auto-updates)
4. Click on incident reports to see full Gemini analysis, matched MITRE patterns, and recommendations
5. Use the **Threat Intelligence Search** bar to query the intel DB

### API Endpoints (FastAPI server only — not needed for Streamlit)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/status` | Pipeline status + stats (running, queue, reports, audit, intel) |
| POST | `/api/run` | Trigger pipeline run (optional `auth_key` param) |
| GET | `/api/reports` | All incident reports (sorted by date desc) |
| GET | `/api/reports/{id}` | Single report detail |
| GET | `/api/audit` | Agent audit trail (sorted by timestamp desc) |
| GET | `/api/intel` | Intel pattern count |
| POST | `/api/intel/search?query=...` | Semantic search (ChromaDB cosine similarity) |
| POST | `/api/intel` | Add new intel pattern (body: `ThreatIntel` JSON) |
| GET | `/api/band/messages` | Band cloud messages (optional `?agent=` filter, `?limit=`) |
| POST | `/api/band/send` | Send message via Band (body: `agent`, `content`) |
| POST | `/api/drive/export-all` | Export all reports to Google Drive (falls back to `exports/` folder) |
| GET | `/api/drive/backups` | List Drive backups + local exports |
| WS | `/api/ws` | WebSocket — auto-broadcasts `{type: "update"}` on pipeline complete; responds to `{type: "ping"}` with pong |

---

## Project Structure

```
Triad/
├── streamlit_app.py         #  Streamlit UI — deploy this on Streamlit Cloud
├── requirements.txt         # Dependencies for Streamlit Cloud deployment
├── backend/
│   ├── main.py              # FastAPI app entry point, lifespan, CORS, service wiring
│   ├── requirements.txt
│   ├── .env.example
│   ├── chroma_data/         # Persistent ChromaDB store (auto-created)
│   ├── agents/
│   │   ├── ingest_agent.py  # Generates 5 sample security alerts into queue
│   │   ├── analyst_agent.py # ChromaDB search + Gemini LLM analysis + heuristic fallback
│   │   ├── manager_agent.py # Compliance report generator (MITRE, recommendations)
│   │   ├── orchestrator.py  # Pipeline coordinator (asyncio.Queue chaining, audit log)
│   │   └── band_agents.py   # Band SDK GeminiAdapter wrappers + bridge registration
│   ├── api/
│   │   └── routes.py        # All 14 REST endpoints + WebSocket + ConnectionManager
│   ├── db/
│   │   └── chroma_wrapper.py # ChromaDB persistent vector store (8 seed patterns)
│   ├── models/
│   │   └── schemas.py       # Pydantic models (Alert, Intel, Analysis, Report, Audit)
│   ├── services/
│   │   ├── band_bridge.py   # Band REST bridge: create room, send/poll messages
│   │   ├── google_drive.py  # Drive export via service account (falls back to local JSON)
│   │   └── message_store.py # In-memory BandMessage store with agent filtering
│   └── tests/               # Test scaffolding
├── frontend/                 # Next.js dashboard (optional — deploy separately on Vercel)
├── docs/
│   └── getting-started.md   # Quickstart guide
├── exports/                 # Local report exports (JSON files) [gitignored]
└── README.md
```

---

## Deploy on Streamlit Cloud 

1. Push the repo to GitHub (done)
2. Go to https://streamlit.io/cloud → **New app**
3. Connect your GitHub repo (`rymfhm/Triad`)
4. Set:
   - **Branch**: `main`
   - **Main file**: `streamlit_app.py`
5. Add **Secrets** (Streamlit Cloud → Advanced Settings → Secrets):
   ```toml
   GEMINI_API_KEY = "your_gemini_key_here"
   ```
6. Deploy — your app is live at `https://your-app.streamlit.app`

No separate backend server needed — Streamlit runs everything in one process.

---

## Google Drive Backup (Optional)

Reports are automatically exported to the `exports/` folder as JSON. To enable cloud backup:

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Create a project → Enable **Drive API**
3. Create a **Service Account** → download JSON key
4. Create a folder in Drive → share with the service account email
5. Set in `.env`:
   ```
   GOOGLE_DRIVE_CREDENTIALS=C:\path\to\your-service-account-key.json
   GOOGLE_DRIVE_FOLDER_ID=your_folder_id
   ```
6. Export: `POST /api/drive/export-all` — saves to Drive if configured, otherwise to `exports/`
7. View backups: `GET /api/drive/backups` — lists both Drive files and local exports

---

## Key Decisions

- **Local pipeline over pure Band-native**: The async queue pipeline runs independently — Band agents run in parallel for cloud sync. This keeps core triage fast and testable without live internet.
- **Dual LLM path**: Local Analyst calls `google-genai` SDK directly for Gemini reasoning (decoupled from Band). Band agents use `GeminiAdapter` for cloud chat. If Gemini is rate-limited, heuristic scoring kicks in — zero blocking.
- **ChromaDB (local, no API key)**: Free, persistent vector store with `all-MiniLM-L6-v2` embeddings. Downloaded once, cached forever. No external dependency.
- **WebSocket over polling**: Frontend uses WebSocket with auto-reconnect and 15s keepalive ping instead of 5s polling — reduces network chatter and gives instant updates.
- **Band bridge with REST polling**: The bridge polls Band REST API (5s interval) for messages instead of WebSocket subscriptions — simpler to implement, but may hit Band's chat room limits (50 rooms max on free tier).
- **Google Drive + local fallback**: If Drive credentials aren't configured, reports save as JSON to `exports/` — the system never fails on missing cloud config.
- **Optional API key auth**: Backend can require an `auth_key` param on pipeline/export endpoints. Leave `API_KEY` empty in `.env` to disable.
