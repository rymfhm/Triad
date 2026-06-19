# Getting Started

## Prerequisites

- Python 3.14+, Node.js 24+
- A Gemini API key — get one free at https://aistudio.google.com/apikey

## Setup

### 1. Backend

```powershell
cd backend
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

Edit `.env` — set your Gemini key (others are optional):

```env
GEMINI_API_KEY=your_key_here
# INGEST_AGENT_ID / INGEST_API_KEY  (for Band cloud, optional)
# GOOGLE_DRIVE_CREDENTIALS           (for Drive export, optional)
# API_KEY                            (auth for endpoints, optional)
```

Start:

```powershell
python main.py
```

Backend runs at **http://localhost:8000**.

### 2. Frontend

```powershell
cd frontend
npm install
npm run dev
```

Frontend runs at **http://localhost:3000**.

---

## Running the Pipeline

### Via the Web Dashboard

1. Open http://localhost:3000
2. Click **Run Pipeline**
3. Watch the audit trail populate in real-time
4. Click any incident report to see full Gemini analysis, matched MITRE patterns, and recommendations
5. Use the **Threat Intelligence Search** bar to query the intel DB

### Via API

```powershell
# Trigger pipeline
Invoke-RestMethod http://localhost:8000/api/run -Method Post

# Check status
Invoke-RestMethod http://localhost:8000/api/status

# View reports
Invoke-RestMethod http://localhost:8000/api/reports

# View audit trail
Invoke-RestMethod http://localhost:8000/api/audit
```

---

## What to Expect

After clicking **Run Pipeline**, the process takes ~25 seconds:

1. **Ingest** — 5 sample alerts are generated (WAF, EDR, SIEM, AV sources)
2. **Analyst** — Each alert is analyzed via ChromaDB similarity search + Gemini LLM reasoning
3. **Manager** — Compliance-ready incident reports are compiled with MITRE ATT&CK mappings and recommendations

The dashboard auto-updates via WebSocket as reports complete. You'll see 5 reports and ~20 audit entries per run.

---

## Exporting Reports

```powershell
# Export all reports to the exports/ folder
Invoke-RestMethod http://localhost:8000/api/drive/export-all -Method Post

# List exported files
Invoke-RestMethod http://localhost:8000/api/drive/backups
```

Reports are saved to `Triad/exports/` as JSON files with full analysis data.

---

## API Endpoints Quick Reference

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/health` | Health check |
| GET | `/api/status` | Pipeline status + stats |
| POST | `/api/run` | Trigger pipeline (optional `?auth_key=`) |
| GET | `/api/reports` | All reports |
| GET | `/api/reports/{id}` | Single report detail |
| GET | `/api/audit` | Agent audit trail |
| GET | `/api/intel` | Intel pattern count |
| POST | `/api/intel/search?query=X` | Semantic search |
| POST | `/api/intel` | Add new intel pattern |
| GET | `/api/band/messages` | Band cloud messages |
| POST | `/api/band/send` | Send message via Band |
| POST | `/api/drive/export-all` | Export all reports (Drive or local) |
| GET | `/api/drive/backups` | List exported files (Drive + local) |
| WS | `/api/ws` | Real-time dashboard updates |

---

## Notes

- **First startup** downloads the ChromaDB embedding model (`all-MiniLM-L6-v2`, ~79MB) — cached after first run
- **Gemini free tier** is rate-limited — if you hit 429 errors, the pipeline falls back to heuristic severity scoring automatically (no LLM required)
- **Band agents** connect to Band cloud at startup but are optional — the local pipeline works without them
- **Chat room limits**: Band cloud free tier allows 50 rooms. If agents fail to create rooms, it's likely at the limit — the local pipeline still works fine
- **WebSocket**: The dashboard connects via `ws://localhost:8000/api/ws` with auto-reconnect and 15s keepalive pings. No polling needed
- **Export fallback**: If Google Drive isn't configured, reports save as JSON to `Triad/exports/` automatically
