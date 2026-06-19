import asyncio
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).parent / "backend"))

from dotenv import load_dotenv

load_dotenv()

gemini_key = os.getenv("GEMINI_API_KEY", "")
if gemini_key:
    os.environ["GOOGLE_API_KEY"] = gemini_key

from agents.orchestrator import AgentOrchestrator
from db.chroma_wrapper import ThreatIntelStore
from models.schemas import Severity

st.set_page_config(
    page_title="TRiaD",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown("""
<style>
    .stApp { background-color: #09090b; }
    .block-container { padding-top: 1.5rem; }
    .stButton button {
        background: #059669;
        color: white;
        border: none;
        font-weight: 600;
        transition: all 0.2s;
    }
    .stButton button:hover {
        background: #047857;
        color: white;
    }
    .stButton button:disabled {
        background: #27272a;
        color: #71717a;
    }
    .stTextInput input {
        background: #18181b;
        border: 1px solid #3f3f46;
        color: #e4e4e7;
    }
    .stTextInput input:focus {
        border-color: #059669;
    }
    .stExpander {
        border: 1px solid #27272a;
        border-radius: 0.5rem;
        background: #18181b;
    }
    .badge-idle {
        display: inline-block;
        padding: 0.125rem 0.625rem;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 600;
        background: #27272a;
        color: #a1a1aa;
        border: 1px solid #3f3f46;
    }
    .badge-active {
        display: inline-block;
        padding: 0.125rem 0.625rem;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 600;
        background: #065f46;
        color: #6ee7b7;
        border: 1px solid #059669;
    }
    .stat-card {
        padding: 1rem 1.25rem;
        border-radius: 0.5rem;
        background: #18181b;
        border: 1px solid #27272a;
    }
    .stat-label {
        font-size: 0.75rem;
        color: #a1a1aa;
        font-weight: 500;
        margin-bottom: 0.25rem;
    }
    .stat-value {
        font-size: 1.875rem;
        font-weight: 700;
        color: #f4f4f5;
    }
    .audit-entry {
        border-left: 2px solid #3f3f46;
        padding: 0.5rem 0 0.5rem 0.75rem;
        margin-bottom: 0.5rem;
    }
    .audit-agent {
        display: inline-block;
        padding: 0.0625rem 0.4375rem;
        border-radius: 0.25rem;
        font-size: 0.6875rem;
        font-weight: 600;
        background: #27272a;
        color: #d4d4d8;
        border: 1px solid #3f3f46;
    }
    .audit-time {
        font-size: 0.6875rem;
        color: #71717a;
        margin-left: 0.5rem;
    }
    .audit-detail {
        font-size: 0.8125rem;
        color: #d4d4d8;
        margin-top: 0.125rem;
    }
    .severity-critical { color: #ef4444; background: #450a0a; border-color: #dc2626; padding: 0.0625rem 0.4375rem; border-radius: 0.25rem; font-size: 0.6875rem; font-weight: 600; border: 1px solid; }
    .severity-high { color: #f97316; background: #431407; border-color: #ea580c; padding: 0.0625rem 0.4375rem; border-radius: 0.25rem; font-size: 0.6875rem; font-weight: 600; border: 1px solid; }
    .severity-medium { color: #eab308; background: #422006; border-color: #ca8a04; padding: 0.0625rem 0.4375rem; border-radius: 0.25rem; font-size: 0.6875rem; font-weight: 600; border: 1px solid; }
    .severity-low { color: #22c55e; background: #052e16; border-color: #16a34a; padding: 0.0625rem 0.4375rem; border-radius: 0.25rem; font-size: 0.6875rem; font-weight: 600; border: 1px solid; }
    .report-card {
        padding: 0.75rem;
        border-radius: 0.5rem;
        background: #18181b;
        border: 1px solid #27272a;
        cursor: pointer;
        margin-bottom: 0.5rem;
        transition: border-color 0.15s;
    }
    .report-card:hover { border-color: #52525b; }
    .report-source { font-size: 0.875rem; color: #e4e4e7; font-weight: 500; }
    .report-msg { font-size: 0.75rem; color: #71717a; margin-top: 0.25rem; }
    .report-time { font-size: 0.6875rem; color: #52525b; margin-top: 0.25rem; }
    .section-header { font-size: 0.875rem; color: #a1a1aa; font-weight: 500; margin-bottom: 0.75rem; }
    .intel-card {
        padding: 0.75rem;
        border-radius: 0.5rem;
        background: #18181b;
        border: 1px solid #27272a;
        margin-bottom: 0.5rem;
    }
    hr { border-color: #27272a; margin: 1.5rem 0; }
    .header-title { font-size: 1.25rem; font-weight: 700; color: #34d399; }
    .header-sub { font-size: 0.75rem; color: #71717a; }
    div[data-testid="stVerticalBlock"] { gap: 0.5rem; }
</style>
""", unsafe_allow_html=True)


@st.cache_resource
def init_stores():
    intel_store = ThreatIntelStore(persist_dir="./chroma_data")
    orchestrator = AgentOrchestrator(intel_store)
    return intel_store, orchestrator


intel_store, orchestrator = init_stores()


def severity_badge(severity: str) -> str:
    return f'<span class="severity-{severity}">{severity.upper()}</span>'


def format_time(dt) -> str:
    if isinstance(dt, str):
        return dt
    return dt.strftime("%b %d, %Y %H:%M:%S")


col1, col2 = st.columns([3, 1])
with col1:
    st.markdown('<div class="header-title">🛡️ TRiaD</div>', unsafe_allow_html=True)
    st.markdown('<div class="header-sub">Threat intelligence & automated defense · Multi-Agent Cyber Incident Triage Squad</div>', unsafe_allow_html=True)
with col2:
    st.markdown('<div style="text-align:right; padding-top:0.5rem">', unsafe_allow_html=True)
    is_running = orchestrator._running if hasattr(orchestrator, '_running') else False
    badge_class = "badge-active" if is_running else "badge-idle"
    badge_text = "● Pipeline Active" if is_running else "○ Idle"
    st.markdown(f'<span class="{badge_class}">{badge_text}</span>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

st.markdown("---")

controls = st.columns([1, 5])
with controls[0]:
    run_clicked = st.button("▶ Run Pipeline", use_container_width=True, type="primary")

st.markdown("---")

report_count = len(orchestrator.reports) if hasattr(orchestrator, 'reports') else 0
audit_count = len(orchestrator.audit_log) if hasattr(orchestrator, 'audit_log') else 0
intel_count = intel_store.count()

stats = st.columns(4)
with stats[0]:
    st.markdown(
        f'<div class="stat-card"><div class="stat-label">Alerts Processed</div>'
        f'<div class="stat-value">{report_count}</div></div>',
        unsafe_allow_html=True,
    )
with stats[1]:
    st.markdown(
        f'<div class="stat-card"><div class="stat-label">Reports Generated</div>'
        f'<div class="stat-value">{report_count}</div></div>',
        unsafe_allow_html=True,
    )
with stats[2]:
    st.markdown(
        f'<div class="stat-card"><div class="stat-label">Intel Patterns</div>'
        f'<div class="stat-value">{intel_count}</div></div>',
        unsafe_allow_html=True,
    )
with stats[3]:
    st.markdown(
        f'<div class="stat-card"><div class="stat-label">Audit Entries</div>'
        f'<div class="stat-value">{audit_count}</div></div>',
        unsafe_allow_html=True,
    )

st.markdown("---")

search_col1, search_col2 = st.columns([4, 1])
with search_col1:
    search_query = st.text_input(
        "Threat Intelligence Search",
        placeholder="Search threat patterns...",
        label_visibility="collapsed",
    )
with search_col2:
    search_clicked = st.button("Search", use_container_width=True)

if search_clicked and search_query.strip():
    results = intel_store.search(search_query.strip(), n_results=5)
    if results:
        st.markdown(f'<div class="section-header">Matched {len(results)} pattern(s)</div>', unsafe_allow_html=True)
        for r in results:
            st.markdown(
                f'<div class="intel-card">'
                f'<div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.25rem">'
                f'<span style="font-weight:500;color:#e4e4e7">{r.attack_type}</span>'
                f'{severity_badge(r.severity.value)}'
                + (f'<span style="font-size:0.6875rem;color:#71717a">{r.mitre_id}</span>' if r.mitre_id else "") +
                f'</div>'
                f'<div style="font-size:0.75rem;color:#a1a1aa">{r.description}</div>'
                f'<div style="font-size:0.6875rem;color:#059669;margin-top:0.25rem">{r.remediation}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )
    else:
        st.info("No matching threat patterns found.")
elif search_query and not search_clicked:
    pass

st.markdown("---")

if run_clicked:
    if orchestrator._running:
        st.warning("Pipeline is already running.")
    else:
        with st.spinner("Running pipeline — ingesting 5 alerts, analyzing with ChromaDB + Gemini..."):
            asyncio.run(orchestrator.start())
        st.success("Pipeline complete! 5 alerts processed and reported.")
        st.rerun()

left_col, right_col = st.columns(2)

with left_col:
    st.markdown('<div class="section-header">📋 Agent Audit Trail</div>', unsafe_allow_html=True)
    if audit_count == 0:
        st.markdown('<p style="color:#71717a;font-size:0.8125rem">Run the pipeline to see agent activity.</p>', unsafe_allow_html=True)
    else:
        audit_log = sorted(orchestrator.audit_log, key=lambda x: x.timestamp, reverse=True) if hasattr(orchestrator, 'audit_log') else []
        for entry in audit_log[:30]:
            agent_label = entry.agent
            ts = format_time(entry.timestamp)
            detail = entry.details[:120]
            st.markdown(
                f'<div class="audit-entry">'
                f'<span class="audit-agent">{agent_label}</span>'
                f'<span class="audit-time">{ts}</span>'
                f'<div class="audit-detail">{detail}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )

with right_col:
    st.markdown('<div class="section-header">📄 Incident Reports</div>', unsafe_allow_html=True)
    if report_count == 0:
        st.markdown('<p style="color:#71717a;font-size:0.8125rem">No reports yet. Run the pipeline.</p>', unsafe_allow_html=True)
    else:
        reports = sorted(orchestrator.reports, key=lambda x: x.generated_at, reverse=True)
        for report in reports:
            with st.expander(f"{report.alert.source}: {report.alert.message[:60]}..."):
                st.markdown(
                    f'<div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.5rem">'
                    f'<span style="font-size:0.75rem;color:#a1a1aa">Risk Level:</span>'
                    f'{severity_badge(report.analysis.risk_level.value)}'
                    f'</div>',
                    unsafe_allow_html=True,
                )
                st.markdown(
                    f'<div style="font-size:0.75rem;color:#a1a1aa;margin-bottom:0.25rem">Analysis</div>'
                    f'<div style="font-size:0.8125rem;color:#d4d4d8;margin-bottom:0.75rem">{report.analysis.summary}</div>',
                    unsafe_allow_html=True,
                )

                if report.analysis.matched_patterns:
                    st.markdown(
                        '<div style="font-size:0.75rem;color:#a1a1aa;margin-bottom:0.25rem">Matched Patterns</div>',
                        unsafe_allow_html=True,
                    )
                    for p in report.analysis.matched_patterns:
                        st.markdown(
                            f'<div style="padding:0.5rem;border-radius:0.375rem;background:#27272a;margin-bottom:0.25rem">'
                            f'<div style="font-size:0.8125rem;color:#e4e4e7">{p.attack_type} ({p.mitre_id})</div>'
                            f'<div style="font-size:0.6875rem;color:#a1a1aa">{p.description}</div>'
                            f'</div>',
                            unsafe_allow_html=True,
                        )

                if report.recommendations:
                    st.markdown(
                        '<div style="font-size:0.75rem;color:#a1a1aa;margin-bottom:0.25rem">Recommendations</div>',
                        unsafe_allow_html=True,
                    )
                    for rec in report.recommendations:
                        st.markdown(
                            f'<div style="font-size:0.8125rem;color:#d4d4d8;margin-left:1rem">• {rec}</div>',
                            unsafe_allow_html=True,
                        )

                if report.compliance_notes:
                    st.markdown(
                        f'<div style="margin-top:0.5rem;padding:0.5rem;border-radius:0.375rem;background:#1c1917;border:1px solid #292524">'
                        f'<div style="font-size:0.75rem;color:#a1a1aa;margin-bottom:0.125rem">Compliance</div>'
                        f'<div style="font-size:0.75rem;color:#d4d4d8;white-space:pre-wrap">{report.compliance_notes}</div>'
                        f'</div>',
                        unsafe_allow_html=True,
                    )

st.markdown("---")
st.markdown(
    '<div style="text-align:center;font-size:0.6875rem;color:#52525b">'
    "TRiaD · Threat intelligence & automated defense · Band of Agents Hackathon 2026</div>",
    unsafe_allow_html=True,
)
