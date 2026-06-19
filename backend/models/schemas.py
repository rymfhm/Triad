from datetime import datetime, timezone
from enum import Enum
from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, Enum):
    INGESTED = "ingested"
    ANALYZING = "analyzing"
    ANALYZED = "analyzed"
    REPORTED = "reported"
    ESCALATED = "escalated"


class RawAlert(BaseModel):
    id: str = Field(default="")
    source: str
    message: str
    severity: Severity
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw_data: dict = Field(default_factory=dict)


class ThreatIntel(BaseModel):
    id: str
    pattern: str
    attack_type: str
    mitre_id: str = ""
    description: str
    severity: Severity
    remediation: str = ""


class AnalysisResult(BaseModel):
    alert_id: str
    matched_patterns: list[ThreatIntel] = Field(default_factory=list)
    similarity_score: float = 0.0
    risk_level: Severity
    summary: str = ""


class IncidentReport(BaseModel):
    alert: RawAlert
    analysis: AnalysisResult
    report_id: str = ""
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    recommendations: list[str] = Field(default_factory=list)
    compliance_notes: str = ""
    status: AlertStatus = AlertStatus.REPORTED


class AgentMessage(BaseModel):
    agent_id: str
    room_id: str
    content: str
    message_type: str = "text"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AuditEntry(BaseModel):
    id: str
    agent: str
    action: str
    details: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
