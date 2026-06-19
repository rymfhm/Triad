import asyncio
import logging
import os
import uuid
from datetime import datetime, timezone

from models.schemas import AlertStatus, RawAlert, Severity, AuditEntry

logger = logging.getLogger(__name__)

SAMPLE_ALERTS = [
    RawAlert(
        source="EDR",
        message="Unusual outbound SMB traffic detected from workstation 10.0.1.45 to external IP 203.0.113.50 on port 445",
        severity=Severity.HIGH,
        raw_data={"src_ip": "10.0.1.45", "dst_ip": "203.0.113.50", "port": 445, "protocol": "SMB", "bytes_sent": 15000000},
    ),
    RawAlert(
        source="SIEM",
        message="Multiple failed login attempts (150 in 5 minutes) from IP 198.51.100.23 targeting admin accounts",
        severity=Severity.MEDIUM,
        raw_data={"src_ip": "198.51.100.23", "target": "admin", "attempts": 150, "window_minutes": 5},
    ),
    RawAlert(
        source="EDR",
        message="PowerShell process (pid 8432) downloading executable from hxxp://malware-c2.example.com/payload.exe",
        severity=Severity.HIGH,
        raw_data={"pid": 8432, "process": "powershell.exe", "url": "hxxp://malware-c2.example.com/payload.exe", "user": "svc_backup"},
    ),
    RawAlert(
        source="AV",
        message="Ransomware behavior detected: file server FS-01 has 5000+ files encrypted in last 60 seconds",
        severity=Severity.CRITICAL,
        raw_data={"server": "FS-01", "files_encrypted": 5000, "extension": ".encrypted", "detected_by": "behavioral_analysis"},
    ),
    RawAlert(
        source="WAF",
        message="SQL injection attempt detected on /api/search endpoint from IP 203.0.113.99",
        severity=Severity.HIGH,
        raw_data={"src_ip": "203.0.113.99", "endpoint": "/api/search", "payload": "' OR 1=1--", "blocked": True},
    ),
]


class IngestAgent:
    def __init__(self, alert_queue: asyncio.Queue, audit_log: list[AuditEntry]):
        self.alert_queue = alert_queue
        self.audit_log = audit_log
        self.band_agent = None

    async def run(self):
        logger.info("IngestAgent started. Monitoring for alerts...")
        for alert in SAMPLE_ALERTS:
            alert.id = str(uuid.uuid4())
            alert.timestamp = datetime.now(timezone.utc)
            self._audit("ingested", f"Alert from {alert.source}: {alert.message[:60]}...")
            await self.alert_queue.put(alert)
            logger.info(f"Ingested alert {alert.id} from {alert.source} [severity={alert.severity.value}]")
            await asyncio.sleep(3)
        logger.info("IngestAgent finished ingesting all sample alerts.")

    def _audit(self, action: str, details: str):
        entry = AuditEntry(
            id=str(uuid.uuid4()),
            agent="ingest",
            action=action,
            details=details,
        )
        self.audit_log.append(entry)
