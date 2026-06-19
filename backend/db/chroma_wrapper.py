import uuid
from typing import Optional

import chromadb
from chromadb.config import Settings

from models.schemas import Severity, ThreatIntel


class ThreatIntelStore:
    def __init__(self, persist_dir: str = "./chroma_data"):
        self.client = chromadb.PersistentClient(
            path=persist_dir,
            settings=Settings(anonymized_telemetry=False),
        )
        self.collection = self.client.get_or_create_collection(
            name="threat_intel",
            metadata={"hnsw:space": "cosine"},
        )
        self._seed_data()

    def _seed_data(self):
        if self.collection.count() > 0:
            return

        seed_patterns = [
            ThreatIntel(
                id=str(uuid.uuid4()),
                pattern="unusual outbound traffic on port 445",
                attack_type="Lateral Movement",
                mitre_id="TA0008",
                description="SMB protocol abuse for lateral movement across network segments.",
                severity=Severity.HIGH,
                remediation="Block SMB outbound to untrusted networks; segment critical assets.",
            ),
            ThreatIntel(
                id=str(uuid.uuid4()),
                pattern="multiple failed login attempts from single IP",
                attack_type="Brute Force",
                mitre_id="T1110",
                description="Credential brute-force attempts against authentication endpoints.",
                severity=Severity.MEDIUM,
                remediation="Enforce account lockout policies; deploy rate limiting.",
            ),
            ThreatIntel(
                id=str(uuid.uuid4()),
                pattern="process injecting code into lsass.exe",
                attack_type="Credential Dumping",
                mitre_id="T1003.001",
                description="LSASS process memory access for credential theft via Mimikatz-like tools.",
                severity=Severity.CRITICAL,
                remediation="Enable Credential Guard; restrict debug privileges; monitor process access events.",
            ),
            ThreatIntel(
                id=str(uuid.uuid4()),
                pattern="dns query to known malware domain",
                attack_type="Command and Control",
                mitre_id="TA0011",
                description="DNS beaconing to known malicious domains for C2 communication.",
                severity=Severity.HIGH,
                remediation="Block known malicious domains via DNS sinkhole; deploy network detection.",
            ),
            ThreatIntel(
                id=str(uuid.uuid4()),
                pattern="large file encryption detected on file server",
                attack_type="Ransomware",
                mitre_id="T1486",
                description="Mass file encryption event indicative of ransomware deployment.",
                severity=Severity.CRITICAL,
                remediation="Isolate affected systems immediately; restore from offline backups.",
            ),
            ThreatIntel(
                id=str(uuid.uuid4()),
                pattern="powershell downloading executable from remote server",
                attack_type="Initial Access",
                mitre_id="T1059.001",
                description="PowerShell used for downloading and executing remote payloads.",
                severity=Severity.HIGH,
                remediation="Restrict PowerShell execution policy; monitor script block logging.",
            ),
            ThreatIntel(
                id=str(uuid.uuid4()),
                pattern="new user account created with admin privileges",
                attack_type="Persistence",
                mitre_id="T1136.001",
                description="Unauthorized local admin account creation for persistent access.",
                severity=Severity.MEDIUM,
                remediation="Audit account creation events; enforce approval workflows for admin accounts.",
            ),
            ThreatIntel(
                id=str(uuid.uuid4()),
                pattern="sql injection attempt on web application",
                attack_type="Exploitation",
                mitre_id="T1190",
                description="SQL injection probing against web application parameters.",
                severity=Severity.HIGH,
                remediation="Use parameterized queries; deploy WAF rules for SQLi patterns.",
            ),
        ]

        self.collection.add(
            ids=[p.id for p in seed_patterns],
            documents=[p.description for p in seed_patterns],
            metadatas=[
                {
                    "pattern": p.pattern,
                    "attack_type": p.attack_type,
                    "mitre_id": p.mitre_id,
                    "severity": p.severity.value,
                    "remediation": p.remediation,
                }
                for p in seed_patterns
            ],
        )

    def search(self, query: str, n_results: int = 3) -> list[ThreatIntel]:
        results = self.collection.query(
            query_texts=[query],
            n_results=min(n_results, self.collection.count()),
        )

        matches = []
        for i in range(len(results["ids"][0])):
            meta = results["metadatas"][0][i]
            matches.append(
                ThreatIntel(
                    id=results["ids"][0][i],
                    pattern=meta.get("pattern", ""),
                    attack_type=meta.get("attack_type", ""),
                    mitre_id=meta.get("mitre_id", ""),
                    description=results["documents"][0][i],
                    severity=Severity(meta.get("severity", "low")),
                    remediation=meta.get("remediation", ""),
                )
            )
        return matches

    def add_intel(self, intel: ThreatIntel) -> str:
        intel_id = intel.id or str(uuid.uuid4())
        self.collection.add(
            ids=[intel_id],
            documents=[intel.description],
            metadatas=[
                {
                    "pattern": intel.pattern,
                    "attack_type": intel.attack_type,
                    "mitre_id": intel.mitre_id,
                    "severity": intel.severity.value,
                    "remediation": intel.remediation,
                }
            ],
        )
        return intel_id

    def count(self) -> int:
        return self.collection.count()
