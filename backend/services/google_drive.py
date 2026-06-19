import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from typing import Optional

from models.schemas import IncidentReport

logger = logging.getLogger(__name__)


class GoogleDriveBackup:
    def __init__(self):
        raw = os.getenv("GOOGLE_DRIVE_CREDENTIALS", "")
        self.credentials_path = os.path.abspath(raw) if raw else ""
        self.folder_id = os.getenv("GOOGLE_DRIVE_FOLDER_ID", "")
        self._service = None
        self._enabled = False

    async def initialize(self) -> bool:
        if not self.credentials_path or not os.path.exists(self.credentials_path):
            logger.warning(
                "Google Drive not configured. "
                "Set GOOGLE_DRIVE_CREDENTIALS to a valid service account JSON path. "
                "See .env.example for setup instructions."
            )
            return False

        try:
            from google.oauth2 import service_account
            from googleapiclient.discovery import build

            creds = service_account.Credentials.from_service_account_file(
                self.credentials_path,
                scopes=["https://www.googleapis.com/auth/drive.file"],
            )
            self._service = build("drive", "v3", credentials=creds)
            self._enabled = True
            logger.info("Google Drive backup initialized")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize Google Drive: {e}")
            return False

    async def export_report(self, report: IncidentReport) -> Optional[str]:
        if not self._enabled or not self._service:
            return await self._export_local(report)

        try:
            content = json.dumps(
                {
                    "report_id": report.report_id,
                    "generated_at": report.generated_at.isoformat(),
                    "alert": {
                        "id": report.alert.id,
                        "source": report.alert.source,
                        "message": report.alert.message,
                        "severity": report.alert.severity.value,
                        "timestamp": report.alert.timestamp.isoformat(),
                        "raw_data": report.alert.raw_data,
                    },
                    "analysis": {
                        "risk_level": report.analysis.risk_level.value,
                        "similarity_score": report.analysis.similarity_score,
                        "summary": report.analysis.summary,
                        "matched_patterns": [
                            {
                                "pattern": p.pattern,
                                "attack_type": p.attack_type,
                                "mitre_id": p.mitre_id,
                                "severity": p.severity.value,
                                "remediation": p.remediation,
                            }
                            for p in report.analysis.matched_patterns
                        ],
                    },
                    "recommendations": report.recommendations,
                    "compliance_notes": report.compliance_notes,
                    "status": report.status.value,
                },
                indent=2,
            )

            from googleapiclient.http import MediaIoBaseUpload
            import io

            file_metadata = {
                "name": f"incident_{report.report_id[:8]}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json",
                "mimeType": "application/json",
                "parents": [self.folder_id] if self.folder_id else [],
            }
            media = MediaIoBaseUpload(
                io.BytesIO(content.encode("utf-8")),
                mimetype="application/json",
                resumable=True,
            )

            drive_file = (
                self._service.files()
                .create(body=file_metadata, media_body=media, fields="id,webViewLink")
                .execute()
            )

            file_id = drive_file.get("id")
            link = drive_file.get("webViewLink", "")
            logger.info(f"Report exported to Google Drive: {file_id}")
            return link

        except Exception as e:
            logger.warning(f"Google Drive export failed, saving locally: {e}")
            return await self._export_local(report)

    async def _export_local(self, report: IncidentReport) -> str:
        export_dir = os.path.join(os.path.dirname(self.credentials_path) if self.credentials_path else ".", "exports")
        os.makedirs(export_dir, exist_ok=True)
        filename = f"incident_{report.report_id[:8]}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(export_dir, filename)
        with open(filepath, "w") as f:
            json.dump({
                "report_id": report.report_id,
                "generated_at": report.generated_at.isoformat(),
                "alert": {
                    "id": report.alert.id,
                    "source": report.alert.source,
                    "message": report.alert.message,
                    "severity": report.alert.severity.value,
                    "timestamp": report.alert.timestamp.isoformat(),
                    "raw_data": report.alert.raw_data,
                },
                "analysis": {
                    "risk_level": report.analysis.risk_level.value,
                    "similarity_score": report.analysis.similarity_score,
                    "summary": report.analysis.summary,
                    "matched_patterns": [
                        {
                            "pattern": p.pattern,
                            "attack_type": p.attack_type,
                            "mitre_id": p.mitre_id,
                            "severity": p.severity.value,
                            "remediation": p.remediation,
                        }
                        for p in report.analysis.matched_patterns
                    ],
                },
                "recommendations": report.recommendations,
                "compliance_notes": report.compliance_notes,
                "status": report.status.value,
            }, f, indent=2)
        logger.info(f"Report saved locally: {filepath}")
        return f"local://{filepath}"

    async def list_backups(self) -> list[dict]:
        files = []
        if self._enabled and self._service:
            try:
                results = (
                    self._service.files()
                    .list(
                        q="name contains 'incident_' and mimeType='application/json'",
                        orderBy="createdTime desc",
                        pageSize=20,
                        fields="files(id, name, webViewLink, createdTime)",
                    )
                    .execute()
                )
                files.extend(results.get("files", []))
            except Exception as e:
                logger.warning(f"Failed to list Drive files: {e}")

        export_dir = os.path.join(os.path.dirname(self.credentials_path) if self.credentials_path else ".", "exports")
        if os.path.exists(export_dir):
            for fname in sorted(os.listdir(export_dir), reverse=True)[:20]:
                if fname.startswith("incident_") and fname.endswith(".json"):
                    fpath = os.path.join(export_dir, fname)
                    files.append({
                        "name": fname,
                        "webViewLink": f"file://{fpath}",
                        "createdTime": datetime.fromtimestamp(
                            os.path.getmtime(fpath), tz=timezone.utc
                        ).isoformat(),
                        "source": "local",
                    })
        return files
