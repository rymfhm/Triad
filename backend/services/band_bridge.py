import asyncio
import logging
import os
from typing import Optional

import httpx

from services.message_store import BandMessage, MessageStore

logger = logging.getLogger(__name__)

BAND_REST_URL = os.getenv("BAND_REST_URL", "https://app.band.ai")


class BandBridge:
    def __init__(self, message_store: MessageStore):
        self.message_store = message_store
        self.shared_room_id: Optional[str] = None
        self._agent_credentials: list[dict[str, str]] = []
        self._running = False
        self._poll_task: Optional[asyncio.Task] = None

    def add_agent(self, agent_id: str, api_key: str, name: str) -> None:
        self._agent_credentials.append({
            "id": agent_id,
            "key": api_key,
            "name": name,
        })

    async def create_shared_room(self) -> Optional[str]:
        if not self._agent_credentials:
            logger.warning("No agent credentials for Band bridge")
            return None

        creds = self._agent_credentials[0]
        headers = {"Authorization": f"Bearer {creds['key']}"}

        async with httpx.AsyncClient(base_url=BAND_REST_URL) as client:
            resp = await client.post(
                "/api/v1/agent/chats",
                headers=headers,
                json={"name": "threat-intel-desk-bridge"},
            )
            if resp.status_code != 201:
                logger.error(f"Failed to create room: {resp.status_code} {resp.text}")
                return None

            data = resp.json()
            self.shared_room_id = data.get("id") or data.get("chat", {}).get("id")
            logger.info(f"Shared Band room created: {self.shared_room_id}")

            for other in self._agent_credentials[1:]:
                await client.post(
                    f"/api/v1/agent/chats/{self.shared_room_id}/participants",
                    headers=headers,
                    json={"agent_id": other["id"]},
                )
                logger.info(f"Added {other['name']} to shared room")

            return self.shared_room_id

    async def send_message(self, agent_name: str, content: str) -> bool:
        if not self.shared_room_id or not self._agent_credentials:
            logger.warning("Bridge not initialized")
            return False

        agent_creds = next(
            (c for c in self._agent_credentials if c["name"] == agent_name),
            self._agent_credentials[0],
        )
        headers = {"Authorization": f"Bearer {agent_creds['key']}"}

        async with httpx.AsyncClient(base_url=BAND_REST_URL) as client:
            resp = await client.post(
                f"/api/v1/agent/chats/{self.shared_room_id}/messages",
                headers=headers,
                json={"content": content, "message_type": "text"},
            )
            if resp.status_code != 201:
                logger.error(f"Send failed: {resp.status_code}")
                return False

        msg = BandMessage(
            agent=agent_name,
            content=content,
            room_id=self.shared_room_id,
        )
        self.message_store.add(msg)
        return True

    async def poll_messages(self) -> None:
        while self._running:
            try:
                await self._fetch_new_messages()
            except Exception as e:
                logger.error(f"Poll error: {e}")
            await asyncio.sleep(5)

    async def _fetch_new_messages(self) -> None:
        if not self.shared_room_id or not self._agent_credentials:
            return

        for creds in self._agent_credentials:
            headers = {"Authorization": f"Bearer {creds['key']}"}
            async with httpx.AsyncClient(base_url=BAND_REST_URL) as client:
                resp = await client.get(
                    f"/api/v1/agent/chats/{self.shared_room_id}/messages",
                    headers=headers,
                    params={"page": 1, "page_size": 20},
                )
                if resp.status_code != 200:
                    continue

                data = resp.json()
                messages = data if isinstance(data, list) else data.get("messages", data.get("data", []))
                for msg_data in messages:
                    content = msg_data.get("content", "")
                    sender = msg_data.get("sender", {}).get("name", "unknown")
                    if not any(
                        m.content == content and m.agent == sender
                        for m in self.message_store._messages[-50:]
                    ):
                        msg = BandMessage(
                            agent=sender,
                            content=content,
                            room_id=self.shared_room_id,
                        )
                        self.message_store.add(msg)

    async def start(self):
        self._running = True
        await asyncio.sleep(2)
        await self.create_shared_room()
        self._poll_task = asyncio.create_task(self.poll_messages())
        logger.info("Band bridge started")

    async def stop(self):
        self._running = False
        if self._poll_task:
            self._poll_task.cancel()
        logger.info("Band bridge stopped")
