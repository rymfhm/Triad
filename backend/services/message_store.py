import uuid
from datetime import datetime, timezone
from typing import Any


class BandMessage:
    def __init__(
        self,
        agent: str,
        content: str,
        room_id: str = "",
        message_type: str = "text",
    ):
        self.id = str(uuid.uuid4())
        self.agent = agent
        self.content = content
        self.room_id = room_id
        self.message_type = message_type
        self.timestamp = datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "agent": self.agent,
            "content": self.content,
            "room_id": self.room_id,
            "message_type": self.message_type,
            "timestamp": self.timestamp.isoformat(),
        }


class MessageStore:
    def __init__(self):
        self._messages: list[BandMessage] = []

    def add(self, message: BandMessage) -> None:
        self._messages.append(message)

    def get_all(self, limit: int = 50) -> list[dict[str, Any]]:
        sorted_msgs = sorted(
            self._messages, key=lambda m: m.timestamp, reverse=True
        )
        return [m.to_dict() for m in sorted_msgs[:limit]]

    def get_by_agent(self, agent: str, limit: int = 20) -> list[dict[str, Any]]:
        filtered = [m for m in self._messages if m.agent == agent]
        sorted_msgs = sorted(filtered, key=lambda m: m.timestamp, reverse=True)
        return [m.to_dict() for m in sorted_msgs[:limit]]

    def clear(self) -> None:
        self._messages.clear()

    @property
    def count(self) -> int:
        return len(self._messages)
