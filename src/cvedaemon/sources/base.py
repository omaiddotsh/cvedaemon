from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime

from cvedaemon.models import Advisory


class Source(ABC):
    """Pluggable advisory source."""

    name: str

    @abstractmethod
    async def fetch(self, since: datetime) -> list[Advisory]:
        """Return advisories modified/published since `since` (UTC)."""
        ...
