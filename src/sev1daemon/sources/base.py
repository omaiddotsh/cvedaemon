from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime

from sev1daemon.models import Advisory


class SourceFetchIncomplete(Exception):
    """A fetch that only partly succeeded (a failed page, ecosystem or feed).

    Carries whatever advisories were fetched before the failure. The daemon
    processes them but does not advance the source's ``last_success``
    checkpoint, so the next cycle re-queries the same window instead of
    skipping past the records that were never fetched.
    """

    def __init__(self, message: str, advisories: list[Advisory] | None = None):
        super().__init__(message)
        self.advisories: list[Advisory] = list(advisories or [])


class Source(ABC):
    """Pluggable advisory source."""

    name: str

    @abstractmethod
    async def fetch(self, since: datetime) -> list[Advisory]:
        """Return advisories modified/published since `since` (UTC).

        Raise ``SourceFetchIncomplete`` (with any partial results) when part
        of the window could not be fetched; raise any other exception when
        nothing usable came back. Never return a silently truncated list.
        """
        ...
