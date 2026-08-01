from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from cvedaemon.models import Alert


@dataclass
class ActionResult:
    status: str  # "ok" | "error" | "skipped"
    detail: str


class Action(ABC):
    name: str
    type: str

    @abstractmethod
    async def run(self, alert: Alert) -> ActionResult: ...
