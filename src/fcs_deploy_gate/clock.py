"""The clock: an injected boundary so tests can fix "today" and record waits."""

from __future__ import annotations

import time
from datetime import UTC, date, datetime
from typing import Protocol


class Clock(Protocol):
    def today(self) -> date: ...

    def sleep(self, seconds: float) -> None: ...


class SystemClock:
    def today(self) -> date:
        return datetime.now(UTC).date()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)
