"""Bounded retries for the download and for each scan (ADR 0001): three attempts with
waits of ten and thirty seconds, through the injected clock."""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from fcs_deploy_gate.clock import Clock

RETRY_WAITS_SECONDS: tuple[float, ...] = (10.0, 30.0)
T = TypeVar("T")


class RetriesExhausted(Exception):
    """Every attempt failed; the message carries the last error."""


def with_retries(
    step: str,
    attempt: Callable[[], T],
    clock: Clock,
    retried: tuple[type[Exception], ...],
) -> T:
    attempts = len(RETRY_WAITS_SECONDS) + 1
    for index in range(attempts):
        try:
            return attempt()
        except retried as exc:
            last = exc
            if index < len(RETRY_WAITS_SECONDS):
                clock.sleep(RETRY_WAITS_SECONDS[index])
    raise RetriesExhausted(f"{step} failed after {attempts} attempts; last error: {last}")
