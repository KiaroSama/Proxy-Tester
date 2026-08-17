"""ANSI colouring and the live progress line."""

from __future__ import annotations

import asyncio
import os
import sys
import time
from typing import TYPE_CHECKING, Deque

from .constants import RECENT_RATE_WINDOW

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .runner import SharedState


class Ansi:
    """The handful of SGR codes used by the status output."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"


USE_COLOR = sys.stderr.isatty() and not os.environ.get("NO_COLOR")


def paint(text: str, code: str) -> str:
    if not USE_COLOR:
        return text
    return f"{code}{text}{Ansi.RESET}"


def recent_rate(samples: Deque[float], window: float = RECENT_RATE_WINDOW) -> float:
    """Rate over a short sliding window, so the figure stays honest near the end."""
    now = time.monotonic()
    while samples and now - samples[0] > window:
        samples.popleft()
    if not samples:
        return 0.0
    span = max(0.25, min(window, now - samples[0]))
    return len(samples) / span


def status_line(state: SharedState, total: int) -> str:
    rate = recent_rate(state.recent_tests)
    return " | ".join(
        (
            paint(f"Tested {state.tested}/{total}", Ansi.CYAN),
            paint(f"working={state.found}", Ansi.GREEN if state.found > 0 else Ansi.DIM),
            paint(f"need={state.need}", Ansi.YELLOW),
            paint(f"rate={rate:.1f}/s", Ansi.MAGENTA),
            paint(f"active={state.active}", Ansi.BLUE if state.active > 0 else Ansi.DIM),
        )
    )


async def progress_loop(state: SharedState, total: int) -> None:
    """Refresh the status line until the run signals stop."""
    while not state.stop_event.is_set():
        print("\r" + status_line(state, total) + " " * 10, end="", file=sys.stderr, flush=True)
        await asyncio.sleep(0.25)
