"""Terminal presentation: colouring, headers, and the live progress line.

Layout helpers mirror FFmWiz's: `paint`, a full-width `separator_line`, a
centred `print_header`, and `pair_text` for gray-label / coloured-value pairs.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
import time
from typing import TYPE_CHECKING, Any, Deque

from .colors import Color
from .constants import RECENT_RATE_WINDOW

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .runner import SharedState

# Escape codes are for humans: suppress them when stderr is redirected.
USE_COLOR = sys.stderr.isatty() and os.environ.get("NO_COLOR") is None


def paint(text: str, color_code: str) -> str:
    if not USE_COLOR:
        return text
    return f"{color_code}{text}{Color.RESET}"


def terminal_width() -> int:
    """Usable width, clamped so a maximised window does not draw a huge rule."""
    return min(100, max(40, shutil.get_terminal_size((80, 24)).columns))


def separator_line(color_code: str = Color.SEPARATOR, char: str = "=") -> str:
    return paint(char * terminal_width(), color_code)


def print_header(text: str, color_code: str = Color.HEADER_SOURCES, char: str = "=") -> None:
    """Blank line, centred title, full-width rule - the FFmWiz section header."""
    print(file=sys.stderr)
    print(paint(text.center(terminal_width()), color_code), file=sys.stderr)
    print(separator_line(color_code, char), file=sys.stderr)


def print_pair(name: str, value: Any, value_color: str = Color.VALUE) -> None:
    label = paint(name + ":", Color.LABEL)
    print(f"  {label} {paint(str(value), value_color)}", file=sys.stderr)


def scheme_color(scheme: str) -> str:
    return {
        "http": Color.SCHEME_HTTP,
        "socks4": Color.SCHEME_SOCKS4,
        "socks5": Color.SCHEME_SOCKS5,
    }.get(scheme, Color.VALUE)


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
            paint(f"tested {state.tested}/{total}", Color.PROGRESS_TESTED),
            paint(
                f"working {state.found}",
                Color.PROGRESS_WORKING if state.found else Color.DIM,
            ),
            paint(f"need {state.need}", Color.PROGRESS_NEED),
            paint(f"{rate:.1f}/s", Color.PROGRESS_RATE),
            paint(
                f"active {state.active}",
                Color.PROGRESS_ACTIVE if state.active else Color.DIM,
            ),
        )
    )


async def progress_loop(state: SharedState, total: int) -> None:
    """Refresh the status line until the run signals stop."""
    while not state.stop_event.is_set():
        print("\r" + status_line(state, total) + " " * 10, end="", file=sys.stderr, flush=True)
        await asyncio.sleep(0.25)
