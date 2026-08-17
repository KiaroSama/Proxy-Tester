"""ANSI colour palette for Proxy Tester terminal output.

Leaf module: depends on nothing. Same shape and naming convention as FFmWiz's
`ffmwiz/core/colors.py`, so the two tools read as one family. Names are
semantic (what the text means) rather than literal (what colour it is), so a
palette change never requires touching call sites.
"""

from __future__ import annotations


class Color:
    RESET = "\033[0m"

    DIM = "\033[38;5;250m"

    # Section headers, one hue each so a scrolled log stays scannable.
    HEADER_SOURCES = "\033[1m\033[38;2;68;221;255m"
    HEADER_TESTING = "\033[1m\033[38;2;255;50;115m"
    HEADER_RESULTS = "\033[1m\033[38;2;145;255;95m"
    SEPARATOR = "\033[1m\033[38;2;75;130;190m"

    # Generic label / value pairing.
    LABEL = "\033[38;5;252m"
    VALUE = "\033[38;2;245;245;245m"

    # Status vocabulary.
    SUCCESS = "\033[38;2;95;255;120m"
    WARNING = "\033[38;5;214m"
    ERROR = "\033[38;2;255;95;95m"

    # Live progress line: every field a distinct hue.
    PROGRESS_TESTED = "\033[38;5;123m"
    PROGRESS_WORKING = "\033[38;5;46m"
    PROGRESS_NEED = "\033[38;5;226m"
    PROGRESS_RATE = "\033[38;5;171m"
    PROGRESS_ACTIVE = "\033[38;5;39m"
    PROGRESS_ELAPSED = "\033[38;5;180m"

    # Source fetch summary.
    SOURCE_NAME = "\033[38;5;147m"
    SOURCE_COUNT = "\033[38;5;82m"
    SOURCE_OK = "\033[38;5;120m"
    SOURCE_FAIL = "\033[38;5;209m"
    SOURCE_TOTAL = "\033[38;2;70;255;210m"

    # Proxy schemes, so a results list is readable at a glance.
    SCHEME_HTTP = "\033[38;5;117m"
    SCHEME_SOCKS4 = "\033[38;5;222m"
    SCHEME_SOCKS5 = "\033[38;5;121m"

    # Run summary values.
    OUTPUT_PATH = "\033[38;2;255;105;180m"
    PROBE_NAME = "\033[38;5;87m"


__all__ = ["Color"]
