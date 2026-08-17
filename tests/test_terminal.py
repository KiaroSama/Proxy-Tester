"""Terminal presentation: palette integrity and the layout helpers."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from proxy_tester import terminal
from proxy_tester.colors import Color
from proxy_tester.constants import SCHEME_ORDER

PALETTE = {name: value for name, value in vars(Color).items() if name.isupper() and isinstance(value, str)}


class TestPalette:
    def test_every_entry_is_a_real_sgr_sequence(self):
        for name, value in PALETTE.items():
            assert value.startswith("\033["), f"{name} is not an escape sequence"
            assert value.endswith("m"), f"{name} does not terminate with 'm'"

    def test_reset_is_the_plain_sgr_reset(self):
        assert Color.RESET == "\033[0m"

    def test_no_entry_is_defined_twice_under_two_names(self):
        # Two names for one colour means the palette cannot be retuned safely.
        seen: dict[str, str] = {}
        for name, value in PALETTE.items():
            if name == "RESET":
                continue
            assert value not in seen, f"{name} duplicates {seen[value]}"
            seen[value] = name

    def test_progress_fields_are_visually_distinct(self):
        fields = [v for k, v in PALETTE.items() if k.startswith("PROGRESS_")]
        assert len(fields) == len(set(fields))

    def test_headers_are_distinct_so_sections_are_scannable(self):
        headers = [v for k, v in PALETTE.items() if k.startswith("HEADER_")]
        assert len(headers) >= 3
        assert len(headers) == len(set(headers))

    def test_every_defined_colour_is_actually_referenced(self):
        # Guards against the palette drifting back into speculative entries.
        src = "".join(
            p.read_text(encoding="utf-8")
            for p in Path(terminal.__file__).parent.glob("*.py")
            if p.name != "colors.py"
        )
        unused = [n for n in PALETTE if f"Color.{n}" not in src]
        assert not unused, f"unused palette entries: {unused}"


class TestPaint:
    def test_wraps_in_colour_when_enabled(self, monkeypatch):
        monkeypatch.setattr(terminal, "USE_COLOR", True)
        assert terminal.paint("hi", Color.SUCCESS) == f"{Color.SUCCESS}hi{Color.RESET}"

    def test_returns_bare_text_when_disabled(self, monkeypatch):
        monkeypatch.setattr(terminal, "USE_COLOR", False)
        assert terminal.paint("hi", Color.SUCCESS) == "hi"

    def test_disabled_output_carries_no_escape_codes(self, monkeypatch):
        # Redirected stderr must stay clean for grep and log files.
        monkeypatch.setattr(terminal, "USE_COLOR", False)
        assert "\033" not in terminal.paint("hi", Color.ERROR)


class TestWidthAndSeparator:
    @pytest.mark.parametrize("columns", [10, 40, 80, 100, 5000])
    def test_width_is_clamped_to_a_sane_range(self, monkeypatch, columns):
        import os
        import shutil

        monkeypatch.setattr(shutil, "get_terminal_size", lambda _d=None: os.terminal_size((columns, 24)))
        assert 40 <= terminal.terminal_width() <= 100

    def test_separator_length_matches_the_width(self, monkeypatch):
        monkeypatch.setattr(terminal, "USE_COLOR", False)
        assert len(terminal.separator_line()) == terminal.terminal_width()

    def test_separator_honours_a_custom_character(self, monkeypatch):
        monkeypatch.setattr(terminal, "USE_COLOR", False)
        assert set(terminal.separator_line(char="-")) == {"-"}


class TestLayoutHelpers:
    def test_header_prints_title_and_rule(self, monkeypatch, capsys):
        monkeypatch.setattr(terminal, "USE_COLOR", False)
        terminal.print_header("SOURCES")
        lines = capsys.readouterr().err.splitlines()
        assert lines[0] == ""
        assert lines[1].strip() == "SOURCES"
        assert set(lines[2]) == {"="}

    def test_pair_prints_label_and_value(self, monkeypatch, capsys):
        monkeypatch.setattr(terminal, "USE_COLOR", False)
        terminal.print_pair("Workers", 1000)
        assert capsys.readouterr().err.strip() == "Workers: 1000"

    @pytest.mark.parametrize("scheme", SCHEME_ORDER)
    def test_every_scheme_has_its_own_colour(self, scheme):
        assert terminal.scheme_color(scheme) != Color.VALUE

    def test_unknown_scheme_falls_back(self):
        assert terminal.scheme_color("gopher") == Color.VALUE

    def test_scheme_colours_are_mutually_distinct(self):
        colours = [terminal.scheme_color(s) for s in SCHEME_ORDER]
        assert len(colours) == len(set(colours))


class TestStatusLine:
    def _state(self, tested=5, found=2, need=10, active=3):
        from proxy_tester.runner import SharedState

        s = SharedState(need=need)
        s.tested, s.found, s.active = tested, found, active
        return s

    def test_reports_every_counter(self, monkeypatch):
        monkeypatch.setattr(terminal, "USE_COLOR", False)
        line = terminal.status_line(self._state(), 100)
        assert "tested 5/100" in line
        assert "working 2" in line
        assert "need 10" in line
        assert "active 3" in line

    def test_rate_is_zero_before_any_sample(self, monkeypatch):
        monkeypatch.setattr(terminal, "USE_COLOR", False)
        assert "0.0/s" in terminal.status_line(self._state(), 100)

    def test_recent_rate_drops_stale_samples(self):
        from collections import deque

        assert terminal.recent_rate(deque()) == 0.0

    def test_line_is_plain_text_when_colour_is_off(self, monkeypatch):
        monkeypatch.setattr(terminal, "USE_COLOR", False)
        assert "\033" not in terminal.status_line(self._state(), 100)

    def test_no_stray_ansi_when_colour_is_on(self, monkeypatch):
        # Every opened sequence must be closed, or the terminal bleeds colour.
        monkeypatch.setattr(terminal, "USE_COLOR", True)
        line = terminal.status_line(self._state(), 100)
        assert line.count(Color.RESET) == len(re.findall(r"\033\[(?!0m)", line))
