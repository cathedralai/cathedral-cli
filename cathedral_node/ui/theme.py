"""Terminal styling.

Restrained on purpose. Four colours, one dim, one bold. Everything must read
correctly with colour stripped and at 80 columns, so colour only ever
*reinforces* a distinction that the text already makes — a red line always also
says what failed, a green line always also says what passed.
"""

from __future__ import annotations

import os
import shutil
import sys

_RESET = "\033[0m"
_CODES = {
    "dim": "\033[2m",
    "bold": "\033[1m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[36m",
}


def colour_enabled(stream=None) -> bool:
    """Honour NO_COLOR, FORCE_COLOR, and whether we are on a terminal."""
    stream = stream or sys.stderr
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR") or os.environ.get("CATHEDRAL_FORCE_COLOR"):
        return True
    if os.environ.get("TERM") == "dumb":
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def width(default: int = 80) -> int:
    """Usable terminal width, clamped so long lines never wrap awkwardly."""
    override = os.environ.get("COLUMNS")
    if override and override.isdigit():
        return max(60, min(int(override), 110))
    try:
        cols = shutil.get_terminal_size((default, 24)).columns
    except OSError:
        cols = default
    return max(60, min(cols, 110))


class Style:
    """Applies or strips styling. One instance per output stream."""

    __slots__ = ("enabled",)

    def __init__(self, enabled: bool | None = None, stream=None) -> None:
        self.enabled = colour_enabled(stream) if enabled is None else enabled

    def _wrap(self, code: str, text: str) -> str:
        if not self.enabled or not text:
            return text
        return f"{_CODES[code]}{text}{_RESET}"

    def dim(self, text: str) -> str:
        return self._wrap("dim", text)

    def bold(self, text: str) -> str:
        return self._wrap("bold", text)

    def red(self, text: str) -> str:
        return self._wrap("red", text)

    def green(self, text: str) -> str:
        return self._wrap("green", text)

    def yellow(self, text: str) -> str:
        return self._wrap("yellow", text)

    def blue(self, text: str) -> str:
        return self._wrap("blue", text)


# Status glyphs. ASCII fallback when the terminal cannot promise UTF-8, because
# a mojibake box is worse than a plain letter.
def stream_unicode_ok(stream) -> bool:
    """Whether UTF-8 may be emitted to THIS stream.

    Inspect the stream we will actually write to — not ``sys.stderr``. When the
    human view goes to stdout, an ASCII stdout with a UTF-8 stderr would otherwise
    be told "unicode ok" from the wrong stream, and the next write of a box-drawing
    glyph raises ``UnicodeEncodeError``.
    """
    if os.environ.get("CATHEDRAL_ASCII"):
        return False
    encoding = (getattr(stream, "encoding", "") or "").lower()
    return "utf" in encoding


def _unicode_ok() -> bool:
    return stream_unicode_ok(sys.stderr)


class Glyphs:
    """The character set. ``mid`` is the separator content uses between
    phrases, so a plain-ASCII terminal never receives a character it cannot
    render — a replacement box is worse than a hyphen."""

    __slots__ = ("ok", "fail", "warn", "info", "pending", "bullet", "rule", "arrow", "mid",
                 "ellipsis", "unicode_ok")

    def __init__(self, unicode_ok: bool | None = None) -> None:
        rich = _unicode_ok() if unicode_ok is None else unicode_ok
        self.unicode_ok = rich
        if rich:
            self.ok, self.fail, self.warn = "✓", "✗", "!"
            self.info, self.pending, self.bullet = "·", "…", "•"
            self.rule, self.arrow, self.mid = "─", "→", "·"
            self.ellipsis = "…"
        else:
            self.ok, self.fail, self.warn = "OK", "X", "!"
            self.info, self.pending, self.bullet = ".", "...", "*"
            self.rule, self.arrow, self.mid = "-", "->", "|"
            self.ellipsis = "..."


def visible_length(text: str) -> int:
    """Length ignoring ANSI escapes, for alignment."""
    import re

    return len(re.sub(r"\033\[[0-9;]*m", "", text))
