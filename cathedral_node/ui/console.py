"""The human presentation layer.

In human mode this writes to **stdout**, so a command's output can be captured or
piped like any other tool's (``cathedral doctor > log.txt``). In ``--json`` mode
the console is silent and stdout carries only the envelope, which is what lets
``cathedral test distill --json | jq`` work. Diagnostics go to stderr, which stays
empty in normal operation.
"""

from __future__ import annotations

import re
import sys
import textwrap
from typing import Any, Sequence

from cathedral_node.ui.theme import Glyphs, Style, stream_unicode_ok, visible_length, width

LABEL_WIDTH = 11

# Trusted styling this console emits: SGR colour sequences (`ESC[…m`). Everything
# else — OSC, cursor moves, CR, BEL, NUL and other C0 controls — is stripped from
# untrusted output at the write boundary so it cannot drive the terminal.
_SGR = re.compile("\x1b\\[[0-9;]*m")
_TERMINAL_STRIP = {c: None for c in range(0x20) if c not in (0x09, 0x0a)}
_TERMINAL_STRIP[0x7f] = None
_TERMINAL_TABLE = str.maketrans(_TERMINAL_STRIP)


def _sanitize_terminal(text: str) -> str:
    """Strip control bytes from ``text`` while preserving only trusted SGR
    sequences. Any ESC that is not a colour sequence (OSC, cursor motion) has its
    introducer removed, leaving its payload as inert text."""
    pieces = _SGR.split(text)
    styles = _SGR.findall(text)
    out: list[str] = []
    for index, piece in enumerate(pieces):
        out.append(piece.translate(_TERMINAL_TABLE))
        if index < len(styles):
            out.append(styles[index])
    return "".join(out)


def _clip(text: str, limit: int, ellipsis: str = "…") -> str:
    """Shorten to ``limit`` columns, marking that something was removed.

    Silent truncation is worse than visible truncation: a clipped value that
    looks complete is a value the reader will act on.
    """
    if limit <= 0:
        return ""
    if visible_length(text) <= limit:
        return text
    if limit <= len(ellipsis):
        return ellipsis[:limit]
    return text[: limit - len(ellipsis)] + ellipsis


class Console:
    """Line-oriented output. No cursor tricks, no alternate screen, no spinner
    that survives a redirect — output stays sane when piped or captured."""

    def __init__(self, stream=None, style: Style | None = None, quiet: bool = False) -> None:
        self.stream = stream or sys.stderr
        self.style = style or Style(stream=self.stream)
        # Detect UTF-8 capability from the stream we will actually write to, so
        # ASCII stdout with a UTF-8 stderr does not get UTF-8 glyphs it cannot
        # encode. The write boundary folds anything that slips through.
        self.glyphs = Glyphs(unicode_ok=stream_unicode_ok(self.stream))
        self.quiet = quiet
        self.width = width()
        g = self.glyphs
        self.glyph_width = max(len(x) for x in (g.ok, g.fail, g.warn, g.info, g.pending))

    # ---- primitives -----------------------------------------------------------

    # Punctuation the glyph set cannot reach: it lives in dynamic message text
    # (a platform note, a probe detail), not in the fixed glyphs. In ASCII mode a
    # terminal that cannot render UTF-8 would otherwise get a replacement box for
    # each one, so fold them to width-preserving ASCII on the way out.
    _ASCII_FOLD = str.maketrans({
        "—": "-", "–": "-", "‑": "-", "·": "-", "•": "*",
        "→": "->", "←": "<-", "“": '"', "”": '"', "‘": "'", "’": "'", "…": "...",
    })

    def write(self, text: str = "") -> None:
        if self.quiet:
            return
        # The single write boundary for the human terminal. Strip untrusted
        # control bytes here — redaction masks secrets but does not stop terminal
        # injection — while preserving only the intentional SGR colour sequences
        # the console itself emits.
        text = _sanitize_terminal(text)
        if not self.glyphs.unicode_ok:
            # Curated fold first (— → -, … → ..., nice ASCII for common
            # punctuation), then a COMPLETE fallback so no non-ASCII byte can ever
            # reach an ASCII terminal — including an arbitrary Unicode config value.
            text = text.translate(self._ASCII_FOLD).encode("ascii", "replace").decode("ascii")
        self.stream.write(text + "\n")
        self.stream.flush()

    def blank(self) -> None:
        self.write("")

    def _clip(self, text: str, limit: int) -> str:
        return _clip(text, limit, self.glyphs.ellipsis)

    def join(self, *parts: str) -> str:
        """Join phrases with the theme's separator.

        Content uses this rather than a literal '·' so ``CATHEDRAL_ASCII`` gets
        a terminal that renders every character it is sent, not a page of
        replacement boxes.
        """
        return f" {self.glyphs.mid} ".join(p for p in parts if p)

    def rule(self, label: str = "") -> None:
        g, s = self.glyphs, self.style
        if label:
            head = f"{g.rule * 2} {label} "
            self.write(s.dim(head + g.rule * max(0, self.width - visible_length(head) - 3)))
        else:
            self.write(s.dim(g.rule * (self.width - 3)))

    def title(self, text: str, subtitle: str = "") -> None:
        s = self.style
        self.blank()
        head = self._clip(text, self.width - 4)
        line = "  " + s.bold(head)
        if subtitle:
            room = self.width - 2 - visible_length(head) - 2
            if room >= 12:
                line += s.dim("  " + self._clip(subtitle, room))
        self.write(line)
        self.rule()

    def row(self, label: str, value: str, glyph: str = " ") -> None:
        """The workhorse line: ``  ✓ label       value``.

        The label column is fixed, so every row in a block aligns. A longer
        label is truncated rather than allowed to push the value column right,
        because a ragged column is harder to scan than an abbreviated word. A
        value too long for the terminal wraps with a hanging indent, so a narrow
        window loses no text and continuations stay attached to their label.
        """
        label = self._clip(label, LABEL_WIDTH)
        padded = label.ljust(LABEL_WIDTH)
        # The glyph column is fixed-width. ASCII glyphs are two or three
        # characters ("OK", "..."), so padding here is what keeps the label
        # column aligned in both themes rather than only the Unicode one.
        marked = glyph + " " * max(0, self.glyph_width - visible_length(glyph))
        indent = 2 + self.glyph_width + 1 + LABEL_WIDTH + 1

        lines = self._wrap_value(value, self.width - indent)
        self.write(f"  {marked} {self.style.dim(padded)} {lines[0]}")
        for continuation in lines[1:]:
            self.write(" " * indent + continuation)

    def _wrap_value(self, value: str, available: int) -> list[str]:
        if available < 16:
            return [self._clip(value, max(8, available))]
        if visible_length(value) <= available:
            return [value]
        # Wrap on the unstyled text; row values are plain, styling is on labels.
        wrapped = textwrap.wrap(value, width=available, break_long_words=True,
                                break_on_hyphens=False)
        return wrapped or [value]

    def ok(self, label: str, value: str) -> None:
        self.row(label, value, self.style.green(self.glyphs.ok))

    def fail(self, label: str, value: str) -> None:
        self.row(label, value, self.style.red(self.glyphs.fail))

    def warn(self, label: str, value: str) -> None:
        self.row(label, value, self.style.yellow(self.glyphs.warn))

    def info(self, label: str, value: str) -> None:
        self.row(label, value, self.style.dim(self.glyphs.info))

    def bullet(self, text: str, indent: int = 4) -> None:
        """One item in a list, wrapped with a hanging indent under the mark."""
        marker = f"{self.glyphs.info} "
        body = indent + len(marker)
        lines = textwrap.wrap(text, width=max(20, self.width - body)) or [text]
        self.write(" " * indent + marker + lines[0])
        for continuation in lines[1:]:
            self.write(" " * body + continuation)

    def bullets(self, items: Sequence[str], indent: int = 4) -> None:
        for item in items:
            self.bullet(str(item), indent=indent)

    def note(self, text: str, indent: int = 6) -> None:
        """Wrapped prose under a row. Used for explanations, never for data."""
        for line in textwrap.wrap(text, width=self.width - indent - 2) or [""]:
            self.write(" " * indent + self.style.dim(line))

    def para(self, text: str, indent: int = 2) -> None:
        for line in textwrap.wrap(text, width=self.width - indent - 2) or [""]:
            self.write(" " * indent + line)

    def command(self, cmd: str, indent: int = 6) -> None:
        """A runnable command. Never wrapped — a broken command line cannot be
        copied — so it is the one thing allowed to exceed the width."""
        self.write(" " * indent + self.style.blue(cmd))

    def kv_block(self, pairs: Sequence[tuple[str, Any]], indent: int = 6) -> None:
        """Aligned key/value detail. Values wrap under themselves."""
        if not pairs:
            return
        keywidth = min(max(len(str(k)) for k, _ in pairs), max(8, self.width // 3))
        body = indent + keywidth + 2
        for key, value in pairs:
            label = self._clip(str(key), keywidth).ljust(keywidth)
            lines = self._wrap_value(str(value), self.width - body)
            self.write(" " * indent + self.style.dim(label) + "  " + lines[0])
            for continuation in lines[1:]:
                self.write(" " * body + continuation)

    def table(self, headers: Sequence[str], rows: Sequence[Sequence[str]], indent: int = 4) -> None:
        """A minimal table.

        Columns size to their content, then shrink from the widest until the
        whole table fits. Truncation is always visible (a trailing ellipsis), so
        a clipped cell never reads as a complete value.
        """
        if not rows:
            return
        cols = len(headers)
        gap = 2
        widths = [visible_length(str(h)) for h in headers]
        for row in rows:
            for i in range(cols):
                widths[i] = max(widths[i], visible_length(str(row[i])) if i < len(row) else 0)

        budget = self.width - indent - (cols - 1) * gap
        # Shrink the widest column repeatedly rather than only the last one, so
        # one long cell cannot push every other column off the screen.
        guard = 0
        while sum(widths) > budget and guard < 500:
            guard += 1
            widest = max(range(cols), key=lambda i: widths[i])
            if widths[widest] <= 6:
                break
            widths[widest] -= 1

        s = self.style
        header = gap * " "
        self.write(" " * indent + s.dim(header.join(
            self._clip(str(h), widths[i]).ljust(widths[i]) for i, h in enumerate(headers)
        )).rstrip())
        for row in rows:
            cells = []
            for i in range(cols):
                raw = self._clip(str(row[i]) if i < len(row) else "", widths[i])
                cells.append(raw + " " * max(0, widths[i] - visible_length(raw)))
            self.write(" " * indent + (gap * " ").join(cells).rstrip())

    # ---- semantic blocks ------------------------------------------------------

    def problem(self, what: str, why: str, action: str | None = None, docs: str | None = None) -> None:
        """The error shape the whole product uses: what failed, why it matters,
        what to do. Never one without the others."""
        s = self.style
        self.blank()
        self.write("  " + s.red(self.glyphs.fail + " " + what))
        if why:
            self.note(why, indent=4)
        if action:
            self.blank()
            self.write("    " + s.dim("Next:"))
            self.command(action, indent=4)
        if docs:
            self.write("    " + s.dim(docs))

    def next_steps(self, steps: Sequence[tuple[str, str | None]]) -> None:
        if not steps:
            return
        self.blank()
        self.write("  " + self.style.dim("Next"))
        for description, command in steps:
            self.para(description, indent=4)
            if command:
                self.command(command, indent=4)

    def progress(self, label: str, detail: str = "") -> None:
        """One line per meaningful state change. Not a spinner: a log an
        operator can scroll back through and an agent can read from a file."""
        self.row(label, self.style.dim(detail) if detail else "", self.style.dim(self.glyphs.pending))
