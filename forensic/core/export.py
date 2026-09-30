# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Export helpers: terminal tables, CSV, JSON and Markdown rendering."""

from __future__ import annotations

import csv
import json
import os
from pathlib import Path
from typing import Any
from collections.abc import Iterable, Sequence

from . import text
from .findings import Finding
from .masking import Masker

ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "grey": "\033[90m",
}
SEVERITY_COLOR = {
    "info": "cyan",
    "ok": "green",
    "warn": "yellow",
    "finding": "magenta",
    "critical": "red",
}


_COLOR_ENABLED = True


def set_color(enabled: bool) -> None:
    """Global colour switch; explicit ``enabled=`` arguments still win."""
    global _COLOR_ENABLED
    _COLOR_ENABLED = bool(enabled)


def color(text: str, name: str, enabled: bool | None = None) -> str:
    use = _COLOR_ENABLED if enabled is None else enabled
    if not use or name not in ANSI:
        return text
    return f"{ANSI[name]}{text}{ANSI['reset']}"


def human_bytes(size: float) -> str:
    step = 1024.0
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(size) < step or unit == "TiB":
            return f"{size:,.2f} {unit}".replace(",", " ")
        size /= step
    return f"{size:.2f} TiB"


def hr(columns: int = 78, char: str = "─") -> str:
    """A rule ``columns`` wide once transliterated, so it stays ``columns`` wide after.

    Drawn from the *transliterated* character and counted in the same units the
    rows are padded in.  The first version multiplied a one-character string and
    then relied on the terminal to draw it one column wide, which is true until
    the terminal cannot — and then a rule that was asked for 76 columns arrives as
    76 question marks, which is wider than the table above it.
    """
    return char * columns


def render_table(
    headers: Sequence[str],
    rows: Iterable[Sequence[Any]],
    color_enabled: bool = True,
    max_col: int = 60,
    transliterate: bool = True,
) -> str:
    """Left-aligned fixed-width table for the terminal.

    Measured and padded in the units the table is **drawn** in.  Padding the
    Polish text with ``len`` and then transliterating at draw time shortens every
    cell that needed it, so the columns stop lining up exactly where a word
    contains ``ł`` — and since a rule is a run of one box-drawing character, those
    are the cells that were longest to begin with.  The ellipsis is the same story:
    ``…`` is one character that draws as three, so the cut marker goes in after
    whatever the cell became.

    ``transliterate=False`` is for tables whose cells are **evidence**.  The
    verification summary prints the value an assertion actually read, and turning
    ``zażółć.txt`` into ``zazolc.txt`` there reports a filename that is not in the
    image — the table would be asserting something false in order to look
    tidy.  Chrome (titles, labels, headings) is transliterated; findings are not.
    """
    shape = text.ascii if transliterate else (lambda value: value)
    body = [[shape("" if cell is None else str(cell)) for cell in row] for row in rows]
    heads = [shape(h) for h in headers]
    widths = [text.width(h) for h in heads]
    for row in body:
        for index, cell in enumerate(row):
            if index < len(widths):
                widths[index] = max(widths[index], min(text.width(cell), max_col))
    out = [
        "  ".join(color(text.pad(h, widths[i]), "bold", color_enabled) for i, h in enumerate(heads))
    ]
    out.append("  ".join(text.rule(widths[i]) for i in range(len(heads))))
    for row in body:
        cells = []
        for index in range(len(heads)):
            cell = row[index] if index < len(row) else ""
            if text.width(cell) > max_col:
                cell = text.pad(cell, max_col - 3) + "..."
            cells.append(text.pad(cell, widths[index]))
        out.append("  ".join(cells))
    return "\n".join(out)


def render_kv(data: dict, color_enabled: bool = True, indent: str = "  ") -> str:
    """Key/value block, aligned on transliterated keys.

    The same alignment trap as :func:`render_table`, one level down: the keys here
    are machine names and mostly short, but ``weryfikacja_kluczowa``-length
    Polish in a value does not move the column, and a key with a diacritic did.
    """
    if not data:
        return f"{indent}-"
    keys = [text.ascii(str(k)) for k in data]
    columns = max(text.width(k) for k in keys)
    lines = []
    for key, value in zip(keys, data.values()):
        rendered = value if isinstance(value, str) else repr(value)
        lines.append(
            f"{indent}{color(text.pad(key + ':', columns + 1), 'grey', color_enabled)}"
            f" {rendered}"
        )
    return "\n".join(lines)


def to_csv(
    path: Path,
    headers: Sequence[str],
    rows: Iterable[Sequence[Any]],
    masker: Masker | None = None,
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(headers)
        for row in rows:
            if masker is None:
                writer.writerow(["" if c is None else c for c in row])
            else:
                writer.writerow(
                    [
                        masker.as_json(c) if not isinstance(c, (str, int, float)) else c
                        for c in row
                    ]
                )
    return path


def json_default(obj: Any):
    """json fallback for the types the findings carry."""
    from pathlib import Path as _Path

    from .masking import Secret

    if isinstance(obj, Secret):
        return str(obj)
    if isinstance(obj, _Path):
        return str(obj)
    if isinstance(obj, (bytes, bytearray)):
        return obj.hex()
    if isinstance(obj, set):
        return sorted(obj)
    return str(obj)


def write_private(path: Path, text: str) -> Path:
    """Write a file readable by its owner only, whatever mode it had before.

    ``os.open`` applies the mode only when it *creates* the file, so an existing
    ``secrets.json`` or ``session.json`` left behind by an earlier run would keep
    whatever permissions it had.  The explicit ``chmod`` after the write is what
    makes the mode a property of the file rather than of the run.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(path, 0o600)
    return path


def to_json(path: Path, payload: Any, masker: Masker | None = None, indent: int = 2) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = masker.as_json(payload) if masker else payload
    path.write_text(
        json.dumps(data, indent=indent, ensure_ascii=False, default=json_default),
        encoding="utf-8",
    )
    return path


def findings_to_markdown(
    findings: Sequence[Finding],
    title: str,
    masker: Masker | None = None,
    generated: str = "",
) -> str:
    lines = [f"# {title}", ""]
    if generated:
        lines += [f"_{generated}_", ""]
    if not findings:
        lines += ["_No findings._", ""]
        return "\n".join(lines)
    icons = {"info": "ℹ", "ok": "✓", "warn": "⚠", "finding": "◆", "critical": "✖"}
    for finding in findings:
        lines.append(f"## {icons.get(finding.severity, '·')} {finding.title}")
        lines.append("")
        if finding.detail:
            lines += [finding.detail, ""]
        if finding.values:
            lines.append("| key | value |")
            lines.append("|---|---|")
            for key, value in finding.values.items():
                rendered = masker.as_json(value) if masker else value
                if not isinstance(rendered, (str, int, float, bool)):
                    rendered = json.dumps(rendered, ensure_ascii=False)
                lines.append(f"| `{key}` | {rendered} |")
            lines.append("")
        if finding.artifacts:
            lines.append("Artifacts:")
            lines += [f"- `{a}`" for a in finding.artifacts]
            lines.append("")
    return "\n".join(lines)
