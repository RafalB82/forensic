# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Shared UI helpers: prompts with defaults, validation, boxes, paging.

The frontends only draw and collect input; every decision lives in the
controller.  This module holds the small vocabulary both need.
"""

from __future__ import annotations

import os
import sys
from typing import Any
from collections.abc import Callable, Sequence

from ..core import i18n, text
from ..core.export import color, hr

QUIT = object()
BACK = object()


def is_tty() -> bool:
    return sys.stdout.isatty() and os.environ.get("TERM", "") != "dumb"


def supports_color() -> bool:
    return is_tty() and os.environ.get("NO_COLOR") is None


def clear() -> None:
    if is_tty():
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()


def banner(
    title: str,
    subtitle: str = "",
    color_enabled: bool = True,
    columns: int = 76,
) -> str:
    """The frame at the top of the screen, measured in transliterated columns.

    The original padded the title with ``f"{title:<73}"`` and drew ``│`` on both
    sides.  A title containing ``ł`` is one character shorter once transliterated,
    so the right border shifted left by exactly one column per diacritic, and a
    title with several looked like it had been typed with the cursor moving.  Both
    borders are now placed by measurement, which means the frame is the same width
    whatever the language.
    """
    inner = max(8, columns)
    lines = [
        color("+" + text.rule(inner) + "+", "grey", color_enabled),
        color(
            "| " + text.pad(text.ascii(title), inner - 2) + " |", "grey", color_enabled
        ),
    ]
    if subtitle:
        lines.append(
            color("| " + text.pad(text.ascii(subtitle), inner - 2) + " |", "grey", color_enabled)
        )
    lines.append(color("+" + text.rule(inner) + "+", "grey", color_enabled))
    return "\n".join(lines)


def box(
    title: str,
    body: Sequence[str] = (),
    color_enabled: bool = True,
    columns: int = 74,
) -> str:
    """A titled frame around a finding, with the same width discipline as `banner`.

    Body entries may span several lines.  They have to be split here, because the
    alternative — handing a multi-line string to one ``pad`` — treats the embedded
    newlines as ordinary characters, counts them as columns, and then draws a
    frame with the text running out through both sides.  The help screen is the
    only caller that does this, and it is exactly the screen that was unreadable.
    """
    inner = max(8, columns - 4)
    out = [
        color("+" + text.rule(inner + 2) + "+", "grey", color_enabled),
        color("| " + text.pad(text.ascii(title), inner) + " |", "bold", color_enabled),
    ]
    for entry in body:
        for line in str(entry).splitlines() or ("",):
            out.append(
                color("| " + text.pad(text.ascii(line), inner) + " |", "grey", color_enabled)
            )
    out.append(color("+" + text.rule(inner + 2) + "+", "grey", color_enabled))
    return "\n".join(out)


def ask(
    prompt: str,
    default: Any = None,
    kind: str = "str",
    choices: Sequence = (),
    color_enabled: bool = True,
    reader: Callable[[str], str] = input,
    on_help: Callable[[], None] | None = None,
) -> Any:
    """Prompt with a default value, validated against ``kind``.

    Returns the typed value, ``QUIT`` on q, ``BACK`` on b.

    ``on_help`` decides what a bare ``?`` does, and the default is **nothing**:
    ``?`` comes back as an ordinary answer.  This used to print the word "help"
    followed by the word "shortcuts" and re-prompt on the same line, which told a
    newcomer nothing and, worse, ate a keystroke they had aimed at the menu's own
    help screen.  A prompt that cannot explain itself should say so once and get
    out of the way, and the screen that *can* explain it now owns the key.
    """
    suffix = f" [{default}]" if default not in (None, "") else ""
    if kind == "choice" and choices:
        suffix += " (" + "|".join(str(c) for c in choices) + ")"
    while True:
        try:
            raw = reader(color(f"{prompt}{suffix}: ", "cyan", color_enabled))
        except (EOFError, KeyboardInterrupt):
            print()
            return QUIT
        raw = raw.strip()
        if raw.lower() in ("q", "quit"):
            return QUIT
        if raw.lower() in ("b", "back"):
            return BACK
        if raw == "" and default not in (None, ""):
            return default
        if raw.lower() in ("?", "help") and on_help is not None:
            on_help()
            continue
        if kind == "int":
            try:
                return int(raw)
            except ValueError:
                print(color(f"{i18n.t('common.error')}: int", "red", color_enabled))
                continue
        if kind == "bool":
            low = raw.lower()
            if low in ("t", "true", "y", "yes", "1", "tak"):
                return True
            if low in ("f", "false", "n", "no", "0", "nie"):
                return False
            print(color(f"{i18n.t('common.error')}: true/false", "red", color_enabled))
            continue
        if kind == "choice" and choices and raw not in [str(c) for c in choices]:
            print(color(f"{i18n.t('common.error')}: {'|'.join(str(c) for c in choices)}", "red", color_enabled))
            continue
        return raw


def confirm(prompt: str, default: bool = False, color_enabled: bool = True) -> bool:
    hint = "t" if default else "n"
    answer = ask(f"{prompt} [{hint}]", default=hint, kind="str", color_enabled=color_enabled)
    if answer is BACK or answer is QUIT:
        return False
    return str(answer).strip().lower() in ("t", "true", "y", "yes", "1", "tak")


def show_text(text: str, color_enabled: bool = True, max_lines: int | None = None) -> None:
    """Print text, paging it when the terminal is interactive."""
    lines = text.splitlines()
    if not is_tty() or max_lines is None:
        print(text)
        return
    step = max(10, (os.get_terminal_size().lines - 4) if hasattr(os, "get_terminal_size") else 20)
    index = 0
    while index < len(lines):
        chunk = lines[index : index + step]
        print("\n".join(chunk))
        index += step
        if index < len(lines):
            try:
                answer = input(color(i18n.t("common.pager_hint") + " ", "grey", color_enabled))
            except (EOFError, KeyboardInterrupt):
                print()
                return
            if answer.strip().lower() in ("q", "quit"):
                return


def progress_line(message: str, color_enabled: bool = True) -> None:
    if is_tty():
        sys.stdout.write("\r\033[2K" + color(message, "grey", color_enabled))
        sys.stdout.flush()


def progress_done(message: str = "", color_enabled: bool = True) -> None:
    if is_tty():
        sys.stdout.write("\r\033[2K")
        if message:
            sys.stdout.write(color(message, "grey", color_enabled) + "\n")
        sys.stdout.flush()


def rule(color_enabled: bool = True, columns: int = 76) -> str:
    return color(hr(columns), "grey", color_enabled)


def toggle_reveal() -> bool:
    i18n.set_reveal(not i18n.reveal())
    return i18n.reveal()


def toggle_lang() -> str:
    i18n.set_lang("en" if i18n.get_lang() == "pl" else "pl")
    return i18n.get_lang()
