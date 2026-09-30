# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""ASCII transliteration for the console, and the width arithmetic that goes with it.

One function, one table, one rule.  Everything the frontends print goes through
:func:`ascii` when the terminal cannot be trusted with anything else, and the
tables that need to line up are measured with :func:`width`, not ``len``.

**Why a table and not the obvious thing.**  The first version of this used
``unicodedata.normalize("NFKD", ch)`` and dropped the combining marks, which
transliterates nine of the ten Polish letters correctly and then fails on
``ł``: it has no decomposition at all, because it is a distinct letter and not
``l`` with a stroke.  The code fell through to ``"?"``, so the menu printed
``ł=?`` wherever a word contained it — a fault in the *renderer*, not in the text,
and one that showed up only in the frontend that called the renderer.

So the letters are listed.  That is not a workaround, it is the definition:
``ą→a`` is a convention chosen by us, and writing it in a table says so where a
decomposition cannot.

**Why width is not ``len``.**  ``len("ł")`` is 1 and the terminal draws it one
column wide, so that agrees.  But ``len("—")`` is also 1 while an em dash is drawn
one column wide by a UTF-8 terminal and ``?`` by one that is not, and after
transliteration ``---`` is three.  Any table that pads with ``len`` and then draws
through :func:`ascii` misaligns by exactly the characters that needed
transliterating — which is the box-drawing set, i.e. the whole frame.  So padding
happens on the *transliterated* string, and :func:`width` is the honest measure.
"""

from __future__ import annotations

import unicodedata

#: Polish letters NFKD cannot reach, plus the ones it reaches in a way that is
#: wrong rather than merely lossy.  Upper and lower are separate keys on purpose:
#: ``Ł`` and ``ł`` are different code points and a transliteration that emitted
#: ``l`` for one of them would be a half-transliteration.
POLISH = {
    "ą": "a", "ć": "c", "ę": "e", "ł": "l", "ń": "n",
    "ó": "o", "ś": "s", "ź": "z", "ż": "z",
    "Ą": "A", "Ć": "C", "Ę": "E", "Ł": "L", "Ń": "N",
    "Ó": "O", "Ś": "S", "Ź": "Z", "Ż": "Z",
}

#: Characters the UI itself draws.  These have no NFKD decomposition at all, so
#: the old renderer turned **every box-drawing character into a question mark** —
#: which is why the plain-text menu showed a frame of ``?`` and the report's rules
#: looked ragged.  Mapping them to ASCII is not a degradation: ``+``, ``-`` and
#: ``|`` are what a box is made of everywhere else.
BOX = {
    "─": "-", "━": "-", "│": "|", "┃": "|",
    "┌": "+", "┐": "+", "└": "+", "┘": "+",
    "├": "+", "┤": "+", "┬": "+", "┴": "+", "┼": "+",
    "╭": "+", "╮": "+", "╰": "+", "╯": "+",
    "═": "=", "║": "|", "╔": "+", "╗": "+", "╚": "+", "╝": "+",
    "╒": "+", "╕": "+", "╘": "+", "╛": "+", "╞": "+", "╡": "+",
    "╤": "+", "╧": "+", "╪": "+", "╫": "+", "╬": "+",
}

#: Typography.  The em dash becomes ``--`` rather than ``-`` because a single
#: hyphen between two words reads as a typo; the bullet keeps a distinguishable
#: mark, since the severity icons depend on being told apart.
TYPO = {
    "—": "--", "–": "-", "‒": "-", "―": "-", "−": "-",
    "‘": "'", "’": "'", "“": '"', "”": '"',
    "„": '"', "«": '"', "»": '"', "‹": "'", "›": "'",
    "…": "...", "·": "*", "•": "*", "×": "x", "÷": "/",
    "±": "+/-", "≤": "<=", "≥": ">=", "≠": "!=", "→": "->",
    "←": "<-", "↔": "<>", "€": "EUR", "£": "GBP", "°": " deg",
    "©": "(c)", "®": "(r)", "§": "S", "¶": "P", " ": " ",
    "✓": "OK", "✔": "OK", "✗": "x", "✘": "x", "★": "*", "☆": "*",
    "☐": "[ ]", "☑": "[x]", "☒": "[x]", "➔": "->", "▪": "*",
}

#: Anything combining is dropped rather than transliterated, which is what NFKD
#: plus combining-mark removal did and is still the right behaviour for anything
#: not named above.
DROPPED = "�"


def _table() -> dict[str, str]:
    out: dict[str, str] = {}
    for source in (POLISH, BOX, TYPO):
        out.update(source)
    return out


TABLE = _table()


def ascii(text: str, strict: bool = True) -> str:
    """Transliterate to something every terminal can draw.

    Letters go through :data:`POLISH` first, then NFKD for the rest of Latin
    (which does cover most European accented characters correctly), then the box
    and typography tables.  A character that survives all three becomes ``?``
    under ``strict`` and is dropped otherwise — and that final question mark is
    the failure the old code produced for ``ł``, so it is reported rather than
    left to be discovered in a menu.

    ``strict=False`` is for the frontends that would rather lose a character than
    print a question mark in the middle of a word.
    """
    out: list[str] = []
    for ch in text:
        if 32 <= ord(ch) < 127:
            out.append(ch)
            continue
        direct = TABLE.get(ch)
        if direct is not None:
            out.append(direct)
            continue
        folded = unicodedata.normalize("NFKD", ch)
        folded = "".join(c for c in folded if not unicodedata.combining(c))
        if folded and all(32 <= ord(c) < 127 for c in folded):
            out.append(folded)
            continue
        out.append("?" if strict else "")
    return "".join(out)


def has_non_ascii(text: str) -> bool:
    """True when anything in ``text`` would need transliterating."""
    return any(ord(ch) > 126 for ch in text)


def width(text: str) -> int:
    """Column width for terminal padding.

    Equal to ``len`` for pure ASCII, which is what every table in this project
    is measured in once transliteration has run.  Kept as a function so that a
    future wide character — a CJK glyph, an emoji — has one place to be handled
    rather than a ``len`` in a format string.
    """
    return sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1 for ch in text)


def pad(text: str, columns: int) -> str:
    """Left-align ``text`` to ``columns`` display columns, cutting if too long."""
    out = text
    while width(out) > columns and out:
        out = out[:-1]
    return out + " " * max(0, columns - width(out))


def rpad(text: str, columns: int) -> str:
    """Right-align ``text`` to ``columns`` display columns."""
    out = text
    while width(out) > columns and out:
        out = out[:-1]
    return " " * max(0, columns - width(out)) + out


def rule(columns: int, char: str = "-") -> str:
    """A horizontal rule exactly ``columns`` wide."""
    return char * max(0, columns)


def non_ascii(text: str) -> list[str]:
    """The distinct characters in ``text`` that :func:`ascii` would change.

    For the self-check: a test that runs every menu label and every table cell
    through this and gets an empty list has proved the frontends cannot print a
    byte the terminal will not draw, without anyone having to look at a screen.
    """
    seen: list[str] = []
    for ch in text:
        if ch in seen or not has_non_ascii(ch):
            continue
        seen.append(ch)
    return seen
