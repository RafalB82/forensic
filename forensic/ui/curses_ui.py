# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Frontend 2: a curses TUI with a module list on the left and details on the right."""

from __future__ import annotations

import curses
from typing import Any

from ..core import config as config_mod
from ..core import i18n
from ..core import text as text_mod
from ..modules import registry
from .menu import ACTIONS as MENU_ACTIONS

CATEGORY_ORDER = [key for key, _label in config_mod.CATEGORIES]
SEVERITY_INDEX = {"info": 0, "ok": 1, "warn": 2, "finding": 3, "critical": 4}
SEVERITY_PAIR = {
    "info": (curses.COLOR_CYAN, -1),
    "ok": (curses.COLOR_GREEN, -1),
    "warn": (curses.COLOR_YELLOW, -1),
    "finding": (curses.COLOR_MAGENTA, -1),
    "critical": (curses.COLOR_RED, curses.A_BOLD),
}


def fitted(text: str, columns: int, chrome: bool = True) -> str:
    """Fit a line to ``columns``, marking it when it does not fit.

    Cutting without a mark is the one way to make a truncated path look complete:
    ``/path/to/redmi3_userdata_full_v`` reads as a whole path to anybody
    who does not already know the longer one.  The mark costs the last three
    columns, so the result is never longer than what it was asked to be.

    ``chrome=False`` skips the transliteration, for the lines that carry
    something read off the image.  Those must reach the screen byte for byte — the
    mark is a display artefact, but a transliterated ``ż`` is a different byte,
    and in this tool that is a different file.
    """
    out = safe(text) if chrome else text
    if text_mod.width(out) <= columns:
        return out
    if columns <= 3:
        return out[:columns]
    return out[: columns - 3] + "..."


def safe(text: str) -> str:
    """Transliterate to the terminal's 8-bit range instead of showing '?'.

    Delegates to :func:`forensic.core.text.ascii`, which has the Polish letters
    in a table.  The NFKD version this replaced worked for nine of the ten and
    failed on ``ł`` — no decomposition, because it is a distinct letter — so the
    menu printed ``ł=?``, and every box-drawing character became a question mark,
    because those have no decomposition either.  One table, shared with the
    plain-text frontend, so the two cannot disagree about what is drawable.
    """
    return text_mod.ascii(text)


class CursesUI:
    """Arrow-key frontend; shares all logic with the controller."""

    name = "curses"

    def __init__(self, controller) -> None:
        self.c = controller
        self.state = {"category": 0, "index": 0, "scroll": 0, "status": ""}

    def run(self) -> int:
        return curses.wrapper(self._boot)

    def _boot(self, stdscr: Any) -> int:
        self.init_colors(stdscr)
        stdscr.nodelay(False)
        return self._main(stdscr)

    def entries(self) -> list[tuple[str, str]]:
        """The same list the plain-text frontend shows, in the same order.

        Both frontends read this one shape — categories with their modules
        indented under them, then the actions — because two frontends offering two
        different orderings is the same problem as two frontends offering two
        different key bindings: a muscle memory trained on one is wrong in the
        other.  The plain-text one shows the *action* names rather than the module
        titles for the actions, so both use the same six labels.
        """
        out: list[tuple[str, str]] = []
        out.append(("act:__head", i18n.t("menu.categories")))
        for key in CATEGORY_ORDER:
            specs = registry.in_category(key)
            if not specs:
                continue
            label = i18n.t(dict(config_mod.CATEGORIES)[key])
            out.append((f"cat:{key}", f"  {len(specs):>2}  {label}"))
            for spec in specs:
                out.append((f"mod:{spec.id}", f"        {i18n.t(spec.title)}"))
        out.append(("act:__head", ""))
        out.append(("act:__head", i18n.t("menu.actions")))
        for letter, name, label_key, hint_key in MENU_ACTIONS:
            label = i18n.t(label_key)
            if hint_key:
                label = f"{label} — {i18n.t(hint_key)}"
            out.append((f"act:{name}", f"  {letter}  {label}"))
        return out

    def _main(self, stdscr: Any) -> int:
        curses.curs_set(0)
        stdscr.keypad(True)
        while True:
            entries = self.entries()
            self.state["index"] = max(0, min(self.state["index"], len(entries) - 1))
            self.draw(stdscr, entries)
            key = stdscr.getch()
            if key in (curses.KEY_UP, ord("k")):
                self.state["index"] -= 1
            elif key in (curses.KEY_DOWN, ord("j")):
                self.state["index"] += 1
            elif key in (curses.KEY_PPAGE, ord("g")):
                self.state["index"] -= 10
            elif key in (curses.KEY_NPAGE, ord("G")):
                self.state["index"] += 10
            elif key in (curses.KEY_HOME,):
                self.state["index"] = 0
            elif key in (curses.KEY_END,):
                self.state["index"] = len(entries) - 1
            elif key in (curses.KEY_RESIZE,):
                continue
            elif key in (10, 13, curses.KEY_ENTER):
                outcome = self.activate(stdscr, entries[self.state["index"]][0])
                if outcome == "quit":
                    return 0
            elif key in (ord("l"),):
                i18n.set_lang("en" if i18n.get_lang() == "pl" else "pl")
            elif key in (ord("r"),):
                i18n.set_reveal(not i18n.reveal())
            elif key in (ord("q"), 27):
                return 0
            elif key in (ord("?"),):
                self.help(stdscr)

    def draw(self, stdscr: Any, entries: list[tuple[str, str]]) -> None:
        stdscr.erase()
        height, width = stdscr.getmaxyx()
        left_width = min(46, max(30, width // 3))
        self.draw_list(stdscr, entries, left_width, height)
        self.draw_detail(stdscr, entries, left_width, width, height)
        stdscr.refresh()

    def draw_list(self, stdscr: Any, entries: list[tuple[str, str]], left: int, height: int) -> None:
        stdscr.attron(curses.A_BOLD)
        stdscr.addstr(0, 0, fitted(f"{i18n.t('app.name')} — {i18n.t('menu.title')}", left - 1))
        stdscr.attroff(curses.A_BOLD)
        stdscr.hline(1, 0, curses.ACS_HLINE, left)
        visible = height - 3
        start = max(0, min(self.state["index"] - visible // 2, len(entries) - visible))
        for row, index in enumerate(range(start, min(start + visible, len(entries)))):
            kind, label = entries[index]
            if index == self.state["index"]:
                stdscr.attron(curses.A_REVERSE)
            stdscr.addstr(2 + row, 1, fitted(label, left - 2))
            if index == self.state["index"]:
                stdscr.attroff(curses.A_REVERSE)
        stdscr.hline(height - 1, 0, curses.ACS_HLINE, left)
        hint = i18n.t("menu.hint.keys")
        if height > 2:
            stdscr.addstr(height - 1, 0, fitted(hint, left - 1), curses.A_DIM)

    def draw_detail(
        self, stdscr: Any, entries: list[tuple[str, str]], left: int, width: int, height: int
    ) -> None:
        kind, label = entries[self.state["index"]]
        stdscr.vline(0, left, curses.ACS_VLINE, height)
        column = left + 2
        available = width - column - 1
        if available < 10:
            return
        lines: list[tuple[str, int, int]] = []

        # Set by `chrome`/`put` below: the pane is rendered from a mixed list, so
        # each line carries its own answer to "is this ours or the image's?".
        data_is_chrome = True

        def put(text: str, attr: int = 0, pair: tuple = ()) -> None:
            """A line carrying something read off the image — never transliterated."""
            nonlocal data_is_chrome
            data_is_chrome = False
            lines.append((text, attr, pair))

        def chrome(text: str, attr: int = 0, pair: tuple = ()) -> None:  # noqa: F811
            """A line of the interface, as opposed to something read off the image.

            The detail pane holds both.  A module summary is chrome and goes
            through ``safe()``; a finding title, a parameter value and an image
            path are evidence and must reach the screen byte for byte, because
            this tool's whole job is to show what the image says.  Passing the
            wrong one of the two is how a report ends up naming a file that is not
            there.
            """
            nonlocal data_is_chrome
            data_is_chrome = True
            lines.append((safe(text), attr, pair))

        if kind.startswith("mod:"):
            spec = registry.by_id(kind[4:])
            if spec is None:
                return
            chrome(i18n.t(spec.title), curses.A_BOLD)
            chrome(i18n.t(spec.summary), 0, (curses.COLOR_GREEN, -1))
            chrome("")
            chrome(f"id: {spec.id}", 0, (curses.COLOR_CYAN, -1))
            for param in spec.params:
                default = param.default
                label = i18n.t(param.label) if param.label.startswith("param.") else param.label
                chrome(f"  - {label}")
                put(f"      default: {default}  ({param.kind})", 0, (curses.COLOR_YELLOW, -1))
            if spec.needs_sudo:
                chrome("(requires sudo)", 0, (curses.COLOR_RED, -1))
            chrome("")
            chrome("Enter = run", curses.A_BOLD)
        elif kind == "act:results":
            chrome(i18n.t("menu.results.title"), curses.A_BOLD)
            for result in self.c.ctx.results:
                put(
                    f"{result.module_id:22s} {result.seconds:6.1f}s  worst={result.worst}"
                )
                for finding in result.findings:
                    pair = SEVERITY_PAIR.get(finding.severity, (curses.COLOR_WHITE, -1))
                    put(f"   {finding.severity:9s} {finding.title[:60]}", 0, pair)
        else:
            chrome(label.strip(" -\u2500"), curses.A_BOLD)
            chrome("")
            chrome(f"{i18n.t('status.image')}:")
            put(str(self.c.ctx.image))
            chrome(f"{i18n.t('status.work')}:")
            put(str(self.c.ctx.workdir))
            chrome(f"{i18n.t('status.lang')}: {i18n.get_lang()}")
            chrome(
                f"{i18n.t('status.reveal')}: "
                f"{i18n.t('status.revealed' if i18n.reveal() else 'status.masked')}"
            )
        start = max(0, self.state["scroll"])
        for row, (text, attr, pair) in enumerate(lines[start : start + (height - 2)]):
            pair_attr = curses.color_pair(self.pair_number(*pair)[0]) if pair else 0
            if pair_attr:
                stdscr.attron(pair_attr)
            if attr:
                stdscr.attron(attr)
            try:
                stdscr.addstr(row, column, fitted(text, available, chrome=data_is_chrome))
            except curses.error:
                pass
            if attr:
                stdscr.attroff(attr)
            if pair_attr:
                stdscr.attroff(pair_attr)

    def pair_number(self, fg: int, bg: int) -> tuple[int, int]:
        index = fg + (10 if bg >= 0 else 0)
        return (index, -1)

    def init_colors(self, stdscr: Any) -> None:  # pragma: no cover - curses specific
        if not curses.has_colors():
            return
        curses.start_color()
        curses.use_default_colors()
        for severity, (fg, attr) in SEVERITY_PAIR.items():
            index = self.pair_number(fg, attr)[0]
            if index < curses.COLOR_PAIRS:
                curses.init_pair(index, fg, -1)

    def progress(self, message: str) -> None:  # pragma: no cover - curses specific
        try:
            height, width = curses.initscr().getmaxyx()
            curses.initscr().addstr(height - 1, 0, safe(message)[: width - 1])
            curses.initscr().refresh()
        except Exception:
            pass

    def activate(self, stdscr: Any, kind: str) -> str:
        if kind == "act:__head":
            return "continue"
        if kind == "act:quit":
            return "quit"
        if kind == "act:lang":
            i18n.set_lang("en" if i18n.get_lang() == "pl" else "pl")
            return "continue"
        if kind == "act:reveal":
            i18n.set_reveal(not i18n.reveal())
            return "continue"
        if kind == "act:results":
            return "continue"
        if kind == "act:report":
            self.c.run_module("report", {"format": "md"})
            return "continue"
        if kind == "act:verify":
            self.c.run_module("verify", {"scope": "all"})
            return "continue"
        if kind.startswith("mod:"):
            spec = registry.by_id(kind[4:])
            if spec is None:
                return "continue"
            params = self.form(stdscr, spec)
            if params is None:
                return "continue"
            self.c.run_module(spec.id, params)
        return "continue"

    def form(self, stdscr: Any, spec) -> dict | None:
        """Simple modal form: number keys toggle, Enter runs with defaults."""
        params = spec.defaults()
        keys = list(params)
        cursor = 0
        while True:
            stdscr.erase()
            height, width = stdscr.getmaxyx()
            stdscr.attron(curses.A_BOLD)
            stdscr.addstr(0, 0, fitted(i18n.t(spec.title), width - 1))
            stdscr.attroff(curses.A_BOLD)
            stdscr.addstr(1, 0, fitted(i18n.t(spec.summary), width - 1))
            row = 3
            for index, key in enumerate(keys):
                param = spec.params[index]
                label = i18n.t(param.label) if param.label.startswith("param.") else param.label
                marker = ">" if index == cursor else " "
                text = f"{marker} {key} = {params[key]!r}   [{label}]"
                if index == cursor:
                    stdscr.attron(curses.A_REVERSE)
                stdscr.addstr(row, 2, safe(text)[: width - 3])
                if index == cursor:
                    stdscr.attroff(curses.A_REVERSE)
                row += 2
            stdscr.addstr(height - 2, 0, fitted(i18n.t("menu.hint.form"), width - 1))
            key = stdscr.getch()
            if key in (ord("q"), 27):
                return None
            if key in (curses.KEY_UP, ord("k")):
                cursor = (cursor - 1) % max(len(keys), 1)
            elif key in (curses.KEY_DOWN, ord("j")):
                cursor = (cursor + 1) % max(len(keys), 1)
            elif key in (ord("d"),):
                value = params[keys[cursor]]
                params[keys[cursor]] = (not value) if isinstance(value, bool) else ("" if value else "1")
            elif key in (ord("e"),):
                return self.edit_value(stdscr, spec, keys[cursor], params)
            elif key in (10, 13, curses.KEY_ENTER):
                return params
        return None

    def edit_value(self, stdscr: Any, spec, key: str, params: dict) -> dict:
        height, width = stdscr.getmaxyx()
        stdscr.erase()
        stdscr.addstr(0, 0, fitted(f"{key}  {i18n.t('menu.hint.edit')}", width - 1))
        label = i18n.t("menu.hint.current") + ": "
        stdscr.addstr(1, 0, fitted(label, width - 1))
        stdscr.addstr(1, text_mod.width(label), str(params[key])[: max(0, width - 1 - text_mod.width(label))])
        curses.echo()
        buffer = ""
        row = 3
        while True:
            stdscr.move(row, 0)
            stdscr.clrtoeol()
            # NOT `safe()`: the buffer is what the user typed, and for a path
            # parameter that is evidence — a file called `zażółć.txt` would be
            # transliterated to `zazolc.txt` and the tool would go looking for a
            # file that is not in the image.  The width guard stays, because
            # curses cannot draw a character at the last column.
            stdscr.addstr(row, 0, buffer[: width - 1])
            stdscr.refresh()
            key_pressed = stdscr.get_wch()
            if key_pressed in ("\n", "\r"):
                break
            if key_pressed == "\x1b":
                curses.noecho()
                return params
            if key_pressed in ("\b", "\x7f"):
                buffer = buffer[:-1]
                continue
            if key_pressed == "\x15":
                buffer = ""
                continue
            buffer += key_pressed
        curses.noecho()
        spec_param = next(p for p in spec.params if p.key == key)
        text = buffer.strip()
        if spec_param.kind == "int":
            try:
                params[key] = int(text)
            except ValueError:
                pass
        elif spec_param.kind == "bool":
            params[key] = text.lower() in ("t", "true", "y", "yes", "1", "tak")
        else:
            params[key] = text
        return params
