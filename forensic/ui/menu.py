# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Frontend 1: numbered and lettered menus, works over SSH and in any terminal.

Two screens and a help screen, and the shape of them is the point.

**Numbers for categories, letters for actions.**  The first version numbered
everything, 1 to 11, with the five actions indented two spaces further and
sharing the same sequence.  Nothing on the screen said which numbers were
categories and which were actions, so the fastest a new user could move was to
try each one.  Now the two kinds are in labelled blocks and use different keys:
categories are a small, stable set of digits; actions are letters, so
``v`` is verify from anywhere and cannot be confused with a category that happens
to be fifth this month.

**Counts in their own column.**  ``(11)`` glued to the end of a label reads as part
of the name and does not line up when one label is longer than another.  It is a
column now, right-aligned, and separated by a gap wide enough to scan.

**No language pairs inside a label.**  ``Weryfikacja (case) / Verify`` and
``Język / Language → pl`` were the two worst offenders: a Polish reader was shown
English, an English reader was shown Polish, and neither was told which was which.
The whole interface is one language at a time, switchable, and the menu says which
one is active in the status line above it.

**The help is a screen, not a shrug.**  Answering ``?`` used to print the word
"Pomoc" and re-prompt on the same line.  It now opens a screen with the keys, what
the blocks mean, and what the tool does not do.
"""

from __future__ import annotations

from collections.abc import Sequence

import os

from ..core import config as config_mod
from ..core import i18n, text
from ..core.export import color
from ..modules import registry
from . import render
from .base import (
    BACK,
    QUIT,
    ask,
    banner,
    box,
    clear,
    confirm,
    progress_done,
    progress_line,
    show_text,
    toggle_lang,
    toggle_reveal,
)

#: Below this the two-column layout stops being a layout, and the menu falls back
#: to one column with the counts on the labels.  Set from the longest label in
#: either language, so neither reader gets a cut name.
MIN_LABEL_COLUMNS = 20
#: Below this the two-column menu stops being two columns.  The frame, the key
#: column and the count column need 9 columns before the label gets any, and a
#: layout that cannot work should say so rather than render wrong: at 20 columns
#: the first version drew a frame two columns wider than the terminal.
MIN_MENU_COLUMNS = 40
#: Used when the terminal size cannot be read — a pipe, a cron job, a test.
FALLBACK_COLUMNS = 80


def terminal_columns(limit: int = 0) -> int:
    """How many columns to draw in.

    The first version of this menu was hardcoded to 76 and the frame around it to
    74, which is fine on a wide terminal and useless in a narrow one: every line
    soft-wraps at the terminal's own edge and the second column of a row lands
    under the first, so the two blocks that were supposed to be scannable side by
    side become a single wrapped column.  A layout that ignores the terminal is a
    layout for one terminal.

    ``limit`` caps the result, and a non-tty falls back to the historical width
    because a pipe has no width to honour and a report captured from one should
    still read.

    The floor of 20 is deliberate and should not be "fixed".  A terminal narrower
    than 20 columns gets a menu 20 columns wide and one soft-wrapped line, which
    is the lesser evil: the alternative is cutting every label to sixteen columns
    and a list nobody can scan.  Real terminals do not go there, and the frame is
    already dropped below :data:`MIN_MENU_COLUMNS`, so the damage is limited to a
    single wrapped line in a pane nobody uses.

    Checked by driving this through a pseudo-terminal at 140, 120, 100, 80, 72,
    64, 56, 48, 40, 32, 24 and 20 columns and asserting that no line exceeds
    the width at any of them.
    """
    if limit:
        return max(20, limit)
    try:
        if not os.isatty(1):
            return FALLBACK_COLUMNS
        return max(20, os.get_terminal_size().columns - 1)
    except (OSError, ValueError, AttributeError):
        return FALLBACK_COLUMNS


def fit_path(value: str, columns: int) -> str:
    """A path that fits ``columns``, keeping the end and admitting it was cut.

    A path is the one thing in this menu that must never be silently shortened:
    ``/path/to/redmi3_userdata_full_v2.img`` and
    ``/path/to/redmi3_userdata_full_v2`` are different arguments to the
    same tool, and the second one looks like the first.  When there is no room,
    the tail is the informative part anyway — it is the filename — and a leading
    ``...`` says the head is not shown.
    """
    if text.width(value) <= columns:
        return value
    if columns <= 4:
        return value[-columns:]
    return "..." + value[-(columns - 3):]


#: The actions, as ``(key, i18n key, optional hint key)``.  Declared once so the
#: menu, the help screen and the key handling cannot disagree about what exists.
ACTIONS: tuple[tuple[str, str, str, str], ...] = (
    # (key, internal name, label key, hint key) — the key and the name are kept
    # apart because the first version offered the letter ``l`` while the
    # dispatcher compared against ``lang``, and the language toggle simply never
    # fired.  One row, so the two cannot drift apart again.
    ("v", "verify", "menu.action.verify", "menu.action.verify.hint"),
    ("r", "report", "menu.action.report", ""),
    ("s", "results", "menu.action.results", ""),
    ("l", "lang", "menu.action.lang", ""),
    ("m", "reveal", "menu.action.reveal", ""),
    ("?", "help", "menu.action.help", ""),
    ("q", "quit", "menu.exit", ""),
)


class MenuUI:
    """Numbered-menu frontend delegating every decision to the controller."""

    name = "menu"

    #: Label column for the category and action blocks.  Sized to the longest
    #: label in either language, so the columns line up without truncation and a
    #: Polish reader and an English one see the same shape.
    LABEL_COLUMNS = 42
    COUNT_COLUMNS = 4

    def __init__(self, controller) -> None:
        self.c = controller

    # -- top level --------------------------------------------------------
    def run(self) -> int:
        while True:
            columns = terminal_columns()
            clear()
            # Below the minimum the frame is the part that cannot fit, so it goes
            # and the list stays.  A menu with no frame is a worse menu; a menu
            # with a frame wider than the terminal is not a menu.
            if columns >= MIN_MENU_COLUMNS:
                print(
                    banner(
                        self.header(),
                        color_enabled=self.c.color,
                        columns=columns - 2,
                    )
                )
            print(self.context(columns))
            print()
            choice = self.categories_menu(columns)
            if choice is QUIT:
                return 0
            if choice is BACK:
                continue
            if choice == "lang":
                toggle_lang()
                continue
            if choice == "reveal":
                toggle_reveal()
                continue
            if choice == "results":
                self.results_screen()
                continue
            if choice == "help":
                self.help_screen()
                continue
            if choice == "verify":
                self.c.run_module("verify", {"scope": "all"})
                continue
            if choice == "report":
                self.c.run_module("report", {"format": "md"})
                continue
            if isinstance(choice, str) and choice.startswith("cat:"):
                self.category_screen(choice[4:])

    def header(self) -> str:
        return f"{i18n.t('app.name')} — {i18n.t('app.tagline')}"

    def label_columns(
        self, columns: int, categories: Sequence[tuple[int, str, str, int]] = ()
    ) -> int:
        """Width of the label column, from the labels themselves.

        Derived rather than fixed, because a fixed 42 is right for the longest
        English action label and wrong for every Polish one shorter than that, and
        it steals columns from the counts on a narrow terminal for no reason.
        """
        labels = [text.width(text.ascii(label)) for _n, _k, label, _c in categories]
        for letter, _name, label_key, hint_key in ACTIONS:
            label = i18n.t(label_key)
            if hint_key:
                label = f"{label} — {i18n.t(hint_key)}"
            labels.append(text.width(text.ascii(label)) + (2 if hint_key else 0))
        wanted = max(labels) + 2
        # Whatever is not the label column goes to the state column, and the state
        # column is the part that disappears gracefully — "-> polski" is a
        # convenience, a module count is not.  So the floor is 20 only where there
        # is room for both, and it yields to the state below about 44 columns.
        # 9 columns are spoken for before the label: 2 indent, 1 key, 2 space,
        # and the 4-column count.  The floor yields below 48 columns, where the
        # state arrow is the part that can go.
        floor = min(MIN_LABEL_COLUMNS if columns >= 48 else 12, max(6, columns - 9))
        return max(floor, min(42, wanted, max(floor, columns - 9)))

    def context(self, columns: int = 0) -> str:
        """Image and work directory on their own lines, state on a third.

        Not for tidiness.  A real case pushes this past 200 columns, and every
        terminal then wraps it somewhere arbitrary — usually through the image
        path, which is the single field anybody opened the tool to read.  So the
        two paths get a line each and are never padded or cut, and the four small
        state fields share the line below, where overflow costs a wrap in a place
        where nothing important is.

        Padding is applied to the *label* only.  The first version padded label
        and value together, which truncated the work directory to
        ``/path/to/work/redmi3`` minus its tail — a path that looks
        valid and points nowhere.
        """
        rows = [
            (i18n.t("status.image"), ctx_path(self.c)),
            (i18n.t("status.work"), str(self.c.ctx.workdir)),
        ]
        state = [
            (i18n.t("status.lang"), i18n.get_lang()),
            (
                i18n.t("status.reveal"),
                i18n.t("status.revealed") if i18n.reveal() else i18n.t("status.masked"),
            ),
            (i18n.t("status.mount"), self._mount_state()),
        ]
        # Measured from the labels, not guessed.  A hard-coded 8 cut
        # "Katalog roboczy:" to "Katalog robo" on the Polish side and left an
        # English label with a column too wide for it.
        # Capped at a third of the width: below that the value column is the part
        # worth keeping, because a path is the reason the line exists and the
        # label is guessable from context.
        available = columns or terminal_columns()
        measured = max(text.width(text.ascii(f"{name}:")) for name, _v in rows) + 2
        # The path is the reason the line exists, so the label yields first: the
        # column is capped at a third of the width, and when even that leaves no
        # room the label is cut rather than the value.  At 24 columns
        # "Katalog roboczy:" is worth less than a tail of the work directory.
        column = min(measured, max(8, available // 3))
        value_columns = max(12, available - column)
        lines = [
            color(
                text.pad(text.ascii(f"{name}:"), column)
                + text.ascii(fit_path(value, value_columns)),
                "grey",
                self.c.color,
            )
            for name, value in rows
        ]
        if columns and columns < 62:
            # Too narrow for one line of four fields, so one per line.  A soft wrap
            # would put the third field under the first and the reader would pair
            # a label with the wrong value.
            lines.extend(
                color(
                    text.pad(text.ascii(f"{name}:"), column)
                    + text.ascii(fit_path(value, value_columns)),
                    "grey",
                    self.c.color,
                )
                for name, value in state
            )
        else:
            lines.append(
                color(
                    "   ".join(
                        f"{text.ascii(name)}: {text.ascii(value)}"
                        for name, value in state
                    ),
                    "grey",
                    self.c.color,
                )
            )
        return "\n".join(lines)

    def _mount_state(self) -> str:
        try:
            from ...core import imagemount

            info = imagemount.find_mount_for(str(self.c.ctx.image))
        except Exception:
            info = None
        if info is not None:
            return f"{i18n.t('status.mounted_ro')}: {info.mountpoint}"
        return i18n.t("status.not_mounted")

    # -- the two blocks ---------------------------------------------------
    def categories_menu(self, columns: int = 0):
        categories: list[tuple[int, str, str, int]] = []
        index = 1
        for key, label_key in config_mod.CATEGORIES:
            items = registry.in_category(key)
            if not items:
                continue
            categories.append((index, key, i18n.t(label_key), len(items)))
            index += 1
        total = sum(count for _n, _k, _l, count in categories)
        width = columns or terminal_columns()
        label_columns = self.label_columns(width, categories)

        out: list[str] = []
        out.append(
            color(
                text.pad(
                    text.ascii(
                        f"{i18n.t('menu.categories')}   {total} {i18n.t('menu.modules')}"
                    ),
                    max(20, width),
                ),
                "bold",
                self.c.color,
            ).rstrip()
        )
        for number, key, label, count in categories:
            out.append(
                color(text.ascii(f"  {number}"), "cyan", self.c.color)
                + "  "
                + text.pad(text.ascii(label), label_columns)
                + color(text.rpad(str(count), self.COUNT_COLUMNS), "grey", self.c.color)
            )
        out.append("")
        out.append(color(text.pad(text.ascii(i18n.t("menu.actions")), max(20, width)), "bold", self.c.color).rstrip())
        for letter, _name, label_key, hint_key in ACTIONS:
            # Cut to the column, not just padded to it: a 37-character label in a
            # 16-column slot has to lose its tail, and leaving it whole overflowed
            # the terminal by 16 columns, where the line soft-wrapped under the
            # block above and the menu stopped being a two-block list.
            name = text.pad(text.ascii(i18n.t(label_key)), label_columns)
            hint = i18n.t(hint_key) if hint_key else self._action_state(letter)
            key = color(text.ascii(f"  {letter}"), "cyan", self.c.color) + "  "
            # The hint goes only if the *whole* row fits, measured from this row's
            # own label and not from the column.  Measuring from the column let a
            # short label borrow space and the hint ran past the terminal edge,
            # where the terminal soft-wraps it under the block above.
            # Two chances, in order: first with the label padded to the column so
            # the states line up, then unpadded so a short label is not followed by
            # a block of spaces that pushes the state past the terminal edge.  The
            # earlier version measured the second case and padded anyway, which is
            # how "-> odsloniete" ended up one column over at 56.
            if hint and 5 + label_columns + 1 + text.width(text.ascii(hint)) <= width:
                row = key + name + color(" " + text.ascii(hint), "grey", self.c.color)
            elif hint and 5 + text.width(text.ascii(i18n.t(label_key))) + 1 + text.width(
                text.ascii(hint)
            ) <= width:
                row = key + text.ascii(i18n.t(label_key)) + color(
                    " " + text.ascii(hint), "grey", self.c.color
                )
            else:
                row = key + name
            out.append(row.rstrip())
        out.append("")
        out.append(
            color(
                text.pad(text.ascii(i18n.t("menu.footer")), max(20, width)), "grey", self.c.color
            ).rstrip()
        )
        print("\n".join(line.rstrip() for line in out))
        return self._resolve(self._read_choice(), categories)

    def _action_state(self, letter: str) -> str:
        """What the action would switch to, shown beside it.

        Showing the *destination* rather than the command is the difference between
        a toggle whose effect is guessable and one that is not: the old menu printed
        ``odsłonić sekrety → zamaskowane``, which says what the state is now in
        words a newcomer has to invert, and printed nothing at all for the language.
        """
        if letter == "l":
            return f"-> {i18n.t('lang.other')}"
        if letter == "m":
            return (
                f"-> {i18n.t('status.masked')}"
                if i18n.reveal()
                else f"-> {i18n.t('status.revealed')}"
            )
        return ""

    def _read_choice(self) -> str:
        answer = ask(
            f"  {i18n.t('menu.choose')}",
            default="",
            color_enabled=self.c.color,
            on_help=self.help_screen,
        )
        if answer in (QUIT, BACK):
            return QUIT
        return str(answer).strip()

    def _resolve(self, answer, categories: Sequence[tuple[int, str, str, int]]):
        if answer is QUIT:
            return QUIT
        low = answer.lower()
        for letter, name, _label, _hint in ACTIONS:
            if letter.lower() == low:
                return name
        mapping = {str(number): key for number, key, _label, _count in categories}
        key = mapping.get(answer)
        if key is None:
            return BACK
        return f"cat:{key}"

    # -- help -------------------------------------------------------------
    def help_screen(self) -> None:
        clear()
        body = [
            f"{i18n.t('menu.help.keys')}",
            i18n.t("menu.help.keys.body"),
            "",
            f"{i18n.t('menu.help.notes')}",
            i18n.t("menu.help.notes.body"),
        ]
        print(
            box(
                i18n.t("menu.help.title"),
                body,
                self.c.color,
                columns=max(30, terminal_columns() - 2),
            )
        )
        print()
        ask(f"  {i18n.t('common.back')}", default="", color_enabled=self.c.color)

    # -- one category -----------------------------------------------------
    def category_screen(self, category: str) -> None:
        """List the modules of one category, then run the chosen one."""
        while True:
            clear()
            answer = self.module_list_screen(category)
            if answer is QUIT or answer is BACK:
                return
            if answer in ("verify", "report", "results"):
                if answer == "verify":
                    self.c.run_module("verify", {"scope": "all"})
                elif answer == "report":
                    self.c.run_module("report", {"format": "md"})
                else:
                    self.results_screen()
                continue
            if answer == "lang":
                toggle_lang()
                continue
            if answer == "reveal":
                toggle_reveal()
                continue
            self.module_screen(answer)

    def module_list_screen(self, category: str):
        specs = registry.in_category(category)
        label_key = dict(config_mod.CATEGORIES).get(category, category)
        print(color(f"  {text.ascii(i18n.t(label_key))}", "bold", self.c.color))
        print(render.specs_table(specs, self.c.color))
        print()
        print()
        print(color(f"  {i18n.t('common.back')}: b      {i18n.t('common.quit')}: q", "grey", self.c.color))
        answer = ask(f"  {i18n.t('menu.choose_module')}", default="", color_enabled=self.c.color)
        if answer is QUIT:
            return QUIT
        if answer is BACK or str(answer).strip().lower() in ("b", "back", "0", ""):
            return BACK
        low = str(answer).strip().lower()
        if low in ("q", "quit"):
            return QUIT
        if low in ("l", "lang"):
            toggle_lang()
            return BACK
        if low in ("m", "reveal"):
            toggle_reveal()
            return BACK
        for letter, name, _label, _hint in ACTIONS:
            if letter.lower() == low and name not in ("quit", "help"):
                return name
        try:
            index = int(answer)
        except ValueError:
            return BACK
        if 1 <= index <= len(specs):
            return specs[index - 1].id
        return BACK

    # -- one module -------------------------------------------------------
    def module_screen(self, module_id: str) -> None:
        spec = registry.by_id(module_id)
        if spec is None:
            return
        while True:
            clear()
            print(
                box(
                    i18n.t(spec.title),
                    [i18n.t(spec.summary)],
                    self.c.color,
                    columns=max(30, terminal_columns() - 2),
                )
            )
            params = spec.defaults()
            if spec.params:
                print(
                    color(f"  {i18n.t('menu.params')}", "grey", self.c.color)
                )
            for param in spec.params:
                label = i18n.t(param.label) if param.label.startswith("param.") else param.label
                value = ask(
                    f"  {label}",
                    default=param.default,
                    kind=param.kind,
                    choices=param.choices,
                    color_enabled=self.c.color,
                )
                if value is QUIT:
                    return
                if value is BACK:
                    return
                params[param.key] = value
            print()
            if spec.needs_sudo:
                print(color(f"  ({i18n.t('msg.mount_needs_sudo')})", "grey", self.c.color))
            if not confirm(f"  {i18n.t('common.run')}? [{i18n.t('common.yes')}]", True, self.c.color):
                return
            self.c.set_progress(self.progress)
            result = self.c.run_module(module_id, params)
            self.c.set_progress(None)
            if result is None:
                return
            render.print_result(result, self.c.ctx.masker, self.c.color)
            print()
            answer = ask(f"  {i18n.t('common.continue')}", default="", color_enabled=self.c.color)
            if answer in (QUIT, BACK, "q", "b", ""):
                return

    def results_screen(self) -> None:
        clear()
        print(
            box(
                i18n.t("menu.results.title"),
                [],
                self.c.color,
                columns=max(30, terminal_columns() - 2),
            )
        )
        if not self.c.ctx.results:
            print(color(f"  ({i18n.t('common.none')})", "grey", self.c.color))
        else:
            show_text(render.results_overview(self.c.ctx.results, self.c.color), self.c.color)
        for result in self.c.ctx.results:
            show_text(
                render.result_text(result, self.c.ctx.masker, self.c.color), self.c.color
            )
        print()
        ask(f"  {i18n.t('common.back')}", default="", color_enabled=self.c.color)

    # -- progress ---------------------------------------------------------
    def progress(self, message: str) -> None:
        progress_line(text.ascii(message), self.c.color)

    def progress_done(self, message: str = "") -> None:
        progress_done(text.ascii(message), self.c.color)


def ctx_path(controller) -> str:
    """The image path, or a note that there is none.

    A case with no image yet is a state the menu has to survive: every module needs
    one, so the answer is an instruction rather than an error.
    """
    path = getattr(controller.ctx, "image", None)
    if path is None:
        return i18n.t("menu.no_image")
    return str(path)
