#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Coverage floors: one for the project, one for each filesystem reader.

A single project-wide number is satisfied by accident.  One well-tested module
lifts a badly-tested one and the total never moves, which is how a reader that is
never exercised sits at zero for a year behind a green gate.  So the floors here
are **per file**, and only for files that earn one: the three filesystem readers,
whose bugs become wrong conclusions about a device rather than a wrong line of
output.  Everything else is left to the project-wide floor.

Branch coverage, for the same reason the project-wide gate uses it: the defects
this repository has actually had were untaken or wrongly-taken branches.  A short
read that was zero-filled instead of raising; an ``if v`` filter that excluded
nothing because ``-1`` is truthy; a ``get(key, 0)`` whose default did the
reporting.  None of those reduces the statement count at all.

This lives in ``tools/`` rather than in ``tests/`` on purpose.  As test files the
floors read 0% on any partial run — ``pytest tests/test_coverage_floor.py``
imports the parsers without executing them — and a check that fails whenever it
is run on its own is a check that gets skipped.  A gate belongs next to the job
that has the whole suite in front of it.

Measured 2026-10-01 with 428 tests, branch coverage:

==================  ======  ===============================================
part                pokrycie  what it means
==================  ======  ===============================================
``core/appdata.py``    96%   Android application evidence
``core/f2fs.py``        85%   a modern `/data`
``core/ext4.py``        69%   the reader most of the evidence goes through
``core/erofs.py``      86%   EROFS — Android 10 and later
**project**          **41,68%**  the total, the least interesting number here
``ui/curses_ui.py``    0%   needs a terminal this harness has not got
==================  ======  ===============================================

``core/appdata.py`` was at **13%** and was the largest real hole in the project:
accounts, Chromium databases, Messenger preferences, WhatsApp stores, Wi-Fi keys,
Signal and Messenger E2EE identity state, Play Store install logs, MIUI usage
history, shared-prefs XML and protobuf blobs — all read by the module with the most
forensic surface and the least automated coverage.  It was exercised by hand and
by ``verify`` against the reference image, and barely by pytest.

It is now 96%, over five passes, because :mod:`tests.appdata_fixtures` builds
**real files** on the readers' own schemas — no image, no 27 GB download, a few
milliseconds each — and five test modules point the readers at them.  What that
bought is not line coverage so much as the things that produce wrong conclusions
about a person:

* an uncatalogued WhatsApp type code counted rather than dropped, and the two
  Android columns' numberings kept apart;
* a missing table (``-1``) distinguishable from an empty one (``0``), both of
  which appear in the same ``counts`` dict;
* a database that will not open never reported as one with nothing in it;
* a schema with no ``trusted`` column saying so instead of reporting zero trusted
  identities from a field that is not there;
* Wi-Fi PSKs read with the quotes the file format left on them, and an open
  network distinguished from a lost key;
* the P2P store's metadata tables excluded, so an empty store reads as empty;
* a sender name recovered from the snippet index when the JSON join has nothing,
  and ``named_by`` saying which source supplied it;
* a composed Jabber ID marked **derived**, so a rule about Polish numbers is not
  read as an identifier that came out of the file;
* a token in an unnamed field kept but flagged as noise, so a push payload is not
  reported as an access token.

Three limitations the tests now pin rather than leave to be discovered:

* the e164 candidate is selected with a hardcoded ``startswith("48")`` — the
  Polish country code, matching the reference device.  On any other country's
  number the reader reports the digits and stops, which is arguably right (a
  country code derived from a person's number is an inference, and a silent one
  is worse than none) but leaves the output indistinguishable from "the file held
  no numbers".
* a lean ``appstate`` schema is an error naming the missing column, and it leaves
  ``rows`` at 1 while ``apps`` is empty — both numbers true, and a reader who sees
  only the first believes the install list was read.
* ``found`` is redundant when a package is given, because the filter is applied
  inside ``_appstate_rows`` and ``found`` filters the already-narrowed list again.

The remaining 4% of ``appdata`` — 38 statements and 14 partial branches — is
concentrated in ``_whatsapp_type_profile`` (9: the disagreement path when a code's
observed MIME falls outside its declared family, and the SQLite error arms), plus
one or two defensive lines each in the protobuf walkers, ``shared_prefs``' XML
error paths and several readers' ``except`` arms.  Every one of them is a branch
behind an input this project's fixtures do not produce: a corrupted MIME join, an
XML document that fails in a particular place, a count that raises on a schema the
real databases do not have.

That is where this stopped, and the reason is worth stating: past this point the
tests stop describing evidence and start describing defensive code.  A fixture
built to reach one ``except`` arm asserts that the arm does not raise, which is
close to what the arm is for and not what the module is.

Usage::

    python -m pytest tests/ -q --cov --cov-report=json:.coverage.json
    python tools/check_coverage.py .coverage.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

#: Filesystem readers, and their branch coverage floors.
#:
#: Floors rather than exact numbers: a floor fails on a **drop**, which is the
#: point, and does not have to be edited every time the numbers go up.
#:
#: Two of these floors were lying the same way.  ``f2fs.py`` sat at 81% with a
#: 70% floor and ``erofs.py`` at 68% with a 55% one, and **every line of both**
#: came from ``ext4_selftest`` — a module the analyst runs by hand.  ``pytest
#: tests/`` looked at either reader exactly never, while the report ranked them
#: among the best-tested in the project.  ``tests/test_erofs.py`` and
#: ``tests/test_f2fs.py`` build their images with the real tools and compare
#: against ``dump.erofs`` and ``dump.f2fs``, so the numbers now describe a run
#: that happens on every push.
#:
#: The EROFS floor is the one that was worst.  ``erofs.py`` sat at 68% — above a
#: 55% floor — while ``pytest tests/`` looked at it **exactly never**: every line
#: of that coverage came from ``ext4_selftest``, a module the analyst runs by
#: hand.  It was the fourth-best-tested reader in the report and the third-worst
#: under CI.  ``tests/test_erofs.py`` builds the images with ``mkfs.erofs`` and
#: compares against ``dump.erofs``, so the number now describes a run that
#: happens.
PARSER_FLOORS = {
    "forensic/core/ext4.py": 60.0,
    "forensic/core/f2fs.py": 78.0,
    "forensic/core/erofs.py": 80.0,
}

#: The Android application readers.  Separate from the parsers because the
#: reason for a floor is different: the parsers' wrong answers are a wrong tree, and
#: these readers' wrong answers are a wrong statement about a **person** — that an
#: account did not exist, that a conversation had no messages, that a database
#: which could not be read held nothing.
#:
#: 13% when this was written, and that was the largest real hole in the project.
#: Building ``tests/appdata_fixtures.py`` — real files on the readers' own
#: schemas, no image needed — took it to 68% over two passes.  The floor sits
#: below that so the next reader of this file sees how far it moved and what is
#: still uncovered.
APPLICATION_FLOORS = {
    "forensic/core/appdata.py": 90.0,
}

#: Project-wide floor.  Kept equal to ``--cov-fail-under`` in the workflow; the
#: test at the bottom checks that the two files still agree.
TOTAL_FLOOR = 35.0


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: check_coverage.py <coverage.json>", file=sys.stderr)
        return 2
    report = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
    by_file = {
        name: float(entry["summary"]["percent_covered"])
        for name, entry in report.get("files", {}).items()
    }
    total = float(report.get("totals", {}).get("percent_covered", 0.0))
    if not by_file:
        print("brak danych w raporcie pokrycia — uruchom pytest z --cov", file=sys.stderr)
        return 1

    problems: list[str] = []
    print(f"  {'całość':32} {total:6.2f}%  (podłoga {TOTAL_FLOOR:.0f}%)")
    if total < TOTAL_FLOOR:
        problems.append(f"pokrycie całego pakietu {total:.2f}% < {TOTAL_FLOOR}%")

    all_floors = {**PARSER_FLOORS, **APPLICATION_FLOORS}
    for path, floor in sorted(all_floors.items()):
        # The reason a reader's wrong answer matters is not the same for both
        # groups, and saying "device" for the application readers would
        # understate what a wrong account list is.
        stakes = (
            "błędna odpowiedź staje się błędnym wnioskiem o urządzeniu"
            if path in PARSER_FLOORS
            else "błędna odpowiedź staje się błędnym wnioskiem o człowieku"
        )
        pct = by_file.get(path)
        if pct is None:
            problems.append(f"{path}: brak pomiaru — nic go nie zaimportowało")
            print(f"  {path:32} {'—':>7}  (podłoga {floor:.0f}%)")
            continue
        mark = "  ← PONIŻEJ PODŁOGI" if pct < floor else ""
        print(f"  {path:32} {pct:6.2f}%  (podłoga {floor:.0f}%){mark}")
        if pct < floor:
            problems.append(
                f"{path}: {pct:.2f}% poniżej podłogi {floor:.0f}% — czytnik, którego "
                f"{stakes}, nie może tracić pokrycia"
            )

    # The two files that hold the floors must not drift apart.  Cheap, and it is
    # the failure mode of a duplicated constant: both files say 35, one of them
    # gets edited, and CI stops enforcing what this tool says.
    workflow = Path(__file__).with_name("..").parent / ".github" / "workflows" / "ci.yml"
    if workflow.exists():
        text = workflow.read_text(encoding="utf-8")
        if f"--cov-fail-under={int(TOTAL_FLOOR)}" not in text:
            problems.append(
                f"ci.yml nie ustawia --cov-fail-under={int(TOTAL_FLOOR)}; "
                f"ta podłoga i bramka w CI rozjeżdżają się"
            )

    if problems:
        print("\nFAIL:", file=sys.stderr)
        for line in problems:
            print(f"  - {line}", file=sys.stderr)
        return 1
    print("\nOK: pokrycie całego pakietu i czytników powyżej podłóg.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))