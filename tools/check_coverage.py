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

Measured 2026-10-01 with 202 tests, branch coverage:

==================  ======  ===============================================
part                pokrycie  what it means
==================  ======  ===============================================
``core/f2fs.py``      81%   the healthiest reader in the project
``core/ext4.py``      69%   the reader most of the evidence goes through
``core/erofs.py``     68%   EROFS, used by ``image_info`` and the self-test
``core/appdata.py``    49%   Android application evidence — see below
**project**          **37,69%**  the total, which is the least interesting number here
``ui/curses_ui.py``    0%   needs a terminal this harness has not got
==================  ======  ===============================================

``core/appdata.py`` was at **13%** and was the largest real hole in the project:
accounts, Chromium databases, Messenger preferences, WhatsApp stores, shared-prefs
XML and protobuf blobs, all read by the module with the most forensic surface and
the least automated coverage.  It was exercised by hand and by ``verify`` against
the reference image, and barely by pytest.

It moved to 49% because :mod:`tests.appdata_fixtures` builds **real files** on
the readers' own schemas — no image, no 27 GB download, a few milliseconds each —
and ``tests/test_appdata_formats.py`` and ``tests/test_appdata_sqlite.py`` point
the readers at them.  What that bought is not line coverage so much as three
things that used to be untested and are the ones that produce wrong conclusions
about a person: an uncatalogued WhatsApp type code being counted rather than
dropped, a missing table staying distinguishable from an empty one, and a database
that will not open never being reported as one with nothing in it.

Still uncovered in ``appdata``, and the next candidates: ``whatsapp_axolotl``
(Signal sessions and sender keys), ``messenger_msys`` (the E2EE identity table),
``wifi_settings`` and ``wpa_supplicant``, ``network_stats``, and the protobuf
helpers behind ``whatsapp_identity``.  Each needs its own fixture, and each one
is a schema to be got right rather than a function to be exercised.

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
PARSER_FLOORS = {
    "forensic/core/ext4.py": 60.0,
    "forensic/core/f2fs.py": 70.0,
    "forensic/core/erofs.py": 55.0,
}

#: The Android application readers.  Separate from the parsers because the
#: reason for a floor is different: the parsers' wrong answers are a wrong tree, and
#: these readers' wrong answers are a wrong statement about a **person** — that an
#: account did not exist, that a conversation had no messages, that a database
#: which could not be read held nothing.
#:
#: 13% when this was written, and that was the largest real hole in the project.
#: Building ``tests/appdata_fixtures.py`` — real files on the readers' own
#: schemas, no image needed — took it to 49%.  The floor sits below that so the
#: next reader of this file sees how far it moved and what is still uncovered.
APPLICATION_FLOORS = {
    "forensic/core/appdata.py": 45.0,
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