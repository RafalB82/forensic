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

Measured 2026-10-01 with 143 tests:

==================  ======  ===============================================
part                pokrycie  what it means
==================  ======  ===============================================
``core/f2fs.py``      81%   the healthiest reader in the project
``core/ext4.py``      69%   the reader most of the evidence goes through
``core/erofs.py``     68%   EROFS, used by ``image_info`` and the self-test
``ui/curses_ui.py``    0%   needs a terminal this harness has not got
``core/appdata.py``    13%   **the largest real gap — see below**
==================  ======  ===============================================

The 13% is worth saying out loud.  :mod:`forensic.core.appdata` is where the
Android application evidence is read — accounts, Chromium databases, Messenger
preferences, WhatsApp stores, shared-prefs XML, protobuf blobs — and it is the
module with the most forensic surface in the project and the least automated
coverage.  It is exercised in practice by ``verify`` against the reference image,
by hand, and by ``ext4_selftest`` for F2FS; it is exercised here by about a
thirteenth.

That is not a call to write 700 tests in one go.  It is a statement of which way
to go next: a ``tests/test_appdata.py`` building real databases on the fly, in
the style of ``tests/test_metadata_csum.py``, would move the number that matters
more than any other in this repository — because ``appdata`` is where a wrong
answer turns into a wrong conclusion about a person.

Usage::

    python -m pytest tests/ -q --cov --cov-report=json:.coverage.json
    python tools/check_coverage.py .coverage.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

#: File -> branch coverage floor.  Only the filesystem readers.
PARSER_FLOORS = {
    "forensic/core/ext4.py": 60.0,
    "forensic/core/f2fs.py": 70.0,
    "forensic/core/erofs.py": 55.0,
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

    for path, floor in sorted(PARSER_FLOORS.items()):
        pct = by_file.get(path)
        if pct is None:
            problems.append(f"{path}: brak pomiaru — nic go nie zaimportowało")
            print(f"  {path:32} {'—':>7}  (podłoga {floor:.0f}%)")
            continue
        mark = "  ← PONIŻEJ PODŁOGI" if pct < floor else ""
        print(f"  {path:32} {pct:6.2f}%  (podłoga {floor:.0f}%){mark}")
        if pct < floor:
            problems.append(
                f"{path}: {pct:.2f}% poniżej podłogi {floor:.0f}% — reader, którego "
                f"błędna odpowiedź staje się błędnym wnioskiem o urządzeniu, nie może "
                f"tracić pokrycia"
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