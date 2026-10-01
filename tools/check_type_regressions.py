#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Fail when the mypy error count in a package **rises**.

The interesting constraint on this repository is that it is 40% typed, and getting
from 62 errors to 0 has to survive every commit that arrives in between.  Making
``mypy forensic`` blocking today would mean either refusing to merge anything or
blocking on 62 errors nobody can fix in one sitting — so CI runs mypy
non-blocking, prints the number, and this script decides whether it moved.

Only a **rise** fails.  A fall is reported and is not an error, so the count can
keep falling without anybody having to edit this file on the way down; when it
reaches zero the baseline entries go to 0 and nothing here does any work any
more.

Per package rather than one total, because a total is easy to satisfy by accident:
deleting one annotation in a clean file and adding a worse one elsewhere keeps the
sum identical and trades a known place for an unknown one.

Usage::

    mypy forensic > /tmp/mypy.txt || true
    python tools/check_type_regressions.py /tmp/mypy.txt

or with no argument, run mypy itself.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

BASELINE = Path(__file__).with_name("mypy_baseline.json")
#: ``forensic/core/foo.py:123: error: ...`` — the shape mypy emits.
ERROR_LINE = re.compile(r"^(?P<file>[^:]+\.py):\d+: error:")


def load_baseline() -> dict[str, int]:
    if not BASELINE.exists():
        return {}
    return json.loads(BASELINE.read_text(encoding="utf-8"))


def counts_from(output: str) -> Counter[str]:
    """Errors per top-level package, plus a grand total under ``__total__``.

    A file is attributed to the directory it sits in, two levels down, so
    ``forensic/modules/offline/…`` is one bucket rather than thirty.
    """
    found: Counter[str] = Counter()
    for line in output.splitlines():
        match = ERROR_LINE.match(line)
        if not match:
            continue
        parts = Path(match.group("file")).parts
        if len(parts) >= 3:
            found[parts[1]] += 1
        else:
            found["(root)"] += 1
    found["__total__"] = sum(found.values())
    return found


def main(argv: list[str]) -> int:
    if argv:
        output = Path(argv[0]).read_text(encoding="utf-8", errors="replace")
    else:
        proc = subprocess.run(
            ["mypy", "forensic"], capture_output=True, text=True, check=False
        )
        output = proc.stdout + proc.stderr

    baseline = load_baseline()
    current = counts_from(output)

    if not baseline:
        print("brak tools/mypy_baseline.json — zapisuję stan wyjściowy")
        BASELINE.write_text(
            json.dumps({k: v for k, v in sorted(current.items())}, indent=2) + "\n",
            encoding="utf-8",
        )
        return 0

    grew = {k: current.get(k, 0) - baseline.get(k, 0) for k in set(baseline) | set(current)}
    worse = {k: delta for k, delta in sorted(grew.items()) if delta > 0}
    better = {k: delta for k, delta in sorted(grew.items()) if delta < 0}

    for key in sorted(set(baseline) | set(current)):
        was, now = baseline.get(key, 0), current.get(key, 0)
        mark = ""
        if key in worse:
            mark = f"  ← WZROŚŁO o {worse[key]}"
        elif key in better:
            mark = f"  (−{-better[key]})"
        print(f"  {key:20} {was:4} → {now:4}{mark}")

    if worse:
        print(
            "\nFAIL: liczba błędów mypy wzrosła. Spadać może, rosnąć nie.",
            file=sys.stderr,
        )
        return 1
    print("\nOK: liczba błędów mypy nie wzrosła.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
