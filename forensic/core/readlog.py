# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""The three answers to "did we read it?", and where they are kept.

A parser has three outcomes for every artifact it is pointed at, and they are not
variants of one answer:

``PRESENT``
    It was there and we read it.  This may mean "it was empty", which is a
    finding about the evidence rather than about the reading.

``ABSENT``
    It was not there.  A clean negative, and the only one of the three that lets
    an analyst conclude something.

``UNREADABLE``
    It was there and we could not read it.  Nothing may be concluded from it.

The third is the one that used to get lost, because the natural way to write the
handling is to catch the exception and return an empty result.  An empty result
is a *value*, so it flows on and is finally rendered as a count of zero, which is
indistinguishable from a genuinely empty database.  ``except sqlite3.Error:
return {}`` and ``return []`` are the shape of it.

:class:`ReadLog` is the alternative, and it is not a new idea: the filesystem
readers have carried ``walk_errors`` for several turns for exactly this reason —
a directory that could not be listed is missing evidence, not a smaller
filesystem.  ``walk_errors`` proved the shape and reached
:mod:`forensic.core.reporting`; this generalises it to every other reader so that
one artifact that failed cannot hide behind a whole module that returned zero.
"""

from __future__ import annotations

from typing import Any

PRESENT = "PRESENT"
ABSENT = "ABSENT"
UNREADABLE = "UNREADABLE"
#: A fourth word, and the only one of the four that is about the *image* rather
#: than about an artifact: the file ends before the filesystem inside it says it
#: should, so what is past the cut is unknown rather than empty.  It lives beside
#: the other three because it travels through the same reports, but it is not a
#: refinement of ``UNREADABLE`` — a whole image can be truncated while every
#: artifact inside it that was read is perfectly intact.
TRUNCATED = "TRUNCATED"


class ReadLog:
    """Failures met while reading evidence, kept instead of swallowed.

    Not an exception handler.  The handlers stay where they are — catching the
    specific error is correct and this does not replace it — but what they return
    is recorded here, so the caller can tell an empty result from a failed one.

    Bounded because it accumulates over a walk of a whole filesystem, where a
    corrupt directory subtree can produce thousands of identical failures and the
    report wants the first few, not all of them.  :attr:`total` keeps the real
    count so nothing is silently under-reported.
    """

    #: Entries kept.  Matches the shape ``walk_errors`` already uses.
    KEEP = 50

    def __init__(self) -> None:
        self._entries: list[dict[str, Any]] = []
        self._failed: set[str] = set()
        self._absent: set[str] = set()
        self._total = 0

    # -- recording ---------------------------------------------------------

    def unreadable(self, artifact: str, reason: str | BaseException, where: str = "") -> None:
        """Record that ``artifact`` was there and could not be read."""
        self._failed.add(artifact)
        self._total += 1
        if len(self._entries) < self.KEEP:
            self._entries.append(
                {
                    "artifact": artifact,
                    "status": UNREADABLE,
                    "why": _reason(reason),
                    "where": where,
                }
            )

    def absent(self, artifact: str, reason: str | BaseException = "") -> None:
        """Record that ``artifact`` was looked for and is not there."""
        self._absent.add(artifact)
        self._total += 1
        if len(self._entries) < self.KEEP:
            self._entries.append(
                {
                    "artifact": artifact,
                    "status": ABSENT,
                    "why": _reason(reason) if reason else "",
                    "where": "",
                }
            )

    # -- querying ----------------------------------------------------------

    def failed(self, artifact: str) -> bool:
        return artifact in self._failed

    def known_absent(self, artifact: str) -> bool:
        return artifact in self._absent

    def status(self, artifact: str) -> str:
        return status_for(artifact, self)

    @property
    def entries(self) -> list[dict[str, Any]]:
        return list(self._entries)

    @property
    def total(self) -> int:
        """How many were recorded, including the ones past :attr:`KEEP`."""
        return self._total

    @property
    def truncated(self) -> bool:
        """True when more happened than :attr:`entries` shows."""
        return self._total > len(self._entries)

    def __len__(self) -> int:
        return self._total

    def __bool__(self) -> bool:
        return self._total > 0

    # -- reporting ---------------------------------------------------------

    def summary(self, artifact: str = "") -> dict[str, Any]:
        """The block a report prints: how much was read, and what was not."""
        unreadable = artifact in self._failed if artifact else bool(self._failed)
        out: dict[str, Any] = {
            "read_errors": self._total,
            "read_error_detail": self._entries[:5],
            "read_errors_truncated": self.truncated,
            "complete": self._total == 0,
        }
        if artifact:
            out["status"] = self.status(artifact)
            out["unreadable"] = unreadable
        return out


def _reason(reason: str | BaseException) -> str:
    """One line, naming the exception type, for a human reading a report."""
    if isinstance(reason, BaseException):
        return f"{type(reason).__name__}: {reason}"
    return str(reason)


def merge_logs(*logs: ReadLog) -> ReadLog:
    """One log from several, for a module that reads through several helpers."""
    out = ReadLog()
    for log in logs:
        for entry in log.entries:
            if entry["status"] == UNREADABLE:
                out.unreadable(entry["artifact"], entry["why"], entry["where"])
            else:
                out.absent(entry["artifact"], entry["why"])
    return out


def status_for(artifact: str, log: ReadLog) -> str:
    """The one-word verdict for ``artifact``, given what the log recorded."""
    if log.failed(artifact):
        return UNREADABLE
    if log.known_absent(artifact):
        return ABSENT
    return PRESENT
