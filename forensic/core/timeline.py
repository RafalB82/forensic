# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""One vocabulary for events on a timeline.

Sources disagree about what a timestamp is: ext4 stores seconds, Chromium
stores microseconds since 1601, Messenger mixes seconds and milliseconds inside
one JSON document, and some values are strings.  A timeline that silently
normalises those differences produces plausible but wrong chronology, so every
event carries the unit that was *assumed*, and :func:`epoch_seconds` is the one
place where the guess is made.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import Any
from collections.abc import Iterable, Sequence

SECONDS = 1_000_000_000
MS = 1_000
US = 1

KIND_FILE = "file_write"
KIND_CRASH = "crash"
KIND_LOGIN = "login"
KIND_LOGOUT = "logout"
KIND_TOKEN = "token"
KIND_CHECKIN = "checkin"
KIND_PACKAGE = "package_use"
KIND_LOCK = "lock"
KIND_NET = "net"
KIND_WIFI = "wifi"
KIND_OTHER = "other"

EPOCH_1980 = 315532800
EPOCH_2000 = 946684800


def epoch_seconds(value: Any) -> dict[str, Any]:
    """Convert a timestamp of unknown unit to seconds, reporting the guess.

    The cut-offs are the ones Android itself implies: below 1e11 a value cannot
    be a millisecond stamp of this century, below 1e14 it cannot be a
    millisecond stamp at all, so anything larger is microseconds.  ISO strings
    (what :meth:`Ext4.stat` returns) are parsed as themselves.
    """
    if value is None or value == "":
        return {"value": None, "unix": 0, "unit": "", "ok": False}
    if isinstance(value, _dt.datetime):
        return {
            "value": value.isoformat(),
            "unix": int(value.timestamp()),
            "unit": "dt",
            "ok": True,
        }
    if isinstance(value, str) and value[:4].isdigit() and value[4] in "-/: ":
        return _iso_seconds(value)
    try:
        number = float(value)
    except (TypeError, ValueError):
        return {"value": value, "unix": 0, "unit": "", "ok": False}
    if number <= 0:
        return {"value": value, "unix": int(number), "unit": "s", "ok": number != 0}
    if number < 1e11:
        unit, seconds = "s", number
    elif number < 1e14:
        unit, seconds = "ms", number / MS
    else:
        unit, seconds = "us", number / (MS * MS)
    return {"value": value, "unix": int(seconds), "unit": unit, "ok": True}


def _iso_seconds(text: str) -> dict[str, Any]:
    cleaned = text.strip().replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            stamp = (
                _dt.datetime.fromisoformat(cleaned)
                if fmt is None
                else _dt.datetime.strptime(text.strip().rstrip("Z"), fmt)
            )
        except ValueError:
            continue
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=_dt.timezone.utc)
        return {"value": text, "unix": int(stamp.timestamp()), "unit": "iso", "ok": True}
    return {"value": text, "unix": 0, "unit": "", "ok": False}


def utc(value: int | None) -> str:
    if not value:
        return ""
    try:
        return (
            _dt.datetime.fromtimestamp(value, _dt.timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
    except (OSError, OverflowError, ValueError):
        return ""


def utc_ms(millis: int | None) -> str:
    return utc(int(millis // 1000)) if millis else ""


def local_warsaw(value: int | None) -> str:
    """Europe/Warsaw without a tz database: the offset is fixed per date."""
    if not value:
        return ""
    try:
        stamp = _dt.datetime.fromtimestamp(value, _dt.timezone.utc)
    except (OSError, OverflowError, ValueError):
        return ""
    offset = 2 if _is_dst(stamp) else 1
    return stamp.astimezone(_dt.timezone(_dt.timedelta(hours=offset))).strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def _is_dst(stamp: _dt.datetime) -> bool:
    """EU summer time: last Sunday of March 01:00 UTC → last Sunday of October."""
    year = stamp.year
    march = _last_sunday(year, 3)
    october = _last_sunday(year, 10)
    start = _dt.datetime(year, 3, march, 1, tzinfo=_dt.timezone.utc)
    end = _dt.datetime(year, 10, october, 1, tzinfo=_dt.timezone.utc)
    return start <= stamp < end


def _last_sunday(year: int, month: int) -> int:
    day = 31 if month in (3, 5, 7, 8, 10, 12) else 30
    while True:
        candidate = _dt.date(year, month, day)
        if candidate.weekday() == 6:
            return day
        day -= 1


@dataclass
class Event:
    """One dated occurrence, with the evidence that dates it."""

    unix: int
    source: str
    kind: str = KIND_OTHER
    detail: str = ""
    unit: str = "s"
    value: Any = None
    package: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def utc(self) -> str:
        return utc(self.unix)

    @property
    def local(self) -> str:
        return local_warsaw(self.unix)

    def as_dict(self) -> dict[str, Any]:
        return {
            "utc": self.utc,
            "local_warsaw": self.local,
            "unix": self.unix,
            "unit": self.unit,
            "kind": self.kind,
            "source": self.source,
            "package": self.package,
            "detail": self.detail,
            "value": self.value,
            "extra": self.extra,
        }

    def row(self) -> list:
        return [self.utc, self.local, self.kind, self.source, self.package, self.detail]


#: ``fls`` type letters, as they appear in a body file's mode column.
MACTIME_TYPES = {
    "reg": "r",
    "dir": "d",
    "lnk": "l",
    "sock": "s",
    "fifo": "p",
    "blk": "b",
    "chr": "c",
}


def mactime_mode(mode: int) -> str:
    """Render an inode mode the way a body file wants it: ``d/drwxrwx---``.

    TSK writes the type letter, a slash, and then **the full ten-character mode
    including the type again** — so the letter appears twice, ``d/drwxrwx---``
    rather than ``d/rwxrwx---``.  Dropping the second one produces a file that
    ``mactime`` still accepts and every other body-file parser misreads, which
    is the worst kind of interoperability bug: no error, wrong answer.
    """
    import stat as _stat

    kind = _stat.S_IFMT(mode)
    letter = {
        _stat.S_IFREG: "r",
        _stat.S_IFDIR: "d",
        _stat.S_IFLNK: "l",
        _stat.S_IFSOCK: "s",
        _stat.S_IFIFO: "p",
        _stat.S_IFBLK: "b",
        _stat.S_IFCHR: "c",
    }.get(kind, "-")
    # TSK repeats the type letter inside the permission string — ``r/rrw-r--r--``
    # — and the repeat is *its* table, not ``stat``'s.  For a socket the two
    # disagree: ``stat`` writes ``s`` and TSK writes ``h``, which is its marker
    # for a type it has no dedicated rendering for.  That single character is
    # the only difference on 1 002 inodes of the reference image, and it is a
    # field any body-file reader would take at face value.
    inner = "h" if kind == _stat.S_IFSOCK else letter
    return f"{letter}/{inner}{_stat.filemode(mode)[1:]}"


def body_line(
    path: str,
    inode: int,
    mode: int,
    uid: int,
    gid: int,
    size: int,
    atime: int,
    mtime: int,
    ctime: int,
    crtime: int,
    md5: str = "0",
) -> str:
    """One body-file record.

    The field order and the timestamp format were both established by feeding
    candidate lines to ``mactime`` and reading what it complained about, not
    from a description of the format, and both differ from the obvious guess:

    * the **name is the second field**, not the last;
    * the four times are **seconds since the epoch**, not a formatted date —
      ``mactime`` rejects a date with "isn't numeric in numeric lt";
    * the mode column is ``type/permissions`` as one field;
    * a name containing ``|`` is fine, because ``mactime`` splits only as many
      times as the format has fields and takes the rest of the line as the name.
      A name containing a newline is not fine, and is rejected here rather than
      silently corrupting the file.
    """
    if "\n" in path or "\r" in path:
        raise ValueError(f"nazwa pliku zawiera znak końca wiersza: {path!r}")
    return "|".join(
        [
            md5 or "0",
            path,
            str(int(inode)),
            mactime_mode(mode),
            str(int(uid)),
            str(int(gid)),
            str(int(size)),
            str(int(atime)),
            str(int(mtime)),
            str(int(ctime)),
            str(int(crtime)),
        ]
    )


def body_file(lines: list[str], comment: str = "") -> str:
    """Assemble a body file.  A leading ``#`` comment is ignored by ``mactime``."""
    head = f"# {comment}\n" if comment else ""
    return head + "".join(line + "\n" for line in lines)


def make_event(
    value: Any,
    source: str,
    kind: str = KIND_OTHER,
    detail: str = "",
    package: str = "",
    raw: Any = None,
    extra: dict | None = None,
) -> Event | None:
    """Build an event from a timestamp of unknown unit; ``None`` when unusable."""
    stamp = epoch_seconds(value)
    if not stamp["unix"]:
        return None
    return Event(
        unix=stamp["unix"],
        source=source,
        kind=kind,
        detail=detail,
        unit=stamp["unit"],
        value=raw if raw is not None else value,
        package=package,
        extra=dict(extra or {}),
    )


@dataclass
class Timeline:
    """An ordered set of events plus the few derived views a report needs."""

    events: list[Event] = field(default_factory=list)
    label: str = ""

    def add(self, event: Event | None) -> Timeline:
        if event is not None:
            self.events.append(event)
        return self

    def extend(self, other: Timeline) -> Timeline:
        self.events.extend(other.events)
        return self

    def sorted(self) -> list[Event]:
        return sorted(self.events, key=lambda item: (item.unix, item.source))

    def dedupe(self, window: int = 0) -> Timeline:
        """Drop events that repeat the same source and detail.

        ``window`` merges neighbours of the same kind within that many seconds,
        which is how a directory full of files written by one boot step is turned
        back into a single event.
        """
        kept: list[Event] = []
        for event in self.sorted():
            if kept:
                last = kept[-1]
                same = last.source == event.source and last.detail == event.detail
                close = not window or (event.unix - last.unix) <= window
                if same and close:
                    if event.unix > last.unix:
                        last.unix = event.unix
                    continue
            kept.append(event)
        return Timeline(events=kept, label=self.label)

    @property
    def count(self) -> int:
        return len(self.events)

    @property
    def first(self) -> Event | None:
        ordered = self.sorted()
        return ordered[0] if ordered else None

    @property
    def last(self) -> Event | None:
        ordered = self.sorted()
        return ordered[-1] if ordered else None

    def window(self) -> dict[str, Any]:
        ordered = self.sorted()
        if not ordered:
            return {
                "count": 0,
                "first_utc": "",
                "last_utc": "",
                "span_seconds": 0,
                "span_human": "",
            }
        span = ordered[-1].unix - ordered[0].unix
        return {
            "count": len(ordered),
            "first_utc": ordered[0].utc,
            "last_utc": ordered[-1].utc,
            "first_local": ordered[0].local,
            "last_local": ordered[-1].local,
            "span_seconds": span,
            "span_human": span_human(span),
        }

    def by_kind(self) -> dict[str, int]:
        return _counter(event.kind for event in self.events)

    def by_source(self) -> dict[str, int]:
        return _counter(event.source for event in self.events)

    def by_day(self) -> dict[str, int]:
        return _counter(event.utc[:10] for event in self.events if event.utc)

    def by_hour(self) -> dict[str, int]:
        return _counter(event.utc[:13] for event in self.events if event.utc)

    def latest(self, kind: str = "", source: str = "") -> Event | None:
        candidates = [
            event
            for event in self.events
            if (not kind or event.kind == kind) and (not source or event.source == source)
        ]
        ordered = sorted(candidates, key=lambda item: item.unix)
        return ordered[-1] if ordered else None

    def rows(self, limit: int = 0) -> list[list]:
        ordered = self.sorted()
        if limit:
            ordered = ordered[-limit:]
        return [event.row() for event in ordered]

    def as_dict(self, limit: int = 0) -> dict[str, Any]:
        # The events, not rows(): rows() yields the six-column body-file row and
        # calling as_dict() on that list raised AttributeError.
        ordered = self.sorted()
        if limit:
            ordered = ordered[-limit:]
        return {
            "label": self.label,
            **self.window(),
            "by_kind": self.by_kind(),
            "by_source": self.by_source(),
            "by_day": self.by_day(),
            "events": [event.as_dict() for event in ordered],
        }


def span_human(seconds: int) -> str:
    if seconds <= 0:
        return "0 s"
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes, secs = divmod(rest, 60)
    parts = []
    if days:
        parts.append(f"{days} d")
    if hours:
        parts.append(f"{hours} h")
    if minutes:
        parts.append(f"{minutes} min")
    if secs and not days:
        parts.append(f"{secs} s")
    return " ".join(parts)


def merge(*timelines: Timeline, label: str = "") -> Timeline:
    events: list[Event] = []
    for item in timelines:
        events.extend(item.events)
    return Timeline(events=events, label=label)


def csv_rows(timeline: Timeline) -> tuple[list[str], list[list]]:
    return (
        ["utc", "local_warsaw", "kind", "source", "package", "detail"],
        timeline.rows(),
    )


def package_of(path: str) -> str:
    """``/data/com.foo.bar/databases/x.db`` → ``com.foo.bar``.

    A source that is not a path (a database name, a log label) has no package,
    and saying so is better than inventing one from its first word.
    """
    text = str(path)
    if not text.startswith("/"):
        return ""
    parts = [part for part in text.strip("/").split("/") if part]
    if not parts:
        return ""
    if parts[0] == "data" and len(parts) > 1:
        return parts[1]
    if parts[0] == "system" and len(parts) > 1 and parts[1] == "app":
        return parts[2].rsplit("-", 1)[0] if len(parts) > 2 else ""
    if parts[0] == "app" and len(parts) > 1:
        return parts[1].rsplit("-", 1)[0]
    return parts[0]


def group_by_package(events: Iterable[Event]) -> dict[str, int]:
    return _counter(event.package or package_of(event.source) for event in events)


def _counter(values: Iterable[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for value in values:
        out[value] = out.get(value, 0) + 1
    return dict(sorted(out.items(), key=lambda item: (-item[1], item[0])))


def last_per_source(timeline: Timeline) -> list[dict[str, Any]]:
    """The most recent event of each source — the usual summary of a timeline."""
    best: dict[str, Event] = {}
    for event in timeline.events:
        current = best.get(event.source)
        if current is None or event.unix > current.unix:
            best[event.source] = event
    return [
        {
            "source": event.source,
            "kind": event.kind,
            "utc": event.utc,
            "local_warsaw": event.local,
            "detail": event.detail,
        }
        for event in sorted(best.values(), key=lambda item: item.unix, reverse=True)
    ]


def group_runs(timeline: Timeline, gap_seconds: int = 300) -> list[dict[str, Any]]:
    """Split a timeline into bursts separated by more than ``gap_seconds``."""
    runs: list[dict[str, Any]] = []
    current: list[Event] = []
    for event in timeline.sorted():
        if current and event.unix - current[-1].unix > gap_seconds:
            runs.append(_run(current))
            current = []
        current.append(event)
    if current:
        runs.append(_run(current))
    return runs


def _run(events: Sequence[Event]) -> dict[str, Any]:
    packages = sorted({package_of(event.source) for event in events if package_of(event.source)})
    return {
        "start_utc": events[0].utc,
        "end_utc": events[-1].utc,
        "start_local": events[0].local,
        "end_local": events[-1].local,
        "events": len(events),
        "seconds": events[-1].unix - events[0].unix,
        "packages": packages,
        "first_source": events[0].source,
        "last_source": events[-1].source,
    }
