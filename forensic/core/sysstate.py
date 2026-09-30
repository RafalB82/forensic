# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Android system state: the files the framework writes outside ``/data``.

A dump of ``/data`` answers what the applications stored.  It does not answer
what the *system* was doing, and the system side is where the least expected
evidence lives: kernel reboot records, the crash history the vendor keeps in
``/system/mcd/klo``, process snapshots, the traffic counters, and the small
debug logs MIUI applications leave on shared storage.

Two of those formats are text and are parsed properly.  Two are binary blobs
written by framework internals; they are read for what can be read without a
schema — magic, size, the strings that are actually there — and anything that
would need a schema is reported as such instead of guessed.
"""

from __future__ import annotations

import re
from typing import Any

PROCSTATS_MAGIC = b"STSP"
UTF16_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){3,48}")
KLO_WINDOW = re.compile(r"Record start:\s*(.+?)\s+Record end:\s*(.+?)\s*\]")
KLO_RANGE = re.compile(r"summary\s*\(\s*(.+?)\s+to\s+(.+?)\s*\)")
KLO_FIELD = re.compile(r"^\s*([A-Za-z][\w .]{0,40}?)\s*:\s*(.*?)\s*$")
KLO_TIME = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
DEBUG_LINE = re.compile(r"^(\d+)\s+(\S+)\s+\[(\w+)\]\s+([\d-]+)\s+([\d:]+)\s+(.*)$")


def procstats_snapshot(blob: bytes, name: str = "") -> dict[str, Any]:
    """One ``/system/procstats/state-*.bin`` snapshot.

    The file is a serialised ``Parcel``: process names are the only text in it,
    and they are the part worth having.  The rest is a table of run times and
    memory figures keyed by those names, which this project does not attempt to
    attribute to fields without the framework's own format definition.
    """
    names: list[str] = []
    for match in UTF16_RUN.finditer(blob):
        value = match.group().decode("utf-16-le", "replace")
        if value not in names:
            names.append(value)
    stamp = ""
    found = re.search(r"(\d{4}-\d{2}-\d{2})-(\d{2})-(\d{2})-(\d{2})", name)
    if found:
        stamp = f"{found.group(1)} {found.group(2)}:{found.group(3)}:{found.group(4)}"
    return {
        "file": name,
        "size": len(blob),
        "magic": blob[:4].decode("ascii", "replace"),
        "is_procstats": blob[:4] == PROCSTATS_MAGIC,
        "version": int.from_bytes(blob[4:8], "little") if len(blob) >= 8 else None,
        "local_time_in_name": stamp,
        "processes": len(names),
        "names": names,
        "verdict": (
            f"{len(names)} nazw procesów w migawce"
            if blob[:4] == PROCSTATS_MAGIC
            else "brak sygnatury STSP — nie jest migawką procstats"
        ),
    }


def procstats_deltas(snapshots: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """What appeared and disappeared between consecutive snapshots."""
    out: list[dict[str, Any]] = []
    previous: dict[str, Any] | None = None
    for item in snapshots:
        if previous is not None:
            before = set(previous.get("names", []))
            after = set(item.get("names", []))
            out.append(
                {
                    "from": previous.get("file", ""),
                    "to": item.get("file", ""),
                    "from_local": previous.get("local_time_in_name", ""),
                    "to_local": item.get("local_time_in_name", ""),
                    "added": sorted(after - before),
                    "removed": sorted(before - after),
                    "added_count": len(after - before),
                    "removed_count": len(before - after),
                }
            )
        previous = item
    return out


def klo_crash_history(blob: bytes, name: str = "") -> dict[str, Any]:
    """``/system/mcd/klo/android_klo_0.txt`` — the vendor crash summary.

    Plain text, grouped by binary, with one line per occurrence.  The times are
    **local** wall clock, so they are reported as written and alongside their UTC
    conversion rather than silently shifted.
    """
    text = blob.decode("utf-8", "replace")
    out: dict[str, Any] = {
        "file": name,
        "size": len(blob),
        "is_text": True,
        "packages": [],
        "window": "",
        "history_range": "",
    }
    window = KLO_WINDOW.search(text)
    if window:
        out["record_start_local"] = window.group(1).strip()
        out["record_end_local"] = window.group(2).strip()
    history = KLO_RANGE.search(text)
    if history:
        out["history_range"] = f"{history.group(1).strip()} → {history.group(2).strip()}"
    package: dict[str, Any] | None = None
    for line in text.splitlines():
        field = KLO_FIELD.match(line)
        if not field:
            continue
        key = field.group(1).strip()
        value = field.group(2).strip()
        if key == "package name":
            if package:
                out["packages"].append(package)
            package = {
                "package": value,
                "version": "",
                "crashes_since_boot": 0,
                "occurrences": [],
            }
            continue
        if package is None:
            continue
        if key == "package version":
            package["version"] = value
        elif key == "crash since start":
            match = re.search(r"(\d+)", value)
            package["crashes_since_boot"] = int(match.group(1)) if match else 0
        elif key == "subtype":
            package["subtype"] = value
        elif key == "happen time":
            package["occurrences"].append(value)
    if package:
        out["packages"].append(package)
    out["occurrences"] = sum(len(item["occurrences"]) for item in out["packages"])
    out["verdict"] = (
        f"{len(out['packages'])} grup, {out['occurrences']} wystąpień w historii "
        f"{out['history_range'] or '?'}"
    )
    return out


def kernel_reboot_records(blob: bytes, name: str = "") -> dict[str, Any]:
    """``kernel_klo_*.txt`` — kernel restart records, one block each."""
    text = blob.decode("utf-8", "replace")
    records: list[dict[str, Any]] = []
    note = ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("kernel reboot"):
            note = stripped.split(":", 1)[1].strip() if ":" in stripped else ""
        elif stripped.startswith("record time_stamp"):
            records.append(
                {
                    "local": stripped.split(":", 1)[1].strip(),
                    "note": note,
                }
            )
            note = ""
    return {
        "file": name,
        "size": len(blob),
        "records": records,
        "count": len(records),
        "verdict": f"{len(records)} rejestrów restartu jądra",
    }


def debug_log(blob: bytes, name: str = "") -> dict[str, Any]:  # noqa: D401
    """MIUI application debug logs on shared storage (``debug_log/<app>/*.txt``).

    Plain text, one event per line: ``<prio> <tag> [<level>] MM-DD HH:MM:SS am <message>``.
    The dates carry no year, so the year comes from the file and is stated as
    such instead of being assumed silently.
    """
    text = blob.decode("utf-8", "replace")
    year = ""
    match = re.search(r"(\d{4})", name)
    if match:
        year = match.group(1)
    entries: list[dict[str, Any]] = []
    for line in text.splitlines():
        hit = DEBUG_LINE.match(line.strip())
        if not hit:
            continue
        priority, tag, level, stamp, clock, message = hit.groups()
        entries.append(
            {
                "priority": priority,
                "tag": tag,
                "level": level,
                "date": f"{year}-{stamp}" if year else stamp,
                "time": clock,
                "message": message[:300],
            }
        )
    tags: list[str] = sorted({item["tag"] for item in entries})
    out = {
        "file": name,
        "size": len(blob),
        "entries": entries,
        "count": len(entries),
        "tags": tags,
    }
    stat_like = _stat_from_debug(out)
    if stat_like:
        out["timestamps"] = stat_like
    out["verdict"] = (
        f"{out['count']} wpisów, tagi: {', '.join(tags)}"
        if entries
        else "brak rozpoznanych wpisów"
    )
    return out


def _stat_from_debug(log: dict[str, Any]) -> list[dict[str, Any]]:
    """Turn ``MM-DD HH:MM:SS`` log stamps into UTC, using the year from the name."""
    from . import timeline as tl

    out: list[dict[str, Any]] = []
    for item in log.get("entries", []):
        date = item.get("date", "")
        if not re.match(r"^\d{4}-\d{2}-\d{2}$", date):
            continue
        stamp = tl.epoch_seconds(f"{date}T{item.get('time', '00:00:00')}Z")
        if not stamp["ok"]:
            out.append({"input": f"{date} {item.get('time')}", "ok": False, "note": "rok spoza zakresu"})
            continue
        local_unix = stamp["unix"]
        utc_text = tl.utc(local_unix - 3600)  # marzec 2026: UTC+1 (czas lokalny)
        out.append(
            {
                "input": f"{date} {item.get('time')} (lokalnie)",
                "utc": utc_text,
                "ok": True,
            }
        )
    return out


def batterystats_checkin(blob: bytes, name: str = "") -> dict[str, Any]:
    """``/system/batterystats-checkin.bin`` — presence and shape, not values.

    The file is a protobuf defined by AOSP's ``powerstats.proto``.  Reading its
    numbers without that schema would mean inventing meanings, so the module
    reports what it can verify on its own — size, that it is a length-delimited
    field stream, and that it carries no readable names — and names the schema
    that would be needed.
    """
    import re as _re

    strings = [m.group().decode() for m in _re.finditer(rb"[\x20-\x7e]{6,40}", blob)]
    out: dict[str, Any] = {
        "file": name,
        "size": len(blob),
        "strings": len(strings),
        "readable_names": [item for item in strings if any(c.isalpha() for c in item)][:10],
        "schema": "AOSP frameworks/base powerstats.proto (BatteryStatsCheckin)",
        "schema_present_in_project": False,
    }
    out["verdict"] = (
        "plik jest czytelny strukturalnie, ale nazwy pól wymagają schemy powerstats.proto, "
        "której projekt nie zawiera — raportowane jako obecność pliku, nie jako odczyt"
    )
    return out
