# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""One traversal of the image, answering every question about file times.

Walking an ext4 image is not expensive in itself — about 7 seconds for 150 000
directory entries — but three different modules need the same traversal, and
paying for it three times makes a regression run twice as slow as it needs to
be.  This module does the walk once and hands out the answers: which files were
written after a cut-off, how many timestamps are unusable, and what the years
look like.

The classification is deliberately blunt, because the interesting part of a
forensic timeline is not a smooth distribution but the outliers:

* ``epoch`` — written while the clock still read the start of 1970;
* ``installer`` — 1979, one day before the ZIP epoch, written by the package
  installer when it unpacked native libraries;
* ``coherent`` — ordinary dates before the cut-off, corroborated by application
  data;
* ``recent`` — at or after the cut-off the caller asked about.

The cut-off is a class boundary, not a filter: the four counts always add up to
the number of files in the image, so a caller can report "how much of this image
is not datable" without walking it again.
"""

from __future__ import annotations

import time
from collections import Counter
from collections.abc import Callable, Iterable

EPOCH_1980 = 315532800
EPOCH_DAY = 86400


def classify(mtime: int) -> str:
    if mtime < EPOCH_DAY:
        return "epoch"
    if mtime < EPOCH_1980:
        return "installer"
    return "coherent"


def scan_files(
    fs,
    root: str = "/",
    since: int = 0,
    progress: Callable[[str], None] | None = None,
    sample_limit: int = 12,
) -> dict:
    """Walk ``root`` once and return both the recent files and the shape of the rest."""
    started = time.time()
    recent: list[dict] = []
    classes: Counter = Counter()
    by_year: Counter = Counter()
    installer_values: Counter = Counter()
    epoch_samples: list[str] = []
    installer_samples: list[str] = []
    epoch_locations: Counter = Counter()
    installer_locations: Counter = Counter()
    entries = 0
    files = 0
    year_cache: dict[int, str] = {}
    coherent_first = 0
    coherent_last = 0
    from . import timeline as tl

    for path, entry in fs.walk(root):
        entries += 1
        node = fs.inode(entry.inode)
        if not node.is_reg:
            continue
        files += 1
        after_cut = bool(since) and node.mtime >= since
        kind = "recent" if after_cut else classify(node.mtime)
        classes[kind] += 1
        if kind == "epoch":
            epoch_locations[_top(path)] += 1
            if len(epoch_samples) < sample_limit:
                epoch_samples.append(path)
        elif kind == "installer":
            installer_values[node.mtime] += 1
            installer_locations[_second(path)] += 1
            if len(installer_samples) < sample_limit:
                installer_samples.append(path)
        elif kind == "coherent":
            by_year[_year_of(node.mtime, year_cache)] += 1
            if coherent_first == 0 or node.mtime < coherent_first:
                coherent_first = node.mtime
            if node.mtime > coherent_last:
                coherent_last = node.mtime
        if after_cut:
            recent.append(
                {
                    "path": path,
                    "mtime": node.mtime,
                    "mtime_utc": tl.utc(node.mtime),
                    "mtime_local": tl.local_warsaw(node.mtime),
                    "crtime": node.crtime,
                    "ctime": node.ctime,
                    "size": node.size,
                    "package": tl.package_of(path),
                }
            )
    recent.sort(key=lambda item: item["mtime"])
    if progress:
        progress(f"{entries} wpisów, {files} plików, {len(recent)} od {tl.utc(since)}")
    walk_errors = list(getattr(fs, "walk_errors", []))
    return {
        "root": root,
        "since": since,
        "since_utc": tl.utc(since),
        "entries": entries,
        "files_total": files,
        "seconds": round(time.time() - started, 2),
        "walk_errors": len(walk_errors),
        "walk_error_detail": walk_errors[:5],
        "names_complete": not walk_errors,
        "recent": recent,
        "recent_count": len(recent),
        "recent_bytes": sum(item["size"] for item in recent),
        "classes": {
            "epoch": classes.get("epoch", 0),
            "installer": classes.get("installer", 0),
            "coherent": classes.get("coherent", 0),
            "recent": classes.get("recent", 0),
        },
        "coherent_by_year": dict(sorted(by_year.items())),
        "coherent_range": [
            tl.utc(coherent_first) if coherent_first else "",
            tl.utc(coherent_last) if coherent_last else "",
        ],

        "installer_by_value": {
            tl.utc(value): count
            for value, count in installer_values.most_common(8)
        },
        "epoch_samples": epoch_samples,
        "installer_samples": installer_samples,
        "epoch_locations": dict(epoch_locations.most_common(8)),
        "installer_locations": dict(installer_locations.most_common(8)),
    }


def _year_of(stamp: int, cache: dict[int, str]) -> str:
    """Calendar year of a timestamp, one date conversion per distinct day.

    Formatting 130 000 timestamps costs seconds; there are only a few thousand
    distinct days in a device's history, so the conversion is cached by day.
    """
    day = stamp // EPOCH_DAY
    year = cache.get(day)
    if year is None:
        import datetime as _dt

        year = _dt.datetime.fromtimestamp(day * EPOCH_DAY, _dt.timezone.utc).strftime("%Y")
        cache[day] = year
    return year


def _top(path: str) -> str:
    parts = [part for part in path.split("/") if part]
    return parts[0] if parts else "/"


def _second(path: str) -> str:
    parts = [part for part in path.split("/") if part]
    if len(parts) >= 2 and parts[0] == "app":
        return parts[1]
    return parts[1] if len(parts) > 1 else (parts[0] if parts else "/")


def window(rows: Iterable[dict]) -> dict:
    """First/last/span of a list of file records, as the timeline reports it."""
    from . import timeline as tl

    items = sorted(rows, key=lambda item: item["mtime"])
    if not items:
        return {"count": 0, "first_utc": "", "last_utc": "", "span_seconds": 0, "span_human": ""}
    span = items[-1]["mtime"] - items[0]["mtime"]
    return {
        "count": len(items),
        "first_utc": items[0]["mtime_utc"],
        "last_utc": items[-1]["mtime_utc"],
        "first_local": items[0]["mtime_local"],
        "last_local": items[-1]["mtime_local"],
        "span_seconds": span,
        "span_human": tl.span_human(span),
    }
