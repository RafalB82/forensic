# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""What the file system itself says about the last time the phone was alive.

A dump has no login record for "the device was switched on", but every write
leaves an mtime.  This module walks the image once, keeps the files whose mtime
falls after a cut-off, and turns the result into a session: how long it lasted,
which packages were touched, whether the ordering looks like a boot rather than
a clock jump, and which crashes happened inside it.
"""

from __future__ import annotations

import re
import time

from ...core import appdata, timeline as tl
from ...core.export import human_bytes, to_csv, to_json
from ...core.findings import ModuleResult
from ...core.session import Ctx
from ..registry import ModuleSpec, Param, register

USAGE_LIST = "/system/package-usage.list"
TOMBSTONES = "/tombstones"
CRASH_MARKERS = ("signal 6", "signal 11", "signal 4", "Fatal signal")
SHUTDOWN_MARKERS = (
    "powerkeeper",
    "com.qualcomm.shutdownlistner",
    "com.android.updater",
    "com.miui.securitycenter",
    "com.android.systemui",
    "com.android.settings",
)
NOTABLE = {
    "accounts.db": "transakcja AccountManager (usuwa tokeny)",
    "locksettings.db": "przepisany locksettings (stan blokady)",
    "gcm_connection_infos": "plik stanu połączenia GCM",
    "gservices.db": "baza stanu usług Google",
    "app_screenshot": "katalog zrzutów ekranu (przełącznik zadań)",
    "tombstone": "zrzut awarii procesu",
    "the.apk": "plik zapisany w katalogu szyfrowanym FBE",
    "contacts2.db": "baza kontaktów zapisana w katalogu szyfrowanym",
    "Contacts.dict": "słownik kontaktów w katalogu szyfrowanym",
    "whatsapp.log": "log WhatsAppa",
    "midrive": "baza usługi Google Drive",
}


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("fs_timeline")
    since = str(params.get("since") or "2026-01-01")
    cut = _cutoff(since)
    limit = int(params.get("limit") or 0)
    started = time.time()
    scan = ctx.file_scan(cut)
    files = scan["recent"][: limit or None]
    walk_info = {
        "files": scan["recent_count"],
        "entries": scan["entries"],
        "seconds": scan["seconds"],
        "files_total": scan["files_total"],
        "shared_scan": True,
        "walk_errors": scan["walk_errors"],
        "walk_error_detail": scan["walk_error_detail"],
    }
    if not files:
        res.add(
            "warn",
            f"Brak plików z mtime od {since}",
            detail=f"przeszukano {walk_info['files']} plików w {walk_info['seconds']} s",
            values={"since": since, "cutoff_utc": tl.utc(cut), **walk_info},
        )
        return ctx.record(res)
    events = tl.Timeline(
        events=[
            tl.Event(
                unix=item["mtime"],
                source=item["path"],
                kind=tl.KIND_FILE,
                detail=f"{item['size']} B",
                unit="s",
                value=item["size"],
                package=item["package"],
            )
            for item in files
        ],
        label="files",
    )
    window = events.window()
    res.add(
        "finding",
        f"Sesja zapisana w metadanych: {window['count']} plików w oknie "
        f"{window['first_utc']} → {window['last_utc']}",
        detail=(
            f"okno trwa {window['span_human']} ({window['first_local']} → {window['last_local']} "
            f"czasem lokalnym); {walk_info['files']} plików przejrzanych w {walk_info['seconds']} s"
        ),
        values={
            "since": since,
            "cutoff_utc": tl.utc(cut),
            "files_scanned": walk_info["files"],
            "entries_scanned": walk_info["entries"],
            "files_total": walk_info["files_total"],
            "seconds": walk_info["seconds"],
            "shared_scan": walk_info["shared_scan"],
            **window,
            "by_day": events.by_day(),
            "by_package": dict(list(tl.group_by_package(events.events).items())[:20]),
            "bytes_written": sum(item["size"] for item in files),
        },
    )
    bursts = tl.group_runs(events, gap_seconds=600)
    if bursts:
        res.add(
            "info",
            f"Bursty aktywności (odstęp > 10 min): {len(bursts)}",
            detail=(
                "bursty o rosnących rozmiarach i kolejności zgodnej z uruchomieniem systemu "
                "wskazują na prawdziwą sesję, a nie na skok zegara"
            ),
            values={
                "bursts": len(bursts),
                "largest": sorted(bursts, key=lambda item: -item["events"])[:8],
                "first_bursts": bursts[:6],
            },
        )
    usage = _usage(ctx, cut)
    if usage:
        res.add(
            "info",
            f"package-usage.list: {usage['packages']} pakietów użytych w tym oknie",
            detail=(
                f"najstarszy {usage['first_utc']}, najnowszy {usage['last_utc']}; "
                "to kolejny, niezależny zapis zegara systemowego"
            ),
            values=usage,
        )
    notable = _notable(files)
    for item in notable:
        res.add(
            "info",
            f"{item['path']} — {item['utc']}",
            detail=item["why"],
            values={**item, "package": tl.package_of(item["path"])},
        )
    crashes = _crashes(ctx, files)
    for crash in crashes:
        res.add(
            "warn" if crash["signal"].startswith("6 (") else "critical",
            f"Awaria procesu {crash['process']}: {crash['signal']}",
            detail=(
                f"zrzut {crash['path']} zapisany {crash['utc']}; "
                f"{crash['build']}; pid {crash['pid']}"
            ),
            values=crash,
        )
    shutdown = _shutdown_sequence(files, usage.get("rows", []))
    if shutdown:
        res.add(
            "info",
            f"Końcowe zapisy sesji: {shutdown['files']} plików w ostatnich "
            f"{shutdown['window_seconds']} s",
            detail=(
                "na końcu zapisywana jest księgowość systemowa (package-usage.list, appops, "
                "konfiguracja Bluetooth, procstats), a usługi "
                f"{', '.join(shutdown['services_stopped'][:6])} miały zapisaną aktywność "
                "w tej samej sekundzie — to zamykanie urządzenia"
            ),
            values=shutdown,
        )
    res.data = {
        "since": since,
        "cutoff_utc": tl.utc(cut),
        "scan": walk_info,
        **window,
        "by_day": events.by_day(),
        "by_hour": events.by_hour(),
        "by_package": tl.group_by_package(events.events),
        "bytes_written": sum(item["size"] for item in files),
        "bursts": bursts,
        "usage": usage,
        "notable": notable,
        "crashes": crashes,
        "shutdown": shutdown,
        "files": files,
    }
    res.export(
        to_json(ctx.work("exports") / "fs_timeline.json", res.data, ctx.masker, indent=1)
    )
    res.export(
        to_csv(
            ctx.work("exports") / "fs_timeline.csv",
            ["utc", "local_warsaw", "package", "size", "path"],
            [
                [
                    tl.utc(item["mtime"]),
                    tl.local_warsaw(item["mtime"]),
                    item["package"],
                    item["size"],
                    item["path"],
                ]
                for item in sorted(files, key=lambda entry: entry["mtime"])
            ],
            ctx.masker,
        )
    )
    res.note(f"{time.time() - started:.1f}s")
    return ctx.record(res)


def _cutoff(since: str) -> int:
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
        try:
            import datetime as _dt

            return int(
                _dt.datetime.strptime(since, fmt)
                .replace(tzinfo=_dt.timezone.utc)
                .timestamp()
            )
        except ValueError:
            continue
    return 0


def _usage(ctx: Ctx, cut: int) -> dict:
    try:
        blob = ctx.fs().read(USAGE_LIST)
    except Exception:
        return {}
    rows = [item for item in appdata.package_usage(blob) if item["last_used_ms"] // 1000 >= cut]
    if not rows:
        return {}
    stamps = [item["last_used_ms"] // 1000 for item in rows]
    return {
        "source": USAGE_LIST,
        "packages": len(rows),
        "first_utc": tl.utc(min(stamps)),
        "last_utc": tl.utc(max(stamps)),
        "span_human": tl.span_human(max(stamps) - min(stamps)),
        "rows": rows,
        "sample": [
            {"package": item["package"], "last_used_utc": item["last_used_utc"]}
            for item in rows[:20]
        ],
        "by_day": tl._counter(
            item["last_used_utc"][:10] for item in rows if item["last_used_utc"]
        ),
    }


def _notable(files: list[dict]) -> list[dict]:
    out: list[dict] = []
    for item in files:
        name = item["path"].rsplit("/", 1)[-1]
        reason = NOTABLE.get(name)
        if reason is None:
            for key, text in NOTABLE.items():
                if key in item["path"]:
                    reason = text
                    break
        if reason:
            out.append(
                {
                    "path": item["path"],
                    "utc": item["mtime_utc"],
                    "local_warsaw": item["mtime_local"],
                    "size": item["size"],
                    "size_human": human_bytes(item["size"]),
                    "why": reason,
                }
            )
    out.sort(key=lambda entry: entry["utc"])
    return out


def _crashes(ctx: Ctx, files: list[dict]) -> list[dict]:
    """Parse the tombstone files written inside the window."""
    out: list[dict] = []
    try:
        entries = ctx.fs().listdir(TOMBSTONES)
    except Exception:
        return out
    inside = {item["path"].rsplit("/", 1)[-1]: item for item in files}
    for entry in entries:
        node = ctx.fs().inode(entry.inode)
        if not entry.is_reg or node.mtime < 1:
            continue
        stamp = inside.get(entry.name)
        if not stamp:
            continue
        text = ctx.fs().read(entry, max_bytes=8192).decode("utf-8", "replace")
        out.append(
            {
                "path": f"{TOMBSTONES}/{entry.name}",
                "utc": stamp["mtime_utc"],
                "size": node.size,
                "process": _crash_field(text, "name"),
                "signal": _crash_field(text, "signal"),
                "pid": _crash_field(text, "pid"),
                "build": _crash_field(text, "Build fingerprint"),
                "text_head": " / ".join(text.splitlines()[1:5]).strip(),
            }
        )
    out.sort(key=lambda item: item["utc"])
    return out


PID_LINE = re.compile(r"^pid:\s*(\d+),\s*tid:\s*(\d+),\s*name:\s*([^>]+?)\s*(?:>>>|$)")
SIGNAL_LINE = re.compile(r"^signal\s+(\d+)\s*\(([^)]+)\)")


def _crash_field(text: str, field: str) -> str:
    """One field of a tombstone header.

    A tombstone header is not ``key: value`` throughout: the process line packs
    pid, tid and name into one line, and the signal line has no colon at all.
    """
    for line in text.splitlines():
        if field == "name":
            match = PID_LINE.match(line)
            if match:
                return match.group(3).strip()
            continue
        if field == "pid":
            match = PID_LINE.match(line)
            if match:
                return match.group(1)
            continue
        if field == "signal":
            match = SIGNAL_LINE.match(line)
            if match:
                return f"{match.group(1)} ({match.group(2)})"
            continue
        if line.startswith(field + ":"):
            return line.split(":", 1)[1].strip()
    return ""


def _shutdown_sequence(files: list[dict], usage_rows: list[dict]) -> dict:
    """The final writes of the session: system bookkeeping, then nothing."""
    if not files:
        return {}
    end = files[-1]["mtime"]
    window = [item for item in files if item["mtime"] >= end - 120]
    services = [
        item["package"]
        for item in usage_rows
        if item["last_used_ms"] // 1000 >= end - 120
    ]
    return {
        "window_seconds": 120,
        "files": len(window),
        "span": tl.span_human(end - window[0]["mtime"]) if window else "0 s",
        "first_utc": window[0]["mtime_utc"] if window else "",
        "last_utc": files[-1]["mtime_utc"],
        "last_file": files[-1]["path"],
        "system_files": [
            {"utc": item["mtime_utc"], "path": item["path"]}
            for item in window
            if item["path"].startswith(("/system/", "/misc/"))
        ],
        "services_stopped": sorted(set(services)),
        "order": [
            {"utc": item["mtime_utc"], "package": item["package"], "path": item["path"]}
            for item in window
        ][:30],
    }


register(
    ModuleSpec(
        id="fs_timeline",
        category="timeline",
        title="mod.fs_timeline.title",
        summary="mod.fs_timeline.summary",
        params=[
            Param(key="since", label="param.since", default="2026-01-01", kind="str"),
            Param(key="limit", label="param.limit", default=0, kind="int"),
        ],
        run=run,
    )
)
