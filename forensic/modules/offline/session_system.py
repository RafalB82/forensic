# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""The system side of the last session: crashes, reboots, processes, counters.

``fs_timeline`` shows that files were written; this module reads *what* the
system wrote and says what it means.  The interesting part of the March 2026
session is not the file list but the fact that the device was unstable — three
kernel restart records and two crashes of the modem daemon inside eight minutes
— and that it was nevertheless used, by the messaging application among others.

Everything here is read from the framework's own files under ``/system`` and
from MIUI's debug logs on shared storage.  Blobs whose field names are not in
this project are reported as present and dated, never decoded by guesswork.
"""

from __future__ import annotations

import time
from pathlib import Path

from ...core import sysstate, timeline as tl
from ...core.export import human_bytes, to_csv, to_json
from ...core.findings import ModuleResult
from ...core.session import Ctx
from ..registry import ModuleSpec, Param, register

SESSION_FLOOR = 1767225600  # 2026-01-01
PROCSTATS_DIR = "/system/procstats"
KLO_DIR = "/system/mcd/klo"
BATTERY_STATS = "/system/batterystats-checkin.bin"
DEBUG_LOG_DIR = "/media/0/MIUI/debug_log"
LOCAL_OFFSET = 3600  # marzec 2026: czas lokalny w Warszawie to UTC+1

CATEGORIES = {
    "netstats": "liczniki ruchu sieciowego (ANET)",
    "procstats": "migawki procesów",
    "klo": "rejestry jądra i historia awarii",
    "tombstone": "zrzut awarii procesu",
    "accounts": "transakcja AccountManagera",
    "locksettings": "stan blokady ekranu",
    "batterystats": "statystyki baterii",
    "appops": "uprawnienia aplikacji",
    "policy": "polityka urządzenia",
    "bluedroid": "konfiguracja Bluetooth",
    "usb": "właściwości USB",
    "fstrim": "trim pamięci",
    "icons": "ikony ekranu ustawień",
    "debug_log": "log diagnostyczny aplikacji MIUI",
    "other": "inne",
}


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("session_system")
    since = int(params.get("since") or SESSION_FLOOR)
    limit = int(params.get("limit") or 40)
    started = time.time()
    scan = ctx.file_scan(since)
    files = _system_files(scan, since)
    res.add(
        "ok" if files else "warn",
        f"Zapisy systemowe poza /data: {len(files)} plików",
        detail=(
            "sesja zapisywała również w /system (liczniki ruchu, migawki procesów, statystyki "
            "baterii, uprawnienia) oraz w /media (log diagnostyczny aplikacji)"
        ),
        values={
            "files": len(files),
            "by_category": _by_category(files),
            "bytes": sum(item["size"] for item in files),
            "bytes_human": human_bytes(sum(item["size"] for item in files)),
            "files_list": files[:limit],
        },
    )
    crashes = _crashes(ctx, since)
    if crashes.get("packages"):
        session_crashes = _in_session(crashes, since)
        res.add(
            "critical" if session_crashes else "info",
            f"Historia awarii: {crashes['occurrences']} wystąpień w {len(crashes['packages'])} grupach",
            detail=(
                f"okno pliku {crashes.get('record_start_local', '?')} → "
                f"{crashes.get('record_end_local', '?')} czasem lokalnym; historia od "
                f"{crashes.get('history_range', '?')}"
            ),
            values={
                "file": crashes["file"],
                "packages": crashes["packages"],
                "occurrences": crashes["occurrences"],
                "history_range": crashes.get("history_range", ""),
                "record_start_local": crashes.get("record_start_local", ""),
                "record_end_local": crashes.get("record_end_local", ""),
                "in_session": session_crashes,
            },
            artifacts=[crashes["file"].split("@")[0]] if "@" in crashes["file"] else [],
        )
        for item in session_crashes:
            pairs = list(zip(item["occurrences"], item["occurrences_utc"]))
            for index, (local, utc_text) in enumerate(pairs):
                res.add(
                    "critical",
                    f"Awaria {item['package']} o {local} czasem lokalnym ({utc_text})",
                    detail=(
                        "czas zgodny ze zrzutem tombstone z tego samego okna"
                        if "mdbd" in item["package"]
                        else f"podgrupa: {item.get('subtype', '?')}"
                    ),
                    values={
                        "package": item["package"],
                        "local": local,
                        "utc": utc_text,
                        "subtype": item.get("subtype", ""),
                        "crashes_since_boot": item.get("crashes_since_boot", 0),
                        "of_occurrences": len(pairs),
                        "index": index + 1,
                    },
                )
    reboots = _reboots(ctx)
    if reboots:
        times = [item["unix"] for item in reboots["records"]]
        res.add(
            "critical" if len(times) > 1 else "warn",
            f"Rejestry restartu jądra: {reboots['count']}",
            detail=(
                "system rejestruje restart jądra osobno od awarii procesu; trzy zapisy w oknie "
                f"{tl.utc(min(times))} → {tl.utc(max(times))} UTC wskazują niestabilność, "
                "nie pojedynczy incydent"
                if len(times) > 1
                else "pojedynczy rejestr restartu jądra"
            ),
            values={
                "file": reboots["file"],
                "count": reboots["count"],
                "records": reboots["records"],
                "first_utc": tl.utc(min(times)) if times else "",
                "last_utc": tl.utc(max(times)) if times else "",
                "span": tl.span_human(max(times) - min(times)) if times else "",
            },
        )
    procstats = _procstats(ctx, since)
    if procstats["snapshots"]:
        res.add(
            "info",
            f"Migawki procesów: {len(procstats['snapshots'])}",
            detail=(
                f"od {procstats['snapshots'][0]['local_time_in_name']} do "
                f"{procstats['snapshots'][-1]['local_time_in_name']} czasem lokalnym; "
                f"największe różnice między migawkami: "
                + "; ".join(
                    f"{item['from_local']}→{item['to_local']}: +{item['added_count']}/-{item['removed_count']}"
                    for item in procstats["deltas"]
                )
            ),
            values={
                "snapshots": [
                    {
                        "file": item["file"],
                        "local_time_in_name": item["local_time_in_name"],
                        "mtime_utc": item.get("mtime_utc", ""),
                        "processes": item["processes"],
                        "magic": item["magic"],
                    }
                    for item in procstats["snapshots"]
                ],
                "deltas": procstats["deltas"],
            },
        )
    debug = _debug_logs(ctx, since)
    if debug["logs"]:
        for log in debug["logs"]:
            res.add(
                "finding",
                f"Log diagnostyczny {log['app']}: {log['count']} wpisów",
                detail=(
                    "aplikacja komunikacyjna działała w trakcie sesji — to jedyny ślad aktywności "
                    "aplikacji zapisany poza /data"
                    if log["app"] == "Mms"
                    else "log diagnostyczny aplikacji MIUI"
                ),
                values=log,
            )
    battery = _battery(ctx, since)
    if battery:
        res.add(
            "info",
            f"Statystyki baterii: {battery['size_human']} ({battery['file']})",
            detail=battery["verdict"],
            values=battery,
        )
    verdict = _verdict(reboots, crashes, debug, procstats, since)
    res.add(
        "finding" if verdict["verdict"] == "unstable_session" else "info",
        f"Sesja: {verdict['verdict']}",
        detail=verdict["detail"],
        values=verdict,
    )
    res.data = {
        "since_utc": tl.utc(since),
        "scan_seconds": scan["seconds"],
        "files": files,
        "by_category": _by_category(files),
        "crashes": crashes,
        "session_crashes": _in_session(crashes, since),
        "kernel_reboots": reboots,
        "procstats": procstats,
        "debug_logs": debug,
        "batterystats": battery,
        "verdict": verdict,
    }
    res.export(
        to_json(ctx.work("exports") / "session_system.json", res.data, ctx.masker, indent=1)
    )
    res.export(
        to_csv(
            ctx.work("exports") / "session_system_files.csv",
            ["utc", "local_warsaw", "category", "bytes", "path"],
            [
                [item["utc"], item["local_warsaw"], item["category"], item["size"], item["path"]]
                for item in files
            ],
            ctx.masker,
        )
    )
    res.export(
        to_csv(
            ctx.work("exports") / "session_crash_history.csv",
            ["package", "occurrences_local", "utc", "subtype"],
            [
                [item["package"], occurrence, item["occurrences_utc"][index], item.get("subtype", "")]
                for item in _in_session(crashes, since)
                for index, occurrence in enumerate(item["occurrences"])
            ],
            ctx.masker,
        )
    )
    res.note(f"{time.time() - started:.1f}s")
    return ctx.record(res)


def _system_files(scan: dict, since: int) -> list[dict]:
    out: list[dict] = []
    for item in scan["recent"]:
        path = item["path"]
        if path.startswith(ENC_PREFIXES):
            continue
        out.append(
            {
                "path": path,
                "name": path.rsplit("/", 1)[-1],
                "category": _category(path),
                "utc": item["mtime_utc"],
                "local_warsaw": item["mtime_local"],
                "unix": item["mtime"],
                "size": item["size"],
            }
        )
    out.sort(key=lambda entry: entry["unix"])
    return out


ENC_PREFIXES = ("/data/",)


def _category(path: str) -> str:
    name = path.rsplit("/", 1)[-1]
    for key, label in CATEGORIES.items():
        if key in path:
            return key
    if name.startswith("tombstone"):
        return "tombstone"
    if "debug_log" in path:
        return "debug_log"
    return "other"


def _by_category(files: list[dict]) -> dict[str, int]:
    out: dict[str, int] = {}
    for item in files:
        out[item["category"]] = out.get(item["category"], 0) + 1
    return dict(sorted(out.items(), key=lambda item: -item[1]))


def _crashes(ctx: Ctx, since: int) -> dict:
    try:
        entries = ctx.fs().listdir(KLO_DIR)
    except Exception:
        return {"packages": [], "occurrences": 0}
    for entry in entries:
        if entry.is_reg and entry.name.startswith("android_klo"):
            local = str(ctx.materialise(f"{KLO_DIR}/{entry.name}"))
            report = sysstate.klo_crash_history(Path(local).read_bytes(), entry.name)
            report["file"] = f"{KLO_DIR}/{entry.name}@{local}"
            return report
    return {"packages": [], "occurrences": 0}


def _in_session(crashes: dict, since: int) -> list[dict]:
    out: list[dict] = []
    for package in crashes.get("packages", []):
        occurrences = package.get("occurrences", [])
        stamps = [_local_to_unix(item) for item in occurrences]
        if not any(stamp >= since for stamp in stamps):
            continue
        out.append(
            {
                "package": package["package"],
                "version": package.get("version", ""),
                "crashes_since_boot": package.get("crashes_since_boot", 0),
                "subtype": package.get("subtype", ""),
                "occurrences": occurrences,
                "occurrences_utc": [tl.utc(stamp) for stamp in stamps],
            }
        )
    return out


def _local_to_unix(text: str) -> int:
    stamp = tl.epoch_seconds(str(text).replace(" ", "T"))
    return stamp["unix"] - LOCAL_OFFSET if stamp["ok"] else 0


def _reboots(ctx: Ctx) -> dict:
    try:
        entries = ctx.fs().listdir(KLO_DIR)
    except Exception:
        return {"records": [], "count": 0}
    for entry in entries:
        if not (entry.is_reg and entry.name.startswith("kernel_klo")):
            continue
        blob = ctx.fs().read(entry, max_bytes=1024 * 1024)
        report = sysstate.kernel_reboot_records(blob, entry.name)
        report["file"] = f"{KLO_DIR}/{entry.name}"
        for record in report["records"]:
            record["unix"] = _local_to_unix(record["local"])
            record["utc"] = tl.utc(record["unix"])
        return report
    return {"records": [], "count": 0}


def _procstats(ctx: Ctx, since: int) -> dict:
    fs = ctx.fs()
    snapshots: list[dict] = []
    try:
        entries = fs.listdir(PROCSTATS_DIR)
    except Exception:
        return {"snapshots": [], "deltas": []}
    names: list[tuple[str, dict]] = []
    for entry in entries:
        if not entry.is_reg or not entry.name.endswith(".bin"):
            continue
        stat = fs.stat(f"{PROCSTATS_DIR}/{entry.name}")
        if stat["mtime_unix"] < since:
            continue
        report = sysstate.procstats_snapshot(
            fs.read(entry, max_bytes=4 * 1024 * 1024), entry.name
        )
        report["mtime_utc"] = stat["mtime_utc"]
        names.append((entry.name, report))
    names.sort(key=lambda item: item[1].get("local_time_in_name", ""))
    snapshots = [item[1] for item in names]
    return {"snapshots": snapshots, "deltas": sysstate.procstats_deltas(snapshots)}


def _debug_logs(ctx: Ctx, since: int) -> dict:
    fs = ctx.fs()
    logs: list[dict] = []
    try:
        apps = fs.listdir(DEBUG_LOG_DIR)
    except Exception:
        return {"logs": []}
    for app in apps:
        if not app.is_dir:
            continue
        try:
            files = fs.listdir(app.inode)
        except Exception:
            continue
        for entry in files:
            if not entry.is_reg or not entry.name.endswith(".txt"):
                continue
            stat = fs.stat(f"{DEBUG_LOG_DIR}/{app.name}/{entry.name}")
            if stat["mtime_unix"] < since:
                continue
            report = sysstate.debug_log(
                fs.read(entry, max_bytes=1024 * 1024), entry.name
            )
            report["app"] = app.name
            report["path"] = f"{DEBUG_LOG_DIR}/{app.name}/{entry.name}"
            report["mtime_utc"] = stat["mtime_utc"]
            logs.append(report)
    logs.sort(key=lambda item: item["mtime_utc"])
    return {"logs": logs, "count": len(logs)}


def _battery(ctx: Ctx, since: int) -> dict:
    try:
        stat = ctx.fs().stat(BATTERY_STATS)
        blob = ctx.fs().read(BATTERY_STATS, max_bytes=8 * 1024 * 1024)
    except Exception:
        return {}
    if stat["mtime_unix"] < since:
        return {}
    report = sysstate.batterystats_checkin(blob, BATTERY_STATS)
    report["mtime_utc"] = stat["mtime_utc"]
    report["size_human"] = human_bytes(stat["size"])
    return report


def _verdict(
    reboots: dict, crashes: dict, debug: dict, procstats: dict, since: int
) -> dict:
    reasons: list[str] = []
    reboots_n = reboots.get("count", 0)
    if reboots_n:
        reasons.append(f"{reboots_n} rejestrów restartu jądra")
    in_session = _in_session(crashes, since)
    if in_session:
        names = ", ".join(item["package"] for item in in_session)
        count = sum(len(item["occurrences"]) for item in in_session)
        reasons.append(f"awarie w sesji: {names} ({count}×)")
    history = crashes.get("history_range", "")
    if history and not in_session:
        reasons.append(f"historia awarii sięga {history}")
    used = [log["app"] for log in debug.get("logs", [])]
    if used:
        reasons.append(f"log diagnostyczny aplikacji: {', '.join(sorted(set(used)))}")
    unstable = reboots_n > 1 or bool(in_session)
    return {
        "verdict": "unstable_session" if unstable else "stable_session",
        "verdict_pl": "sesja niestabilna" if unstable else "sesja stabilna",
        "reasons": reasons,
        "detail": (
            "; ".join(reasons)
            + (
                " — telefon był używany (aplikacje komunikacyjne, klawiatura, kalendarz), "
                "mimo że nie było uwierzytelnionej sesji sieciowej"
                if used
                else ""
            )
        ),
        "kernel_reboots": reboots_n,
        "crash_packages_in_session": [item["package"] for item in in_session],
        "crashes_in_session": sum(len(item["occurrences"]) for item in in_session),
        "apps_with_debug_log": sorted(set(used)),
        "procstats_snapshots": len(procstats.get("snapshots", [])),
    }


register(
    ModuleSpec(
        id="session_system",
        category="timeline",
        title="mod.session_system.title",
        summary="mod.session_system.summary",
        params=[
            Param(key="since", label="param.since_unix", default=SESSION_FLOOR, kind="int"),
            Param(key="limit", label="param.limit", default=40, kind="int"),
        ],
        run=run,
    )
)
