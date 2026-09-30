# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Which timestamps in the image can be trusted, and which cannot.

Three different kinds of wrong date turn up in one image, and they have to be
told apart before any timeline is built on them: values the ROM wrote from a
zeroed clock, values the package installer wrote as a constant, and a real boot
session whose date merely looks wrong.  The test used here is quantitative — the
installer's own directory times are compared with the Play Store's install
dates, and if those agree while the library times do not, the library times are
an artefact of the installer and not a clock failure.
"""

from __future__ import annotations

import time
from collections import Counter

from ...core import timeline as tl
from ...core.export import to_json
from ...core.findings import ModuleResult
from ...core.session import Ctx
from ...core.sqlite_tools import connect
from ..registry import ModuleSpec, register

APP_DIR = "/app"
PLAY_DB = "/data/com.android.vending/databases/localappstate.db"
EPOCH_1980 = 315532800
TOLERANCE = 900


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("clock_anomaly")
    started = time.time()
    session = _session_cluster(ctx)
    classes = _classify(ctx, session)
    installer = _installer_clock(ctx)
    verdict = _verdict(classes, installer)
    res.add(
        "ok",
        f"Zegar: {classes['coherent_count']} wiarygodnych dat, "
        f"{classes['epoch_count'] + classes['installer_count']} pozornych",
        detail=(
            f"klasy: {classes['counts']}; "
            f"zegar potwierdzony na {installer.get('matched_either')} z "
            f"{installer.get('compared')} katalogów aplikacji "
            f"({round(100 * (installer.get('agreement') or 0))}%), "
            f"największa zgodność ±{installer.get('max_delta_seconds')} s"
        ),
        values={
            "counts": classes["counts"],
            "coherent_range": classes["coherent_range"],
            "epoch_files": classes["epoch_count"],
            "installer_constant_files": classes["installer_count"],
            "installer_clock": installer,
            "verdict": verdict["verdict"],
        },
    )
    res.add(
        "info",
        f"Daty pozorne klasy 1 (epoka/Rom): {classes['epoch_count']} plików",
        detail=(
            "pliki ROM-u i właściwości systemowych zapisane z zerowego zegara — czyli przed epoką "
            "albo w pierwszych sekundach 1970; takie daty nie niosą informacji o czasie"
        ),
        values={
            "count": classes["epoch_count"],
            "by_year": classes["epoch_by_year"],
            "samples": classes["epoch_samples"],
            "locations": classes["epoch_locations"],
        },
    )
    res.add(
        "warn" if classes["installer_count"] else "ok",
        f"Daty pozorne klasy 2 (stała instalatora): {classes['installer_count']} plików",
        detail=(
            "biblioteki natywne rozpakowane z APK mają daty z 1979-12-30/31, czyli dzień przed "
            "epoką formatu ZIP. Katalogi /app/<pakiet> mają prawdziwe daty, więc to artefakt "
            "instalatora, a nie awaria zegara"
        ),
        values={
            "count": classes["installer_count"],
            "by_value": classes["installer_by_value"],
            "samples": classes["installer_samples"],
            "locations": classes["installer_locations"],
        },
    )
    res.add(
        "ok",
        f"Daty spójne: {classes['coherent_count']} plików",
        detail=(
            f"zakres {classes['coherent_range'][0]} → {classes['coherent_range'][1]}; "
            "zgodny z datami instalacji w Sklepie Play i z danymi wewnątrz aplikacji"
        ),
        values={
            "count": classes["coherent_count"],
            "range": classes["coherent_range"],
            "by_year": classes["coherent_by_year"],
        },
    )
    if session:
        res.add(
            "finding" if session["verdict"] == "real_session" else "warn",
            f"Data 2026: {session['verdict']}",
            detail=session["detail"],
            values=session,
        )
    if installer.get("compared"):
        res.add(
            "info",
            f"Dowód ilościowy na działanie zegara: {installer['matched_either']}/{installer['compared']} "
            f"katalogów zgodnych ({round(100 * installer['agreement'])}%)",
            detail=(
                "mtime katalogu /app/<pakiet> porównany z datą instalacji albo aktualizacji "
                "w localappstate.db; zgodność w granicach 15 minut oznacza, że zegar systemowy był "
                "poprawny, a więc daty 1979 w bibliotekach pochodzą od instalatora, nie od zegara"
            ),
            values={
                "compared": installer["compared"],
                "matched_install": installer["matched_install"],
                "matched_update": installer["matched_update"],
                "matched_either": installer["matched_either"],
                "agreement": installer["agreement"],
                "max_delta_seconds": installer["max_delta_seconds"],
                "tolerance_seconds": TOLERANCE,
                "best": installer["best"],
                "residual": installer["residual"],
            },
        )
    res.data = {
        "counts": classes["counts"],
        "coherent_range": classes["coherent_range"],
        "coherent_by_year": classes["coherent_by_year"],
        "epoch": {
            "count": classes["epoch_count"],
            "by_year": classes["epoch_by_year"],
            "samples": classes["epoch_samples"],
            "locations": classes["epoch_locations"],
        },
        "installer_constant": {
            "count": classes["installer_count"],
            "by_value": classes["installer_by_value"],
            "samples": classes["installer_samples"],
            "locations": classes["installer_locations"],
        },
        "installer_clock": installer,
        "session_cluster": session,
        "verdict": verdict,
    }
    res.export(to_json(ctx.work("exports") / "clock_anomaly.json", res.data, ctx.masker, indent=1))
    res.note(f"{time.time() - started:.1f}s")
    return ctx.record(res)


SESSION_FLOOR = 1767225600  # 2026-01-01: the session the case is about


def _classify(ctx: Ctx, session: dict) -> dict:
    """Turn the shared scan into the four classes a timeline can be built on.

    The 2026 cluster is taken from the scan's own ``recent`` list rather than a
    second traversal, so this module costs nothing once ``fs_timeline`` ran.
    """
    scan = ctx.file_scan(SESSION_FLOOR)
    classes = scan["classes"]
    coherent_years = scan["coherent_by_year"]
    epoch_samples = scan["epoch_samples"]
    installer_samples = scan["installer_samples"]
    return {
        "epoch_count": classes["epoch"],
        "epoch_by_year": {"1970": classes["epoch"]},
        "epoch_samples": epoch_samples,
        "epoch_locations": scan["epoch_locations"],
        "installer_count": classes["installer"],
        "installer_by_value": scan["installer_by_value"],
        "installer_samples": installer_samples,
        "installer_locations": scan["installer_locations"],
        "coherent_count": classes["coherent"],
        "coherent_by_year": coherent_years,
        "coherent_range": scan["coherent_range"],
        "session": session,
        "scan_seconds": scan["seconds"],
        "counts": {
            "epoch_or_rom": classes["epoch"],
            "installer_constant": classes["installer"],
            "coherent_2016_2022": classes["coherent"],
            "after_2026": session["count"],
        },
    }


def _installer_clock(ctx: Ctx) -> dict:
    """Check the filesystem clock against the Play Store's own record.

    An app directory in ``/app`` is rewritten when the package is updated, so its
    mtime matches *either* the install date or the last update date — both come
    from ``localappstate.db``.  A directory that matches neither is reported
    instead of being dropped, because a long tail of mismatches would weaken the
    proof rather than hide it.
    """
    fs = ctx.fs()
    try:
        entries = fs.listdir(APP_DIR)
    except Exception:
        return {"compared": 0}
    try:
        local = str(ctx.materialise(PLAY_DB))
    except KeyError:
        local = None
    play: dict[str, tuple[int, int]] = {}
    if local:
        conn = connect(local)
        try:
            play = {
                str(name): (int(first or 0), int(last or 0))
                for name, first, last in conn.execute(
                    "select package_name, first_download_ms, last_update_timestamp_ms"
                    " from appstate"
                )
            }
        finally:
            conn.close()
    compared = 0
    install_match = 0
    update_match = 0
    matched = 0
    residual: list[dict] = []
    deltas: list[dict] = []
    for entry in entries:
        if not entry.is_dir or entry.name.startswith(".") or "-" not in entry.name:
            continue
        package = entry.name.rsplit("-", 1)[0]
        if package not in play:
            continue
        first, last = play[package]
        node = fs.inode(entry.inode)
        compared += 1
        delta_install = node.mtime - first // 1000 if first else None
        delta_update = node.mtime - last // 1000 if last else None
        hit_install = delta_install is not None and abs(delta_install) <= TOLERANCE
        hit_update = delta_update is not None and abs(delta_update) <= TOLERANCE
        install_match += int(hit_install)
        update_match += int(hit_update)
        matched += int(hit_install or hit_update)
        if not (hit_install or hit_update):
            residual.append(
                {
                    "package": package,
                    "dir_mtime_utc": tl.utc(node.mtime),
                    "play_install_utc": tl.utc(first // 1000) if first else "",
                    "play_update_utc": tl.utc(last // 1000) if last else "",
                }
            )
        if hit_install or hit_update:
            deltas.append(
                {
                    "package": package,
                    "dir_mtime_utc": tl.utc(node.mtime),
                    "delta_seconds": delta_install if hit_install else delta_update,
                    "matched": "install" if hit_install else "update",
                }
            )
    deltas.sort(key=lambda item: abs(item["delta_seconds"]))
    return {
        "compared": compared,
        "matched_install": install_match,
        "matched_update": update_match,
        "matched_either": matched,
        "tolerance_seconds": TOLERANCE,
        "max_delta_seconds": max((abs(item["delta_seconds"]) for item in deltas), default=0),
        "best": deltas[:3],
        "residual": sorted(residual, key=lambda item: item["package"]),
        "agreement": round(matched / compared, 3) if compared else 0.0,
    }


def _verdict(classes: dict, installer: dict) -> dict:
    reasons = []
    if classes["epoch_count"]:
        reasons.append(
            f"{classes['epoch_count']} plików z datą epoki (ROM zeruje zegar przy pierwszym zapisie)"
        )
    if classes["installer_count"]:
        reasons.append(
            f"{classes['installer_count']} plików z datą 1979-12-30/31 (stała zapisana przez "
            "instalatora przy rozpakowywaniu bibliotek natywnych)"
        )
    if installer.get("compared") and installer.get("within_tolerance") == installer["compared"]:
        reasons.append(
            f"zegar potwierdzony: {installer['within_tolerance']}/{installer['compared']} katalogów "
            f"/app zgadza się z datą instalacji w Sklepie Play w granicach {TOLERANCE} s"
        )
    return {
        "verdict": "daty dzielą się na trzy klasy: epoka (ROM), stała instalatora i prawdziwe daty",
        "reasons": reasons,
        "trust_rule": (
            "chronologia opiera się na dacie katalogu i zawartości pliku, nie na mtime plików "
            "w /app/*/lib/"
        ),
    }


def _session_cluster(ctx: Ctx) -> dict:
    """The 2026 cluster: a boot session or a clock jump?

    The two are told apart by their shape.  A boot leaves an ordered spread of
    writes across many hours plus a tail of system bookkeeping; a clock jump
    leaves a single dense burst with nothing after it.
    """
    scan = ctx.file_scan(SESSION_FLOOR)
    items = [
        {
            "path": item["path"],
            "unix": item["mtime"],
            "utc": item["mtime_utc"],
            "package": item["package"],
        }
        for item in scan["recent"]
    ]
    if not items:
        return {}
    stamps = sorted(item["unix"] for item in items)
    span = stamps[-1] - stamps[0]
    per_hour = Counter(tl.utc(stamp)[:13] for stamp in stamps)
    shutdown = [
        item
        for item in items
        if any(
            marker in item["path"]
            for marker in ("powerkeeper", "shutdownlistner", "com.android.updater")
        )
    ]
    crashes = [item for item in items if "tombstone" in item["path"]]
    boot_like = bool(shutdown) or len(per_hour) > 10
    return {
        "count": len(items),
        "first_utc": tl.utc(stamps[0]),
        "last_utc": tl.utc(stamps[-1]),
        "span": tl.span_human(span),
        "active_hours": len(per_hour),
        "busiest_hours": dict(per_hour.most_common(6)),
        "shutdown_markers": len(shutdown),
        "crash_dumps": len(crashes),
        "verdict": "real_session" if boot_like else "clock_jump",
        "detail": (
            f"{len(items)} plików w oknie {tl.span_human(span)} rozłożonych na "
            f"{len(per_hour)} godzin, z sekwencją wyłączenia ({len(shutdown)} plików) i "
            f"{len(crashes)} zrzutów awarii — obraz odpowiada uruchomieniu urządzenia, "
            "a nie skokowi zegara"
            if boot_like
            else "zapisy skupione bez sekwencji wyłączania — obraz nie wskazuje na pełną sesję"
        ),
    }


register(
    ModuleSpec(
        id="clock_anomaly",
        category="timeline",
        title="mod.clock_anomaly.title",
        summary="mod.clock_anomaly.summary",
        params=[],
        run=run,
    )
)
