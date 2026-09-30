# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""When each application arrived on the device, and what it left in the store.

The Play Store's ``localappstate.db`` is the only place that records an install
*date* rather than a directory timestamp, so it is the backbone of this timeline.
It is joined with the system package usage list (when the app was last run) and
with the packages still present in the image, which is what makes an uninstall
visible as a gap rather than as silence.
"""

from __future__ import annotations

import time

from ...core import appdata
from ...core.export import to_csv, to_json
from ...core.findings import ModuleResult
from ...core.session import Ctx
from ..registry import ModuleSpec, Param, register

PLAY_DB = "/data/com.android.vending/databases/localappstate.db"
USAGE_LIST = "/system/package-usage.list"
PLAY_DIR = "/data/com.android.vending"


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("app_install_timeline")
    play_db = str(params.get("play_db") or PLAY_DB)
    package = str(params.get("package") or "")
    include_usage = bool(params.get("usage_list", True))
    started = time.time()
    try:
        local = str(ctx.materialise(play_db))
    except KeyError:
        res.add("warn", f"Brak ścieżki w obrazie: {play_db}")
        return ctx.record(res)
    except FileNotFoundError as exc:
        res.add("critical", "Brak obrazu", detail=str(exc))
        return ctx.record(res)
    report = appdata.play_localappstate(local, package)
    apps = report.get("apps", [])
    if not apps:
        res.add(
            "warn",
            "localappstate.db: brak tabeli appstate albo brak wierszy",
            detail=str(report.get("error") or "0 wierszy"),
            values={"database": local, "integrity": report.get("integrity")},
        )
        return ctx.record(res)
    res.add(
        "ok",
        f"Sklep Play: {report['rows']} aplikacji w localappstate.db",
        detail=(
            f"konta użyte do instalacji: {', '.join(report['accounts']) or 'brak'}; "
            f"lata pobrań: {', '.join(f'{k} ({v})' for k, v in report['by_year'].items())}"
        ),
        values={
            "database": local,
            "integrity": report.get("integrity"),
            "rows": report["rows"],
            "by_year": report["by_year"],
            "accounts": report["accounts"],
            "with_title": sum(1 for app in apps if app["title"]),
            "with_referrer": sum(1 for app in apps if app["referrer"]),
        },
        artifacts=[local],
    )
    usage = _usage(ctx) if include_usage else []
    usage_by_package = {item["package"]: item for item in usage}
    data_dirs = _data_dirs(ctx)
    joined = []
    for app in apps:
        name = app["package_name"]
        entry = dict(app)
        entry["data_dir_present"] = name in data_dirs
        entry["usage_list_entry"] = name in usage_by_package
        entry["usage_last_used_utc"] = usage_by_package.get(name, {}).get("last_used_utc", "")
        entry["state"] = "data_dir_present" if entry["data_dir_present"] else "no_data_dir"
        joined.append(entry)
    joined.sort(key=lambda item: (not item["first_download_ms"], item["first_download_ms"]))
    present = [item for item in joined if item["data_dir_present"]]
    gone = [item for item in joined if not item["data_dir_present"]]
    gone_still_listed = [item for item in gone if item["usage_list_entry"]]
    res.add(
        "info" if gone else "ok",
        f"Zgodność rekordu Sklepu Play z dyskiem: {len(present)} z katalogiem, {len(gone)} bez",
        detail=(
            "brak katalogu /data/<pakiet> oznacza, że aplikacja nie jest zainstalowana w tym "
            "użytkowniku. " + _usage_sentence(gone_still_listed)
        ),
        values={
            "data_dir_present": len(present),
            "without_data_dir": len(gone),
            "without_data_dir_but_in_usage_list": len(gone_still_listed),
            "without_data_dir_packages": [item["package_name"] for item in gone],
        },
    )
    latest = [item for item in joined if item["first_download_utc"]][-10:]
    for item in reversed(latest):
        res.add(
            "info",
            f"{item['package_name']} — {item['first_download_utc'][:10]}",
            detail=(
                f"{item['title'] or 'bez tytułu'}; wersja {item['last_notified_version']}, "
                f"źródło: {item['referrer'] or 'bez referrera'} (konto {item['account'] or 'brak'})"
            ),
            values=item,
        )
    if package and not report.get("found"):
        res.add(
            "info",
            f"Brak rekordu dla {package}",
            detail=(
                "pakiet nie występuje w localappstate.db — nie był instalowany ze Sklepu Play "
                "(albo zapis wygasł)"
            ),
            values={"package": package, "found": None},
        )
    res.data = {
        "database": play_db,
        "integrity": report.get("integrity"),
        "rows": report["rows"],
        "by_year": report["by_year"],
        "accounts": report["accounts"],
        "apps": joined,
        "usage": usage,
        "data_dirs": sorted(data_dirs),
        "data_dir_present": len(present),
        "without_data_dir": len(gone),
        "without_data_dir_but_in_usage_list": len(gone_still_listed),
        "usage_list_entries": len(usage),
        "selected_package": package,
    }
    res.export(to_json(ctx.work("exports") / "app_install_timeline.json", res.data, ctx.masker))
    res.export(
        to_csv(
            ctx.work("exports") / "app_install_timeline.csv",
            [
                "package_name",
                "title",
                "first_download_utc",
                "last_update_utc",
                "last_notified_version",
                "account",
                "referrer",
                "usage_last_used_utc",
                "data_dir_present",
            ],
            [
                [
                    item["package_name"],
                    item["title"],
                    item["first_download_utc"],
                    item["last_update_utc"],
                    item["last_notified_version"],
                    item["account"],
                    item["referrer"],
                    item["usage_last_used_utc"],
                    "tak" if item["data_dir_present"] else "nie",
                ]
                for item in joined
            ],
            ctx.masker,
        )
    )
    res.note(f"{time.time() - started:.1f}s")
    return ctx.record(res)


def _usage(ctx: Ctx) -> list[dict]:
    try:
        blob = ctx.fs().read(USAGE_LIST)
    except Exception:
        return []
    return appdata.package_usage(blob)


NON_PACKAGE_DIRS = {"media", "misc", "system", "app", "cache", "data", "sdcard"}


def _usage_sentence(still_listed: list[dict]) -> str:
    count = len(still_listed)
    if not count:
        return (
            "Żadna z nich nie figuruje już w package-usage.list, więc zniknęła również "
            "z pamięci systemu pakietów."
        )
    names = ", ".join(item["package_name"] for item in still_listed[:5])
    return (
        f"{count} z nich nadal figuruje w package-usage.list ({names}"
        f"{'…' if count > 5 else ''}), więc system pakietów nadal o nich pamięta."
    )


def _data_dirs(ctx: Ctx) -> set[str]:
    """Directories in ``/data`` that are named like a package.

    A package name is a dotted, lower-case identifier; ``com.android.vending``
    and ``pl.tajchert.canary`` both qualify, so filtering on a single prefix
    would silently drop half of the non-Google apps.
    """
    out: set[str] = set()
    try:
        entries = ctx.fs().listdir("/data")
    except Exception:
        return out
    for entry in entries:
        name = entry.name
        if name.startswith(".") or name in NON_PACKAGE_DIRS or not entry.is_dir:
            continue
        if "." in name and " " not in name and name.replace(".", "").replace("_", "").isalnum():
            out.add(name)
    return out


register(
    ModuleSpec(
        id="app_install_timeline",
        category="apps",
        title="mod.app_install_timeline.title",
        summary="mod.app_install_timeline.summary",
        params=[
            Param(key="play_db", label="param.play_db", default=PLAY_DB, kind="path"),
            Param(key="package", label="param.package", default="", kind="str"),
            Param(key="usage_list", label="param.usage_list", default=True, kind="bool"),
        ],
        run=run,
    )
)
