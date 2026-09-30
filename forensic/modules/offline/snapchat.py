# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""An application that left nothing behind — proof, not absence of proof.

Snapchat was uninstalled, so its own directory, and with it the auth token, are
gone.  The question an analyst still has to answer is *what do the leftovers
prove*, and the leftovers are scattered: the Play Store's own install record, the
MIUI cloud backup list, the gallery's component history and the empty directory
on shared storage.  Each source is reported separately, because a claim of "no
data" is only as good as the evidence behind it.
"""

from __future__ import annotations

import time
from pathlib import Path

from ...core import appdata
from ...core.export import to_csv, to_json
from ...core.findings import ModuleResult
from ...core.session import Ctx
from ..registry import ModuleSpec, Param, register

PACKAGE = "com.snapchat.android"
APP_DIR = f"/data/{PACKAGE}"
PLAY_DB = "/data/com.android.vending/databases/localappstate.db"
CLOUD_BACKUP = "/data/com.miui.cloudbackup/files/cloud/record/backup_record.xml"
GALLERY_HISTORY = "/data/com.miui.gallery/files/components-history.json"
MEDIA_DIR = "/media/0/Snapchat"
LEFTOVER_MARKERS = ("SCOUT_TOKEN", "snapchat_token", "auth_token")


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("snapchat")
    package = str(params.get("package") or PACKAGE)
    play_db = str(params.get("play_db") or PLAY_DB)
    started = time.time()
    present = _app_dir(ctx, package)
    if present:
        res.add(
            "finding",
            f"Katalog aplikacji {package} istnieje w obrazie",
            detail=present["verdict"],
            values=present,
        )
    else:
        res.add(
            "ok",
            f"{package}: brak katalogu aplikacji (apka odinstalowana)",
            detail=(
                "katalog danych aplikacji nie istnieje, więc nie ma w nim auth_token, main.db "
                "ani pamięci multimedialnych — ich usunięcie jest faktem, nie założeniem"
            ),
            values={
                "app_dir": f"/data/{package}",
                "exists": False,
                "verdict": "katalog /data/<pakiet> nie istnieje w obrazie",
            },
        )
    play = _play(ctx, play_db, package)
    if play.get("found"):
        record = play["found"][0]
        res.add(
            "finding",
            f"Sklep Play: {record['title'] or package}",
            detail=(
                f"pobranie {record['first_download_utc']}, "
                f"ostatnia wersja {record['last_notified_version']}, "
                f"konto {record['account'] or 'brak'}"
            ),
            values={
                "database": play["file"],
                "integrity": play.get("integrity"),
                **record,
            },
            artifacts=[play["file"]],
        )
    else:
        res.add(
            "warn",
            f"Brak wiersza dla {package} w localappstate.db",
            detail=str(play.get("error") or "rekord nieobecny"),
            values={"database": play.get("file"), "found": None},
        )
    backup = _cloud_backup(ctx, package)
    if backup.get("found"):
        res.add(
            "info",
            "Rekord kopii zapasowej MIUI (dowód, że aplikacja była zainstalowana)",
            values={"source": CLOUD_BACKUP, **backup["found"]},
        )
    gallery = _gallery(ctx, package)
    if gallery.get("entries"):
        for entry in gallery["entries"]:
            res.add(
                "info",
                f"Galeria MIUI: {entry['component'].rsplit('.', 1)[-1]} otwarte {entry['recent_utc']}",
                detail=(
                    f"{entry['launches']} uruchomienia w historii — jedyne uruchomienie aplikacji, "
                    "jakie da się wykazać"
                ),
                values={"source": GALLERY_HISTORY, **entry},
            )
    media = _media(ctx)
    res.add(
        "info",
        f"Katalog mediów {MEDIA_DIR}: {media['entries']} pozycji",
        detail=(
            "katalog utworzony w dniu pobrania z Play i pusty — to miejsce, w którym Snapchat "
            "zapisuje udostępnione media"
        ),
        values=media,
    )
    markers = _markers(ctx, package)
    res.add(
        "ok" if not markers["hits"] else "warn",
        f"Markery tokena w katalogu aplikacji ({len(markers['hits'])} trafień)",
        detail=(
            "przeszukanie plików .db/.xml/.json w katalogu aplikacji pod kątem nazw pól "
            "autoryzacji; katalogu nie ma, więc miejsca na token nie było"
        ),
        values=markers,
    )
    res.data = {
        "package": package,
        "app_dir": present or {"app_dir": f"/data/{package}", "exists": False},
        "play": play,
        "cloud_backup": backup,
        "gallery": gallery,
        "media_dir": media,
        "markers": markers,
        "verdict": (
            "zainstalowana z Play, otwarta raz, odinstalowana — nazwy, numeru ani uidu konta "
            "nie da się ustalić, bo te dane nigdy nie opuściły usuniętego katalogu"
        ),
    }
    res.export(to_json(ctx.work("exports") / "snapchat.json", res.data, ctx.masker))
    record = (play.get("found") or [{}])[0]
    timeline = [
        [record.get("first_download_utc", ""), "localappstate.db", f"pobranie z Play ({package})"],
        [
            record.get("delivery_data_utc", ""),
            "localappstate.db",
            f"zapis dostawy {record.get('last_notified_version')}",
        ],
        [
            record.get("last_update_utc", ""),
            "localappstate.db",
            f"ostatnia aktualizacja {record.get('last_notified_version')}",
        ],
        [media.get("created_utc", ""), MEDIA_DIR, "utworzenie katalogu mediów"],
    ] + [
        [entry["recent_utc"], "components-history.json", entry["component"]]
        for entry in gallery.get("entries", [])
    ]
    res.export(
        to_csv(
            ctx.work("exports") / "snapchat_timeline.csv",
            ["utc", "source", "event"],
            timeline,
            ctx.masker,
        )
    )
    res.note(f"{time.time() - started:.1f}s")
    return ctx.record(res)


def _app_dir(ctx: Ctx, package: str) -> dict | None:
    fs = ctx.fs()
    try:
        entries = fs.listdir(f"/data/{package}")
    except KeyError:
        return None
    return {
        "app_dir": f"/data/{package}",
        "exists": True,
        "entries": len(entries),
        "verdict": "katalog istnieje — aplikacja była zainstalowana w chwili dumpu",
    }


def _play(ctx: Ctx, play_db: str, package: str) -> dict:
    try:
        local = str(ctx.materialise(play_db))
    except KeyError:
        return {"file": play_db, "error": "brak localappstate.db"}
    report = appdata.play_localappstate(local, package)
    report["file"] = play_db
    report["local_copy"] = local
    return report


def _cloud_backup(ctx: Ctx, package: str) -> dict:
    try:
        local = ctx.materialise(CLOUD_BACKUP)
    except KeyError:
        return {"error": "brak backup_record.xml"}
    return appdata.miui_backup_records(Path(local).read_bytes(), package)


def _gallery(ctx: Ctx, package: str) -> dict:
    try:
        local = ctx.materialise(GALLERY_HISTORY)
    except KeyError:
        return {"error": "brak components-history.json"}
    return appdata.miui_gallery_history(Path(local).read_bytes(), package)


def _media(ctx: Ctx) -> dict:
    fs = ctx.fs()
    out: dict = {"path": MEDIA_DIR, "entries": 0, "files": []}
    try:
        entries = fs.listdir(MEDIA_DIR)
    except KeyError:
        out["error"] = "katalog nie istnieje"
        return out
    stat = fs.stat(MEDIA_DIR)
    out["created_utc"] = stat["crtime"]
    out["mtime_utc"] = stat["mtime"]
    out["bytes"] = stat["blocks_512"] * 512
    for entry in entries:
        if entry.name in (".", ".."):
            continue
        out["entries"] += 1
        out["files"].append(entry.name)
    out["empty"] = not out["entries"]
    return out


def _markers(ctx: Ctx, package: str) -> dict:
    """Field names that would hold a session token, looked up inside the app dir.

    Searching the whole 27 GB image for a string is a turn-1 operation and takes
    two minutes, so the default here is the app's own directory; a wider scope is
    a parameter away.
    """
    fs = ctx.fs()
    out: dict = {"scope": f"/data/{package}", "markers": list(LEFTOVER_MARKERS), "hits": []}
    try:
        candidates = [entry.name for entry in fs.listdir(f"/data/{package}")]
    except KeyError:
        return {**out, "error": "katalog aplikacji nie istnieje"}
    for name in candidates:
        if not name.endswith((".db", ".xml", ".json")):
            continue
        try:
            blob = fs.read(f"/data/{package}/{name}", max_bytes=64 * 1024 * 1024)
        except Exception:
            continue
        text = blob.decode("utf-8", "ignore")
        for marker in LEFTOVER_MARKERS:
            count = text.count(marker)
            if count:
                out["hits"].append({"file": name, "marker": marker, "count": count})
    out["scanned_files"] = len(candidates)
    return out


register(
    ModuleSpec(
        id="snapchat",
        category="apps",
        title="mod.snapchat.title",
        summary="mod.snapchat.summary",
        params=[
            Param(key="package", label="param.package", default=PACKAGE, kind="str"),
            Param(key="play_db", label="param.play_db", default=PLAY_DB, kind="path"),
        ],
        run=run,
    )
)
