# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Messenger (com.facebook.orca): which local store holds the conversations.

The interesting question in a Messenger directory is not "how many databases
are there" but *which* one survived with text in it.  This module answers that:
it walks the app directory, opens the candidates one by one and reports a
verdict per database — message text present, empty, or encrypted — together with
the account, the login marker and the end-to-end encryption state.
"""

from __future__ import annotations

import time
from pathlib import Path

from ...core import appdata
from ...core.export import human_bytes, to_csv, to_json
from ...core.findings import ModuleResult
from ...core.masking import token_of
from ...core.session import Ctx
from ..registry import ModuleSpec, Param, register

APP_DIR = "/data/com.facebook.orca"
DATABASES = f"{APP_DIR}/databases"
MEDIA_DIRS = (
    f"{APP_DIR}/cache/image",
    f"{APP_DIR}/files/stickers",
    f"{APP_DIR}/files/audio",
    f"{APP_DIR}/app_image",
    f"{APP_DIR}/files/encrypted_attachments",
    f"{APP_DIR}/files/SavedVideos",
)
THREADS_DB = f"{DATABASES}/threads_db2"
PREFS_DB = f"{DATABASES}/prefs_db"
ACCOUNT_PREFIX = "/orca_accounts/saved_"


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("messenger")
    app_dir = str(params.get("app_dir") or APP_DIR)
    limit = int(params.get("limit") or 50)
    started = time.time()
    try:
        inventory = _inventory(ctx, app_dir)
    except KeyError:
        res.add("warn", f"Brak katalogu aplikacji w obrazie: {app_dir}")
        return ctx.record(res)
    except FileNotFoundError as exc:
        res.add("critical", "Brak obrazu", detail=str(exc))
        return ctx.record(res)
    res.add(
        "ok",
        f"messenger: {inventory['files']} plików, {human_bytes(inventory['bytes'])}",
        values={
            "app_dir": app_dir,
            "files": inventory["files"],
            "dirs": inventory["dirs"],
            "bytes": inventory["bytes"],
            "bytes_human": human_bytes(inventory["bytes"]),
            "databases": inventory["databases"],
            "largest": inventory["largest"][:8],
        },
    )
    media = _media(ctx)
    if media["files"]:
        res.add(
            "info",
            f"Media w katalogu aplikacji: {media['files']} plików ({human_bytes(media['bytes'])})",
            values={**media, "by_extension": media["by_extension"]},
        )
    threads = _local_store(ctx)
    if threads.get("error") or not threads.get("counts", {}).get("messages"):
        res.add(
            "warn",
            "threads_db2: brak odczytywalnych wiadomości",
            detail=threads.get("error") or str(threads.get("counts")),
            values=threads,
        )
    else:
        res.add(
            "finding",
            f"threads_db2: {threads['messages_total']} wiadomości, "
            f"{threads.get('with_text', 0)} z tekstem",
            detail=(
                f"okno rozmów {threads['plausible_range_utc'][0]} → {threads['plausible_range_utc'][1]}, "
                f"{threads.get('with_attachments', 0)} z załącznikami, "
                f"{threads.get('zero_timestamps', 0)} rekordów bez znacznika czasu, "
                f"{threads.get('implausible_timestamps', 0)} rekordów sprzed 2015 (nieprawdopodobne)"
            ),
            values={
                "database": threads["file"],
                "integrity": threads.get("integrity"),
                "threads": threads["counts"].get("threads"),
                "messages": threads["messages_total"],
                "with_text": threads.get("with_text"),
                "with_attachments": threads.get("with_attachments"),
                "participants": threads["counts"].get("thread_participants"),
                "contacts": threads["counts"].get("thread_users"),
                "reactions": threads["counts"].get("message_reactions"),
                "first_message_utc": threads.get("first_message_utc"),
                "last_message_utc": threads.get("last_message_utc"),
                "plausible_range_utc": threads.get("plausible_range_utc"),
                "implausible_timestamps": threads.get("implausible_timestamps"),
                "implausible_before": threads.get("implausible_before"),
                "zero_timestamps": threads.get("zero_timestamps"),
            },
            artifacts=[threads["file"]],
        )
        for thread in threads.get("threads", [])[:limit]:
            res.add(
                "info",
                f"Rozmowa: {thread['name'] or thread['thread_key']}",
                detail=f"ostatnia wiadomość {thread['last_message_utc']}, nieprzeczytanych: {thread['unread']}",
                values=thread,
            )
    prefs = _prefs(ctx)
    if prefs.get("accounts"):
        res.add(
            "finding" if len(prefs["accounts"]) > 1 else "ok",
            f"Zapisane konta Messengera: {len(prefs['accounts'])}",
            detail=(
                "ostatnie udane logowanie: "
                f"{prefs.get('last_login_utc') or 'brak znacznika'}"
            ),
            values={
                "database": prefs["file"],
                "accounts": [
                    {
                        "uid": item["uid"],
                        "name": item["name"],
                        "kind": item["kind"],
                        "last_logout_utc": item["last_logout_utc"],
                        "last_unseen_utc": item["last_unseen_utc"],
                        "has_access_token": bool(item["access_token"]),
                    }
                    for item in prefs["accounts"]
                ],
                "last_login_utc": prefs.get("last_login_utc"),
                "machine_id": prefs.get("machine_id", ""),
            },
            artifacts=[prefs["file"]],
        )
    msys = _msys(ctx)
    for store in msys:
        if store.get("encrypted"):
            res.add(
                "info",
                f"msys_database zaszyfrowany: {Path(store['target']).name}",
                detail=store["verdict"],
                values={"database": store["target"], "size": store["size"]},
            )
            continue
        for identity in store.get("identities", []):
            res.add(
                "critical" if identity["private_key_present"] else "info",
                f"Klucze E2EE (local_registration_id {identity['local_registration_id']})",
                detail=(
                    "para kluczy prywatnych jest zapisana lokalnie — zaszyfrowane rozmowy "
                    "da się odszyfrować (klucze maskuje raport)"
                    if identity["private_key_present"]
                    else "brak blobów prywatnych"
                ),
                values={
                    **identity,
                    "identity_key_private": "***" if identity["private_key_present"] else None,
                    "wcc_client_key_private": "***" if identity["wcc_client_key_private_bytes"] else None,
                    "database": store["target"],
                },
            )
        for token in store.get("auth_tokens", []):
            expired = token["expires_unix"] and token["expires_unix"] < time.time()
            res.add(
                "info",
                f"crypto_auth_token ({token['verifier_id']}) wygasł {token['expires_utc']}",
                detail="to czas wygaśnięcia zapisanego tokenu autoryzacji, nie czas logowania",
                values={
                    **token,
                    "expired": bool(expired),
                    "session_id": token_of(token["session_id"]) if token["session_id"] else "",
                },
            )
        res.add(
            "info",
            f"msys_database: {store.get('integrity', '?')}",
            detail=store.get("verdict", ""),
            values={
                "database": store["target"],
                "tables_with_data": store.get("tables_present", []),
                "counts": store.get("counts", {}),
                "verdict": store.get("verdict", ""),
            },
            artifacts=[store["file"]],
        )
    tincan = _tincan(ctx)
    if tincan:
        res.add(
            "info" if tincan["non_empty"] else "ok",
            f"tincan_db: {tincan.get('integrity', '?')}",
            detail=tincan.get("verdict", ""),
            values={"database": tincan["file"], "non_empty": tincan["non_empty"]},
            artifacts=[tincan["file"]],
        )
    res.data = {
        "app_dir": app_dir,
        "inventory": inventory,
        "media": media,
        "threads": threads,
        "prefs": _mask_prefs(prefs),
        "msys": _mask_msys(msys),
        "tincan": tincan,
    }
    res.export(to_json(ctx.work("exports") / "messenger.json", res.data, ctx.masker))
    res.export(
        to_csv(
            ctx.work("exports") / "messenger_threads.csv",
            ["thread_key", "name", "messages", "unread", "last_message_utc", "snippet"],
            [
                [
                    item["thread_key"],
                    item["name"],
                    item["messages"],
                    item["unread"],
                    item["last_message_utc"],
                    item["snippet"],
                ]
                for item in threads.get("threads", [])
            ],
            ctx.masker,
        )
    )
    res.export(
        to_csv(
            ctx.work("exports") / "messenger_accounts.csv",
            ["uid", "name", "kind", "last_logout_utc", "last_unseen_utc", "has_access_token"],
            [
                [
                    item["uid"],
                    item["name"],
                    item["kind"],
                    item["last_logout_utc"],
                    item["last_unseen_utc"],
                    "tak" if item["access_token"] else "nie",
                ]
                for item in prefs.get("accounts", [])
            ],
            ctx.masker,
        )
    )
    res.note(f"{time.time() - started:.1f}s")
    return ctx.record(res)


def _mask_prefs(prefs: dict) -> dict:
    """The account list carries live access tokens; the export must not."""
    out = dict(prefs)
    out["accounts"] = [
        {**item, "access_token": token_of(item["access_token"]) if item.get("access_token") else ""}
        for item in prefs.get("accounts", [])
    ]
    return out


def _mask_msys(stores: list[dict]) -> list[dict]:
    out: list[dict] = []
    for store in stores:
        item = dict(store)
        item["auth_tokens"] = [
            {**token, "session_id": token_of(token["session_id"]) if token.get("session_id") else ""}
            for token in store.get("auth_tokens", [])
        ]
        out.append(item)
    return out


def _inventory(ctx: Ctx, app_dir: str) -> dict:
    fs = ctx.fs()
    files = 0
    dirs = 0
    total = 0
    databases = 0
    largest: list[dict] = []
    for path, entry in fs.walk(app_dir):
        node = fs.inode(entry.inode)
        if entry.is_dir:
            dirs += 1
            continue
        files += 1
        total += node.size
        if path.startswith(f"{app_dir}/databases/"):
            databases += 1
        largest.append({"path": path, "bytes": node.size})
    largest.sort(key=lambda item: -item["bytes"])
    return {
        "files": files,
        "dirs": dirs,
        "bytes": total,
        "databases": databases,
        "largest": largest[:12],
    }


def _media(ctx: Ctx) -> dict:
    fs = ctx.fs()
    per_dir: dict[str, int] = {}
    files = 0
    total = 0
    paths: list[str] = []
    for folder in MEDIA_DIRS:
        try:
            entries = list(fs.listdir(folder))
        except Exception:
            continue
        for entry in entries:
            if entry.is_dir:
                continue
            node = fs.inode(entry.inode)
            files += 1
            total += node.size
            per_dir[folder] = per_dir.get(folder, 0) + 1
            paths.append(path_of(folder, entry.name))
    return {
        "files": files,
        "bytes": total,
        "by_dir": per_dir,
        "by_extension": appdata.media_inventory(paths) if paths else {},
    }


def path_of(folder: str, name: str) -> str:
    return f"{folder.rstrip('/')}/{name}"


def _open_db(ctx: Ctx, target: str) -> str | None:
    try:
        return str(ctx.materialise(target))
    except KeyError:
        return None


def _local_store(ctx: Ctx) -> dict:
    local = _open_db(ctx, THREADS_DB)
    if not local:
        return {"error": f"brak {THREADS_DB}"}
    return appdata.messenger_threads_db(local)


def _prefs(ctx: Ctx) -> dict:
    local = _open_db(ctx, PREFS_DB)
    if not local:
        return {"error": f"brak {PREFS_DB}"}
    return appdata.messenger_prefs_db(local)


def _msys(ctx: Ctx) -> list[dict]:
    fs = ctx.fs()
    found: list[dict] = []
    try:
        entries = fs.listdir(DATABASES)
    except Exception:
        return []
    for entry in entries:
        if not entry.name.startswith("msys_database"):
            continue
        target = f"{DATABASES}/{entry.name}"
        node = fs.inode(entry.inode)
        local = _open_db(ctx, target)
        if not local:
            continue
        # Ten werdykt jest kosztowny w skutkach: „zaszyfrowany" kieruje
        # analityka do szukania klucza, więc nie opiera się na jednej regule.
        # Libmagic dostaje cały plik, bo nagłówek SQLite leży w pierwszych
        # 16 bajtach, a dla pliku zaszyfrowanego żadna etykieta nie zarzuci
        # nam fałszywej pewności.
        verdict = appdata.classify_checked(Path(local).read_bytes())
        if verdict["report"] != "sqlite":
            found.append(
                {
                    "file": local,
                    "target": target,
                    "size": node.size,
                    "encrypted": True,
                    "verdict": "plik zaszyfrowany (brak sygnatury SQLite) — bez klucza nie do odczytu",
                    "format_ours": verdict["format"],
                    "format_magic": verdict["magic"],
                    "format_magic_raw": verdict["magic_raw"],
                    "format_note": verdict["note"],
                }
            )
            continue
        report = appdata.messenger_msys(local)
        report["target"] = target
        report["size"] = node.size
        found.append(report)
    found.sort(key=lambda item: -(item.get("counts", {}).get("contacts", 0) or 0))
    return found


def _tincan(ctx: Ctx) -> dict:
    fs = ctx.fs()
    candidates: list[dict] = []
    try:
        entries = fs.listdir(DATABASES)
    except Exception:
        return {}
    for entry in entries:
        if not entry.name.startswith("tincan_db"):
            continue
        local = _open_db(ctx, f"{DATABASES}/{entry.name}")
        if not local:
            continue
        report = appdata.messenger_tincan(local)
        report["target"] = f"{DATABASES}/{entry.name}"
        report["size"] = fs.inode(entry.inode).size
        report["_sort"] = (
            -len(report.get("non_empty", {})),
            -report["size"],
            len(entry.name),
            entry.name,
        )
        candidates.append(report)
    if not candidates:
        return {}
    return min(candidates, key=lambda item: item["_sort"])


register(
    ModuleSpec(
        id="messenger",
        category="apps",
        title="mod.messenger.title",
        summary="mod.messenger.summary",
        params=[
            Param(key="app_dir", label="param.app_dir", default=APP_DIR, kind="path"),
            Param(key="limit", label="param.limit", default=50, kind="int"),
        ],
        run=run,
    )
)
