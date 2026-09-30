# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Whether the phone had a network when the image was taken.

The question has to be answered negatively, and a negative needs evidence from
several independent places: the last DHCP lease, the absence of traffic counters,
the state of the push connection, the last Google check-in, and whether the
account tokens were ever refreshed.  Any one of them alone could be explained
away; together they are a verdict.
"""

from __future__ import annotations

import time
from typing import Any

from pathlib import Path

from ...core import appdata, timeline as tl
from ...core.export import to_json
from ...core.findings import ModuleResult
from ...core.session import Ctx
from ..registry import ModuleSpec, register

DHCP_DIR = "/misc/dhcp"
NETSTATS_DIRS = ("/data/misc/netstats", "/system/netstats")
WPA_CONF = "/misc/wifi/wpa_supplicant.conf"
GCM_INFOS = "/data/com.google.android.gms/files/gcm_connection_infos"
GSF_DB = "/data/com.google.android.gsf/databases/gservices.db"
GMS_DEVICE_KEY = "/data/com.google.android.gms/files/device_key"
PLAY_LOGS = "/data/com.android.vending/cache/logs"
ACCOUNTS_DB = "/system/users/0/accounts.db"


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("net_state")
    started = time.time()
    leases = _leases(ctx)
    counters = _counters(ctx)
    wpa = _wpa(ctx)
    gcm = _gcm(ctx)
    gsf = _gsf(ctx)
    play = _play(ctx)
    tokens = _token_age(ctx)
    recent = int(params.get("recent_since") or 1767225600)
    signals = {
        "dhcp_last_lease": leases.get("newest_utc", ""),
        "netstats": counters.get("verdict", ""),
        "netstats_dirs": counters.get("dirs", []),
        "netstats_ifaces": counters.get("ifaces", []),
        "wpa_supplicant_mtime": wpa.get("mtime_utc", ""),
        "gcm_infos_mtime": gcm.get("mtime_utc", ""),
        "gcm_infos_bytes": gcm.get("size", 0),
        "gsf_last_checkin": gsf.get("mtime_utc", ""),
        "play_null_account": play.get("null_account_logs", 0),
        "play_account_logs": play.get("account_logs", 0),
        "newest_token_grant": tokens.get("newest_utc", ""),
    }
    online = _online(leases, counters, gsf, tokens, recent)
    res.add(
        "critical" if not online else "ok",
        f"Sesja sieciowa: {'brak' if not online else 'aktywna'}",
        detail=(
            f"żaden zapis uwierzytelnienia sieciowego po {tl.utc(recent)}: ostatni lease DHCP "
            f"{leases.get('newest_utc') or 'brak'}, ostatni check-in GSF "
            f"{gsf.get('mtime_utc') or 'brak'}, najnowszy grant tokenu "
            f"{tokens.get('newest_utc') or 'brak'}"
            + (
                f"; UWAGA: liczniki ruchu istnieją ({counters.get('verdict')}) — brak lease "
                "świadczy o braku sesji uwierzytelnionej, nie o braku zliczania"
                if not counters.get("missing_everywhere")
                else ""
            )
            if not online
            else f"co najmniej jeden zapis sieciowy po {tl.utc(recent)}"
        ),
        values={
            "verdict": "no_authenticated_session" if not online else "authenticated_session",
            "verdict_pl": "brak uwierzytelnionej sesji" if not online else "sesja uwierzytelniona",
            "counters_are_not_a_signal": True,
            "recent_since_utc": tl.utc(recent),
            "signal_ages_days": _ages(leases, gsf, tokens, recent),
            "signals": signals,
            "leases": leases,
            "counters": counters,
            "wpa_supplicant": wpa,
            "gcm": gcm,
            "gsf": gsf,
            "play": play,
            "token_grants": tokens,
        },
    )
    if leases.get("files"):
        res.add(
            "info",
            f"Lease'y DHCP: {len(leases['files'])} plików, najnowszy {leases['newest_utc']}",
            detail=(
                "pliki lease są binarne i należą do interfejsów, z których telefon korzystał; "
                "ich mtime to ostatni moment, gdy radium uzyskało adres"
            ),
            values={k: v for k, v in leases.items() if k != "files"} | {
                "files": leases["files"]
            },
        )
    res.add(
        "ok" if not counters.get("missing_everywhere") else "info",
        f"Liczniki ruchu: {counters.get('verdict', 'brak katalogu')}",
        detail=(
            "Android zapisuje zliczenia ruchu w dwóch miejscach; sprawdzane są oba. "
            + (
                "Obecność pliku ANET dowodzi, że zliczanie działało — nie dowodzi jednak "
                "sesji uwierzytelnionej, bo lease DHCP nie został odświeżony"
                if not counters.get("missing_everywhere")
                else "brak plików ANET w obu katalogach"
            )
        ),
        values=counters,
    )
    for item in counters.get("files", []):
        res.add(
            "finding" if item.get("ifaces") else "info",
            f"Licznik ruchu {Path(item['file']).name}"
            + (f" — interfejs {', '.join(item['ifaces'])}" if item.get("ifaces") else ""),
            detail=(
                f"format {item.get('magic')} v{item.get('version', '?')}, "
                f"zapisany {item.get('mtime_utc', '?')}, state={item.get('state')} "
                "(liczba ze struktury, bez przypisanego znaczenia)"
            ),
            values=item,
        )
    if wpa.get("networks"):
        res.add(
            "info",
            f"wpa_supplicant.conf: {wpa['networks']} zapisanych sieci, mtime {wpa['mtime_utc']}",
            detail=(
                "plik ma znacznik czasu epoki (ROM zeruje zegar przy pierwszym zapisie), więc "
                "jego treść jest aktualna, a sam mtime nie mówi nic o ostatnim użyciu"
            ),
            values=wpa,
        )
    if gcm.get("records"):
        res.add(
            "info",
            f"gcm_connection_infos: {len(gcm['records'])} zapisanych połączeń",
            detail=(
                "plik był zapisywany w 2026, ale zawiera wyłącznie identyfikatory SSID bez adresów "
                "i bez zapisanych połączeń serwera"
            ),
            values=gcm,
        )
    if gsf.get("mtime_utc"):
        res.add(
            "info",
            f"GSF: ostatni check-in {gsf['mtime_utc']}",
            detail=(
                "usługi Google nie zapisały nowego check-inu, więc nie połączyły się z serwerem; "
                f"token urządzenia {gsf.get('device_key_utc', 'brak')}"
            ),
            values=gsf,
        )
    if play:
        res.add(
            "ok" if play.get("null_account_logs") else "info",
            f"Sklep Play: {play.get('account_logs', 0)} logów konta, "
            f"{play.get('null_account_logs', 0)} logów bez konta",
            detail=(
                "Sklep Play działał lokalnie (logi z 2026), ale zapisów pod kontem Google jest więcej "
                "niż pod null_account — konto było znane sklepowi, choć lokalnie wylogowane"
            ),
            values=play,
        )
    res.data = {
        "verdict": "no_authenticated_session" if not online else "authenticated_session",
        "verdict_pl": "brak uwierzytelnionej sesji" if not online else "sesja uwierzytelniona",
        "counters_are_not_a_signal": True,
        "recent_since_utc": tl.utc(recent),
        "signal_ages_days": _ages(leases, gsf, tokens, recent),
        "signals": signals,
        "leases": leases,
        "counters": counters,
        "wpa_supplicant": wpa,
        "gcm": gcm,
        "gsf": gsf,
        "play": play,
        "token_grants": tokens,
    }
    res.export(to_json(ctx.work("exports") / "net_state.json", res.data, ctx.masker, indent=1))
    res.note(f"{time.time() - started:.1f}s")
    return ctx.record(res)


def _ages(leases: dict, gsf: dict, tokens: dict, floor: int) -> dict:
    """How long ago each network signal was written, in days."""
    out: dict[str, Any] = {}
    for name, stamp in (
        ("dhcp_lease", leases.get("newest_unix", 0)),
        ("gsf_checkin", gsf.get("mtime_unix", 0)),
        ("token_grant", tokens.get("newest_unix", 0)),
    ):
        if stamp:
            out[name] = {
                "utc": tl.utc(stamp),
                "days_before_floor": round((floor - stamp) / 86400, 1),
            }
    return out


def _online(leases: dict, counters: dict, gsf: dict, tokens: dict, floor: int) -> bool:
    """Was there an *authenticated* network session inside the window?

    The traffic counters are deliberately not a signal: their presence proves
    that the kernel was accounting for network use, not that a session was
    established.  A session shows up as a renewed DHCP lease, a Google
    check-in, or a refreshed account token — all three are dated.
    """
    return (
        leases.get("newest_unix", 0) > floor
        or gsf.get("mtime_unix", 0) > floor
        or tokens.get("newest_unix", 0) > floor
    )


def _leases(ctx: Ctx) -> dict:
    files: list[dict] = []
    try:
        entries = ctx.fs().listdir(DHCP_DIR)
    except Exception:
        return {"files": [], "verdict": f"brak katalogu {DHCP_DIR}"}
    newest = 0
    for entry in entries:
        if not entry.is_reg or not entry.name.endswith(".lease"):
            continue
        stat = ctx.fs().stat(f"{DHCP_DIR}/{entry.name}")
        files.append(
            {
                "file": f"{DHCP_DIR}/{entry.name}",
                "size": stat["size"],
                "mtime_utc": stat["mtime"],
                "interface": entry.name.split(".")[0],
                "binary": _binary(ctx, f"{DHCP_DIR}/{entry.name}"),
            }
        )
        newest = max(newest, stat["mtime_unix"])
    files.sort(key=lambda item: item["mtime_utc"])
    return {
        "files": files,
        "count": len(files),
        "newest_utc": tl.utc(newest),
        "newest_unix": newest,
        "verdict": f"najnowszy lease {tl.utc(newest)}",
    }


def _binary(ctx: Ctx, target: str) -> bool:
    try:
        blob = ctx.fs().read(target, max_bytes=512)
    except Exception:
        return False
    return appdata_is_binary(blob)


def appdata_is_binary(blob: bytes) -> bool:
    printable = sum(1 for byte in blob if 32 <= byte < 127 or byte in (9, 10, 13))
    return len(blob) and printable / len(blob) < 0.7


def _counters(ctx: Ctx) -> dict:
    """Traffic counters, in both places Android writes them.

    An earlier version of this module looked only at ``/data/misc/netstats`` and
    read its absence as proof that nothing was ever transferred.  The counters
    for this session are in ``/system/netstats`` instead, so the absence proved
    nothing; what proves the lack of a session is the DHCP lease that was never
    renewed.
    """
    dirs: list[dict] = []
    files: list[dict] = []
    for directory in NETSTATS_DIRS:
        present = True
        try:
            entries = ctx.fs().listdir(directory)
        except Exception:
            present = False
            entries = []
        found: list[dict] = []
        for entry in entries:
            if not entry.is_reg or not entry.name.startswith(("uid", "dev", "tag", "xt", "iface")):
                continue
            target = f"{directory}/{entry.name}"
            stat = ctx.fs().stat(target)
            parsed = appdata.network_stats(ctx.fs().read(target, max_bytes=65536), entry.name)
            parsed["file"] = target
            parsed["mtime_utc"] = stat["mtime_utc"]
            found.append(parsed)
        files += found
        dirs.append(
            {
                "directory": directory,
                "present": present,
                "files": len(found),
                "newest_utc": max((item.get("stamp_utc") or "" for item in found), default=""),
            }
        )
    ifaces = sorted({iface for item in files for iface in item.get("ifaces", [])})
    newest = max((item.get("stamp_ms") or 0 for item in files), default=0)
    return {
        "directories": NETSTATS_DIRS,
        "dirs": dirs,
        "files": files,
        "ifaces": ifaces,
        "newest_utc": tl.utc_ms(newest) if newest else "",
        "missing_everywhere": not files,
        "missing": not files,
        "verdict": (
            f"{len(files)} plików ANET, najnowszy {tl.utc_ms(newest) if newest else '?'}"
            if files
            else "brak plików ANET"
        ),
    }


def _wpa(ctx: Ctx) -> dict:
    from ...core import appdata

    try:
        stat = ctx.fs().stat(WPA_CONF)
        blob = ctx.fs().read(WPA_CONF, max_bytes=256 * 1024)
    except Exception:
        return {"path": WPA_CONF, "networks": 0, "verdict": "brak pliku"}
    parsed = appdata.wpa_supplicant(blob)
    return {
        "path": WPA_CONF,
        "size": stat["size"],
        "mtime_utc": stat["mtime_utc"],
        "epoch_mtime": stat["mtime_unix"] < 86400,
        "networks": len(parsed["networks"]),
        "ssids": parsed["ssids"],
        "with_psk": len(parsed["with_psk"]),
        "verdict": f"{len(parsed['networks'])} sieci zapisanych w pliku",
        "note": "klucze WPA to sekrety — ich treść podaje moduł wifi_creds (z maskowaniem)",
    }


def _gcm(ctx: Ctx) -> dict:
    out: dict = {"path": GCM_INFOS, "records": []}
    try:
        stat = ctx.fs().stat(GCM_INFOS)
        blob = ctx.fs().read(GCM_INFOS, max_bytes=4096)
    except Exception:
        return {**out, "verdict": "brak pliku"}
    out.update(
        {
            "size": stat["size"],
            "mtime_utc": stat["mtime_utc"],
            "mtime_unix": stat["mtime_unix"],
            "strings": [item for item in appdata_strings(blob) if len(item) > 3],
            "verdict": "plik zapisany, ale bez zapisanych połączeń serwera",
        }
    )
    out["records"] = [item for item in out["strings"] if "@" in item or "gcm" in item.lower()]
    return out


def appdata_strings(blob: bytes) -> list[str]:
    import re

    return [m.group().decode("ascii") for m in re.finditer(rb"[\x20-\x7e]{4,}", blob)]


def _gsf(ctx: Ctx) -> dict:
    out: dict = {}
    for key, target in (("mtime", GSF_DB), ("device_key", GMS_DEVICE_KEY)):
        try:
            stat = ctx.fs().stat(target)
        except Exception:
            continue
        out[f"{key}_utc"] = stat["mtime_utc"]
        out[f"{key}_unix"] = stat["mtime_unix"]
        out[key] = target
    if "mtime" not in out:
        out["verdict"] = f"brak {GSF_DB}"
        return out
    out["verdict"] = f"ostatni check-in {out['mtime_utc']}"
    return out


def _play(ctx: Ctx) -> dict:
    out = {"account_logs": 0, "null_account_logs": 0, "accounts": []}
    try:
        entries = ctx.fs().listdir(PLAY_LOGS)
    except Exception:
        return {}
    for entry in entries:
        if not entry.is_dir or entry.name.startswith("."):
            continue
        count = 0
        newest = 0
        for log in ctx.fs().listdir(entry.inode):
            if not log.is_reg or not log.name.endswith(".log"):
                continue
            count += 1
            stat = ctx.fs().stat(f"{PLAY_LOGS}/{entry.name}/{log.name}")
            newest = max(newest, stat["mtime_unix"])
        if not count:
            continue
        out["accounts"].append(
            {"account": entry.name, "logs": count, "newest_utc": tl.utc(newest)}
        )
        if entry.name == "null_account":
            out["null_account_logs"] = count
        else:
            out["account_logs"] += count
    out["newest_utc"] = max((item["newest_utc"] for item in out["accounts"]), default="")
    return out


def _token_age(ctx: Ctx) -> dict:
    from ...core.sqlite_tools import connect

    try:
        local = str(ctx.materialise(ACCOUNTS_DB))
    except KeyError:
        return {}
    conn = connect(local)
    try:
        rows = list(conn.execute("select key, value from extras where key like 'EXP:%'"))
    finally:
        conn.close()
    stamps = []
    for _key, value in rows:
        try:
            stamps.append(int(value))
        except (TypeError, ValueError):
            continue
    if not stamps:
        return {"count": 0, "verdict": "brak terminów ważności tokenów"}
    return {
        "count": len(stamps),
        "newest_unix": max(stamps),
        "newest_utc": tl.utc(max(stamps)),
        "oldest_utc": tl.utc(min(stamps)),
        "verdict": f"najnowszy grant {tl.utc(max(stamps))}",
    }


def _unix(text: str) -> int:
    stamp = tl.epoch_seconds(text)
    return stamp["unix"]


register(
    ModuleSpec(
        id="net_state",
        category="timeline",
        title="mod.net_state.title",
        summary="mod.net_state.summary",
        params=[],
        run=run,
    )
)
