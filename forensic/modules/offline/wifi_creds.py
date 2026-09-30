# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""WiFi credentials left on the device, from both places Android keeps them.

Two independent stores hold the same secrets: the Settings database, which on
this Android version keeps pre-shared keys in the clear, and
``wpa_supplicant.conf``.  Reading both and comparing them is the point — a value
in one store and not the other means something removed it, and a value in
neither means the key was never saved on this device.
"""

from __future__ import annotations

import time

from ...core import appdata
from ...core.export import to_csv, to_json
from ...core.findings import ModuleResult
from ...core.masking import secret_of
from ...core.session import Ctx
from ..registry import ModuleSpec, Param, register

WIFI_DB = "/data/com.android.settings/databases/wifi_settings.db"
WPA_CONF = "/misc/wifi/wpa_supplicant.conf"
WIFI_DIR = "/misc/wifi"


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("wifi_creds")
    db_path = str(params.get("path") or WIFI_DB)
    conf_path = str(params.get("supplicant") or WPA_CONF)
    started = time.time()
    database = _database(ctx, db_path)
    conf = _supplicant(ctx, conf_path)
    if not database and not conf:
        res.add("warn", f"Brak {db_path} i {conf_path} w obrazie")
        return ctx.record(res)
    merged = _merge(database, conf)
    with_psk = [item for item in merged if item["psk"]]
    res.add(
        "critical" if with_psk else "warn",
        f"Zapisane sieci WiFi z kluczem w jawnej postaci: {len(with_psk)}",
        detail=(
            f"SSID: {', '.join(item['ssid'] for item in merged) or 'brak'}; "
            f"Android 7 nie szyfruje kluczy WPA-Personal w bazie Ustawień ani w supplicant"
        ),
        values={
            "networks": len(merged),
            "with_psk": len(with_psk),
            "ssids": [item["ssid"] for item in merged],
            "sources": sorted({src for item in merged for src in item["sources"]}),
            "distinct_psks": len({item["psk"] for item in with_psk}),
            "without_psk": [item["ssid"] for item in merged if not item["psk"]],
            "account": database.get("accounts", []),
        },
    )
    for item in with_psk:
        res.add(
            "critical",
            f"SSID {item['ssid']} — klucz WPA w jawnej postaci",
            detail=(
                f"znaleziony w: {', '.join(item['sources'])}; "
                f"{item['length']} znaków, zapisany jako {'obecny' if item['has_both'] else 'częściowo'}"
            ),
            values={
                "ssid": item["ssid"],
                "psk": wifi_secret(item["psk"]),
                "length": item["length"],
                "sources": item["sources"],
                "bssids": item["bssids"],
                "account": item["account"],
                "has_both": item["has_both"],
            },
        )
    if database.get("sync"):
        res.add(
            "info",
            "wifi_sync: konto powiązane z synchronizacją sieci",
            detail=(
                "identyfikator konta jest zapisany w bazie Ustawień; blob sync_extra_info ma "
                f"{database['sync'][0].get('sync_extra_info_bytes', 0)} znaków i nie daje się "
                "odczytać bez schemy protokołu"
            ),
            values={
                "sync": [
                    {
                        "account_name": item.get("account_name"),
                        "marker": item.get("marker"),
                        "sync_extra_info_bytes": item.get("sync_extra_info_bytes"),
                        "sync_extra_info_decodable": item.get("sync_extra_info_decodable"),
                    }
                    for item in database["sync"]
                ]
            },
        )
    if conf:
        res.add(
            "info",
            f"{conf_path}: {len(conf['networks'])} sieci w pliku konfiguracyjnym",
            detail=(
                f"mtime {conf['mtime_utc']}"
                + (
                    " (znacznik czasu epoki — ROM zeruje zegar, więc plik nie datuje ostatniego użycia)"
                    if conf["epoch_mtime"]
                    else ""
                )
                + f"; hostname '{conf['device']}'"
            ),
            values={
                "path": conf_path,
                "networks": len(conf["networks"]),
                "ssids": conf["ssids"],
                "mtime_utc": conf["mtime_utc"],
                "epoch_mtime": conf["epoch_mtime"],
                "device": conf["device"],
                "model": conf["model"],
                "serial": conf["serial"],
                "size": conf["size"],
            },
        )
    others = _other_files(ctx)
    if others:
        res.add(
            "info",
            f"Pozostałe pliki w {WIFI_DIR}: {len(others)}",
            detail="sprawdzone pod kątem innych zapisanych sieci",
            values={"files": others},
        )
    exported = [
        {**item, "psk": wifi_secret(item["psk"])}
        if item["psk"]
        else item
        for item in merged
    ]
    res.data = {
        "database": _mask_database(database),
        "supplicant": _mask_supplicant(conf),
        "networks": exported,
        "with_psk": len(with_psk),
        "other_files": others,
        "verdict": (
            f"{len(with_psk)} kluczy WPA w jawnej postaci"
            if with_psk
            else "brak kluczy WPA w jawnym zapisie"
        ),
    }
    res.export(to_json(ctx.work("exports") / "wifi_creds.json", res.data, ctx.masker, indent=1))
    res.export(
        to_csv(
            ctx.work("exports") / "wifi_creds.csv",
            ["ssid", "psk", "sources", "bssids", "account"],
            [
                [
                    item["ssid"],
                    wifi_secret(item["psk"])
                    if item["psk"]
                    else "",
                    ", ".join(item["sources"]),
                    "; ".join(item["bssids"]),
                    item["account"],
                ]
                for item in merged
            ],
            ctx.masker,
        )
    )
    res.note(f"{time.time() - started:.1f}s")
    return ctx.record(res)


def wifi_secret(value: str):
    """A WPA pre-shared key, wrapped and registered in one step."""
    return secret_of(value, kind="wifi-psk", keep_head=0, keep_tail=2)


def _database(ctx: Ctx, db_path: str) -> dict:
    try:
        local = str(ctx.materialise(db_path))
    except KeyError:
        return {}
    report = appdata.wifi_settings(local)
    report["path"] = db_path
    try:
        stat = ctx.fs().stat(db_path)
        report["mtime_utc"] = stat["mtime_utc"]
        report["crtime_utc"] = stat["crtime_utc"]
    except Exception:
        pass
    return report


def _supplicant(ctx: Ctx, conf_path: str) -> dict:
    try:
        blob = ctx.fs().read(conf_path, max_bytes=512 * 1024)
        stat = ctx.fs().stat(conf_path)
    except Exception:
        return {}
    parsed = appdata.wpa_supplicant(blob)
    globals_ = parsed["globals"]
    mtime = stat["mtime_unix"]
    return {
        "path": conf_path,
        "size": stat["size"],
        "mtime_utc": stat["mtime_utc"],
        "epoch_mtime": mtime < 86400,
        "networks": parsed["networks"],
        "ssids": parsed["ssids"],
        "with_psk": len(parsed["with_psk"]),
        "device": globals_.get("device_name", ""),
        "model": globals_.get("model_name", ""),
        "serial": globals_.get("serial_number", ""),
        "globals": globals_,
    }


def _mask_database(database: dict) -> dict:
    out = dict(database)
    out["networks"] = [
        {**item, "psk": wifi_secret(item["psk"])}
        if item.get("psk")
        else item
        for item in database.get("networks", [])
    ]
    out["distinct_psk"] = len({item["psk"] for item in database.get("with_psk", [])})
    out.pop("with_psk", None)
    out.pop("distinct_psks", None)
    return out


def _mask_supplicant(conf: dict) -> dict:
    """The parsed blocks carry PSKs; the export keeps the shape, not the keys."""
    out = dict(conf)
    out["networks"] = len(conf.get("networks", []))
    out.pop("globals", None)
    return out


def _merge(database: dict, conf: dict) -> list[dict]:
    """One row per SSID, with the sources that carry it and the key they hold."""
    out: dict[str, dict] = {}
    for item in database.get("networks", []):
        ssid = item.get("ssid") or ""
        if not ssid:
            continue
        row = out.setdefault(
            ssid,
            {
                "ssid": ssid,
                "psk": "",
                "length": 0,
                "sources": [],
                "bssids": [],
                "account": "",
                "has_both": False,
            },
        )
        row["sources"].append("wifi_settings.db")
        if item.get("psk") and not row["psk"]:
            row["psk"] = item["psk"]
            row["length"] = len(item["psk"])
        if item.get("bssid") and item["bssid"] != "restore":
            row["bssids"].append(item["bssid"])
        if item.get("account"):
            row["account"] = item["account"]
    for item in conf.get("networks", []):
        ssid = item.get("ssid") or ""
        if not ssid:
            continue
        row = out.setdefault(
            ssid,
            {
                "ssid": ssid,
                "psk": "",
                "length": 0,
                "sources": [],
                "bssids": [],
                "account": "",
                "has_both": False,
            },
        )
        if "wpa_supplicant.conf" not in row["sources"]:
            row["sources"].append("wpa_supplicant.conf")
        if item.get("psk") and not row["psk"]:
            row["psk"] = item["psk"]
            row["length"] = len(item["psk"])
    for row in out.values():
        row["sources"] = sorted(set(row["sources"]))
        row["has_both"] = len(row["sources"]) > 1 and bool(row["psk"])
        row["bssids"] = sorted(set(row["bssids"]))
    return sorted(out.values(), key=lambda item: item["ssid"])


def _other_files(ctx: Ctx) -> list[dict]:
    out: list[dict] = []
    try:
        entries = ctx.fs().listdir(WIFI_DIR)
    except Exception:
        return out
    for entry in entries:
        if not entry.is_reg or entry.name in ("wpa_supplicant.conf", "p2p_supplicant.conf"):
            continue
        stat = ctx.fs().stat(f"{WIFI_DIR}/{entry.name}")
        out.append(
            {"file": f"{WIFI_DIR}/{entry.name}", "size": stat["size"], "mtime_utc": stat["mtime"]}
        )
    out.sort(key=lambda item: item["file"])
    return out


register(
    ModuleSpec(
        id="wifi_creds",
        category="timeline",
        title="mod.wifi_creds.title",
        summary="mod.wifi_creds.summary",
        params=[
            Param(key="path", label="param.path", default=WIFI_DB, kind="path"),
            Param(key="supplicant", label="param.supplicant", default=WPA_CONF, kind="path"),
        ],
        run=run,
    )
)
