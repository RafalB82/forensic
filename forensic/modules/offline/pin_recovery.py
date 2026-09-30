# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Lock-screen recovery: read locksettings, derive the salt, search the PIN space.

The module is honest about what it does: it reproduces the AOSP hash
construction and searches the digit space offline.  The recovered PIN is treated
like any other secret, so it is masked in exports and reports unless reveal is
on.
"""

from __future__ import annotations

import time

from ...core import aosp
from ...core.export import to_json
from ...core.findings import ModuleResult
from ...core.masking import password_of
from ...core.session import Ctx
from ..registry import INT, ModuleSpec, Param, register

DEFAULT_LOCKSETTINGS = "/system/locksettings.db"
DEFAULT_PASSWORD_KEY = "/system/password.key"
DEFAULT_KEYSTORE = "/misc/keystore/user_0"


def _mask_key_info(key_info: dict) -> dict:
    """``password.key`` is a credential hash; only its shape may be exported."""
    out = {
        name: value
        for name, value in key_info.items()
        if name not in ("text", "sha1_part", "md5_part")
    }
    if key_info.get("text"):
        out["text"] = password_of(key_info["text"])
        out["sha1_part"] = "***"
        out["md5_part"] = "***"
    return out


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("pin_recovery")
    lock_path = str(params.get("locksettings") or DEFAULT_LOCKSETTINGS)
    key_path = str(params.get("password_key") or DEFAULT_PASSWORD_KEY)
    keystore_path = str(params.get("keystore_dir") or DEFAULT_KEYSTORE)
    length = int(params.get("length", 4) or 4)
    brute = bool(params.get("bruteforce", True))
    try:
        lock_local = ctx.materialise(lock_path)
    except KeyError:
        res.add("warn", f"Brak {lock_path} w obrazie")
        return ctx.record(res)
    settings = aosp.locksettings(lock_local)
    state = settings.get("lock_state", {})
    res.add(
        "ok",
        f"locksettings.db: typ blokady {state.get('password_type')} ({state.get('password_type_name')})",
        values={
            "path": str(lock_local),
            "tables": settings.get("tables"),
            **state,
            "lockout_attempt_deadline": state.get("lockout_attempt_deadline"),
        },
        artifacts=[str(lock_local)],
    )
    salt_text = state.get("salt_text")
    if not salt_text:
        res.add("warn", "Brak wartości password_salt — brak podstawy do odtworzenia PIN-u")
        return ctx.record(res)
    res.add(
        "info",
        f"Sól (Long.toHexString): {salt_text}",
        detail=(
            "LockPatternUtils buduje password.key jako UPPER(SHA1(pin+sól)) + UPPER(MD5(pin+sól)); "
            "sól jest podawana jako szesnastkowy tekst długiej"
        ),
        values={"salt_text": salt_text, "salt_long": state.get("salt")},
    )
    try:
        key_local = ctx.materialise(key_path)
    except KeyError:
        key_local = None
    key_info: dict = {}
    if key_local is not None:
        key_info = aosp.read_password_key(key_local)
        res.add(
            "ok" if key_info.get("format_ok") else "warn",
            f"password.key: {key_info.get('length')} znaków, format {'OK' if key_info.get('format_ok') else 'NIEPOPRAWNY'}",
            values={
                "path": str(key_local),
                "size": key_info.get("size"),
                "length": key_info.get("length"),
                "format_ok": key_info.get("format_ok"),
                "uppercase_hex": key_info.get("uppercase_hex"),
                "sha1_part": key_info.get("sha1_part"),
                "md5_part": key_info.get("md5_part"),
                "gesture_key": key_info.get("gesture_key"),
            },
            artifacts=[str(key_local)],
        )
    target = key_info.get("text", "")
    if not target:
        res.add("warn", "Brak password.key — nie ma czego szukać")
        return ctx.record(res)
    if not brute:
        res.add("info", "Przeszukiwanie PIN-u wyłączone (parametr bruteforce=false)")
        return ctx.record(res)
    state_box = {"last": 0.0}

    def progress(checked: int, total: int) -> None:
        now = time.time()
        if now - state_box["last"] > 2.0:
            state_box["last"] = now
            ctx.log(f"Sprawdzono {checked}/{total} kombinacji")

    search_started = time.time()
    candidates = aosp.brute_force_pin(target, salt_text, length=length, progress=progress)
    elapsed = round(time.time() - search_started, 2)
    res.add(
        "ok",
        f"Przeszukano {10 ** length} kombinacji w {elapsed}s",
        detail=f"znalezione kandydaty: {len(candidates)}",
        values={
            "space": 10**length,
            "length": length,
            "seconds": elapsed,
            "candidates": [password_of(c.pin) for c in candidates],
        "candidates_count": len(candidates),
        },
    )
    for candidate in candidates:
        res.add(
            "critical",
            f"Odzyskany PIN: {candidate.pin}",
            detail=(
                "weryfikacja offline: password_key = UPPER(SHA1(pin+sól)) + UPPER(MD5(pin+sól)) "
                "zgadza się z plikiem z obrazu"
            ),
            values={
                "pin": password_of(candidate.pin),
                "pin_length": len(candidate.pin),
                "salt_text": salt_text,
                "verified_hash": aosp.password_key_hash(candidate.pin, salt_text)[:16] + "…",
                "seconds": elapsed,
            },
        )
    if not candidates:
        res.add(
            "warn",
            "Brak kandydata w przeszukanej przestrzeni",
            detail="sprawdź długość PIN-u (parametr length) oraz czy blokada nie jest wzorem",
        )
    try:
        ks = ctx.fs().stat(keystore_path)
        uids: list[str] = []
        for entry in ctx.fs().listdir(keystore_path):
            if entry.name.startswith("."):
                continue
            uid = entry.name.split("_", 1)[0]
            if uid.isdigit() and uid not in uids:
                uids.append(uid)
        res.add(
            "ok",
            f"Keystore: {len(uids)} uidów z kluczami",
            detail="brak wpisów oznacza, że aplikacja nie ma już dostępu do swoich kluczy",
            values={
                "path": keystore_path,
                "uids": sorted(uids, key=int),
                "count": len(uids),
                "masterkey_mtime": ks.get("mtime"),
                "known": {
                    uid: name
                    for uid, name in aosp.common_android_uids().items()
                    if str(uid) in uids
                },
            },
        )
    except Exception as exc:
        res.add("info", f"Nie odczytano katalogu keystore ({exc})")
    res.data = {
        "locksettings": settings,
        "state": state,
        "salt_text": salt_text,
        "password_key": _mask_key_info(key_info),
        "candidates": [password_of(c.pin) for c in candidates],
        "candidates_count": len(candidates),
        "search_seconds": elapsed,
    }
    res.export(to_json(ctx.work("exports") / "pin_recovery.json", res.data, ctx.masker))
    return ctx.record(res)


register(
    ModuleSpec(
        id="pin_recovery",
        category="accounts",
        title="mod.pin_recovery.title",
        summary="mod.pin_recovery.summary",
        params=[
            Param(key="locksettings", label="Ścieżka locksettings.db", default=DEFAULT_LOCKSETTINGS, kind="path"),
            Param(key="password_key", label="Ścieżka password.key", default=DEFAULT_PASSWORD_KEY, kind="path"),
            Param(key="keystore_dir", label="Katalog keystore", default=DEFAULT_KEYSTORE, kind="path"),
            Param(key="length", label="Długość PIN-u", default=4, kind=INT),
            Param(key="bruteforce", label="Przeszukaj przestrzeń PIN-ów", default=True, kind="bool"),
        ],
        run=run,
    )
)
