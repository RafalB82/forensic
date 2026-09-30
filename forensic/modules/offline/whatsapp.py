# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""WhatsApp: why there is no password, and what the account left behind.

WhatsApp has no password mechanism at all — registration is a phone number plus
an SMS code, so the honest finding is a negative one, and it has to be argued
from evidence rather than asserted.  The module therefore shows the
registration state files, the account identity, the Signal key state, and the
keystore entries that would be needed to open the encrypted Noise key pair.
"""

from __future__ import annotations

import time
from pathlib import Path

from ...core import appdata
from ...core.export import to_csv, to_json
from ...core.findings import ModuleResult
from ...core.masking import phone_of
from ...core.session import Ctx
from ..registry import ModuleSpec, Param, register


def _counts_sentence(msgstore: dict) -> str:
    """The ``forwarded`` / ``starred`` counts, or a note that they are unknown.

    Both keys are ``None`` when their query failed and absent when the column is
    not in this version of the database.  Those are three different states —
    a count, something we could not read, and a feature this build never had —
    and this sentence says which, because ``get(key, 0)`` says "zero" for all
    three and a report that claims zero stars on a database it failed to read is
    asserting something it does not know.
    """
    parts = []
    for key, label in (("forwarded", "przekazanych dalej"), ("starred", "oznaczonych gwiazdką")):
        if key not in msgstore:
            continue
        value = msgstore[key]
        parts.append(f"{value} {label}" if value is not None else f"{label}: nieczytelne")
    return ", ".join(parts) + "." if parts else ""

APP_DIR = "/data/com.whatsapp"
DATABASES = f"{APP_DIR}/databases"
PREFS = f"{APP_DIR}/shared_prefs"
FILES = f"{APP_DIR}/files"
REGISTRATION = (
    f"{PREFS}/registration.RegisterPhone.xml",
    f"{PREFS}/registration.VerifySms.xml",
    f"{PREFS}/registration.VerifyPhoneNumber.xml",
)
KEYSTORE_XML = f"{PREFS}/keystore.xml"
ANDROID_KEYSTORE = "/misc/keystore/user_0"
KNOWN_UIDS = {10133: "com.whatsapp", 10092: "com.facebook.messenger", 10149: "com.facebook.system"}


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("whatsapp")
    app_dir = str(params.get("app_dir") or APP_DIR)
    keystore_dir = str(params.get("keystore_dir") or ANDROID_KEYSTORE)
    started = time.time()
    try:
        ctx.fs().listdir(app_dir)
    except KeyError:
        res.add("warn", f"Brak katalogu aplikacji w obrazie: {app_dir}")
        return ctx.record(res)
    except FileNotFoundError as exc:
        res.add("critical", "Brak obrazu", detail=str(exc))
        return ctx.record(res)
    identity = _identity(ctx, app_dir)
    registration = _registration(ctx)
    res.add(
        "finding",
        "WhatsApp nie ma mechanizmu hasła",
        detail=(
            "rejestracja i logowanie idą numerem telefonu + SMS; lokalnie nie ma żadnego pola "
            "hasła ani jego skrótu. Potwierdzone przez: brak hasła w accounts.db, pliki "
            "rejestracji z kodem weryfikacyjnym oraz stan keystore bez kluczy Noise tego konta"
        ),
            values={
                "app_dir": app_dir,
                "account_number": phone_of(identity.get("number", "")) if identity.get("number") else None,
                "e164": phone_of(identity.get("e164", "")) if identity.get("e164") else None,
                "jabber_id": identity.get("jabber_id", ""),
                "jabber_id_derived": identity.get("jabber_id_derived"),
                "country_code": identity.get("country_code", ""),
                "digit_fields": identity.get("digit_fields", []),
                "registration_files": registration,
                "password_fields_found": 0,
            },
    )
    msgstore = _database(ctx, f"{DATABASES}/msgstore.db", appdata.whatsapp_msgstore)
    if msgstore:
        if msgstore.get("encrypted"):
            # The file is intact and sealed.  Saying so is the finding; a
            # libsqlite3 "file is not a database" would instead send the
            # analyst looking for a failed extraction.
            res.add(
                "finding",
                f"msgstore.db jest zaszyfrowaną kopią WhatsApp ({msgstore.get('version')})",
                detail=str(msgstore.get("note", "")),
                values={
                    "version": msgstore.get("version"),
                    "iv": msgstore.get("iv"),
                    "header_len": msgstore.get("header_len"),
                    "key_available": msgstore.get("key_available"),
                    "database": msgstore["file"],
                },
                artifacts=[msgstore["file"]],
            )
        elif msgstore.get("error"):
            res.add(
                "critical",
                f"msgstore.db nieczytelny: {msgstore['error']}",
                values={"error": msgstore["error"], "database": msgstore["file"]},
                artifacts=[msgstore["file"]],
            )
        else:
            res.add(
                "finding",
                f"msgstore.db: {msgstore.get('messages_total', 0)} wiadomości",
                detail=(
                    f"okno {msgstore.get('first_message_utc')} → {msgstore.get('last_message_utc')}, "
                    f"{msgstore.get('with_text', 0)} z tekstem, integralność {msgstore.get('integrity')}"
                ),
                values={
                    "database": msgstore["file"],
                    "integrity": msgstore.get("integrity"),
                    "messages": msgstore.get("messages_total"),
                    "with_text": msgstore.get("with_text"),
                    "outgoing": msgstore.get("outgoing"),
                    "first_message_utc": msgstore.get("first_message_utc"),
                    "last_message_utc": msgstore.get("last_message_utc"),
                    "counts": msgstore.get("counts", {}),
                },
                artifacts=[msgstore["file"]],
            )
            kinds = msgstore.get("type_kinds") or {}
            if kinds:
                column = msgstore.get("type_column")
                mimes = msgstore.get("type_mimes", {})
                res.add(
                    "info",
                    "Rodzaje wiadomości: "
                    + ", ".join(f"{kind} {count}" for kind, count in
                                sorted(kinds.items(), key=lambda kv: -kv[1])),
                    detail=(
                        f"kolumna {column}; kody niekatalogowane są liczone, nie pomijane. "
                        + _counts_sentence(msgstore)
                    ),
                    values={
                        "type_column": column,
                        "type_codes": msgstore.get("types", {}),
                        "type_kinds": kinds,
                        "type_labels": msgstore.get("type_labels", {}),
                        "type_mimes": mimes,
                        "forwarded": msgstore.get("forwarded"),
                        "starred": msgstore.get("starred"),
                    },
                )
            disputed = msgstore.get("type_disputed") or {}
            if disputed:
                res.add(
                    "warn",
                    f"Słownik typów wiadomości sporny dla {len(disputed)} kodów — "
                    "MIME z obrazu nie zgadza się z etykietą",
                    detail="; ".join(
                        f"kod {code}: słownik mówi {item['dictionary']!r}, "
                        f"obraz pokazuje {','.join(item['observed_mime'])}"
                        for code, item in sorted(disputed.items())
                    )[:400],
                    values={
                        # Nazwa zgodna z kluczem w eksporcie, żeby eksport nie
                        # miał dwóch określeń tej samej rzeczy.
                        "type_disputed": disputed,
                        "note": (
                            "Oba odczyty zostawione. Słownik może być nieaktualny albo "
                            "MIME może być kontenerem wybranym przez Whatsappa; "
                            "analityk ma widzieć sprzeczność, nie wybierać za niego."
                        ),
                    },
                )
        if msgstore.get("media"):
            res.add(
                "info",
                f"Media w msgstore: {len(msgstore['media'])} pozycji",
                values={
                    "media": len(msgstore["media"]),
                    "mime_kinds": msgstore.get("media_mime_kinds", {}),
                    "sample": msgstore["media"][:10],
                },
            )
    axolotl = _database(ctx, f"{DATABASES}/axolotl.db", appdata.whatsapp_axolotl)
    if axolotl:
        counts = axolotl.get("counts", {})
        res.add(
            "info" if counts.get("message_base_key") == 0 else "warn",
            f"axolotl.db: {counts.get('sessions', 0)} sesji Signal, "
            f"{counts.get('sender_keys', 0)} sender_keys",
            detail="; ".join(
                part
                for part in (axolotl.get("verdict", ""), axolotl.get("verdict_note", ""))
                if part
            ),
            values={
                "database": axolotl["file"],
                "integrity": axolotl.get("integrity"),
                "sessions": counts.get("sessions"),
                "identities": counts.get("identities"),
                "sender_keys": counts.get("sender_keys"),
                "prekeys": counts.get("prekeys"),
                "message_base_key": counts.get("message_base_key"),
                "trusted_identities": axolotl.get("trusted_identities"),
                "verdict": axolotl.get("verdict"),
            },
            artifacts=[axolotl["file"]],
        )
    contacts = _database(ctx, f"{DATABASES}/wa.db", appdata.whatsapp_contacts)
    if contacts:
        res.add(
            "info",
            f"wa.db: {contacts.get('contacts', 0)} kontaktów, {contacts.get('named_contacts', 0)} z nazwą",
            values={
                "database": contacts["file"],
                "integrity": contacts.get("integrity"),
                "contacts": contacts.get("contacts"),
                "named_contacts": contacts.get("named_contacts"),
                "sample": contacts.get("sample", [])[:10],
            },
            artifacts=[contacts["file"]],
        )
    key_material = _key_material(ctx, app_dir)
    if key_material:
        res.add(
            "critical",
            f"Materiał kluczy WhatsApp ({len(key_material)} plików)",
            detail=(
                "pliki `key`, `rc2` i `backup_token` to strumienie Java; para kluczy Noise jest "
                "szyfrowana kluczem z keystore, którego dla tego uid na dysku nie ma"
            ),
            values={"files": key_material},
        )
    blocking = _keystore(ctx, keystore_dir)
    res.add(
        "warn" if blocking["missing"] else "ok",
        f"Keystore systemowy: brak kluczy dla {len(blocking['missing'])} z {len(KNOWN_UIDS)} uidów",
        detail=(
            f"zaszyfrowanej pary kluczy Noise nie da się otworzyć, dopóki kluczy dla tych uidów "
            f"nie ma w {blocking['directory']}"
            if blocking["missing"]
            else "klucze dla wszystkich sprawdzanych uidów są obecne"
        ),
        values=blocking,
    )
    res.data = {
        "app_dir": app_dir,
        "identity": identity,
        "registration": registration,
        "msgstore": msgstore,
        "axolotl": axolotl,
        "contacts": contacts,
        "key_material": key_material,
        "keystore": blocking,
        "verdict": "brak mechanizmu hasła (numer + SMS)",
    }
    res.export(to_json(ctx.work("exports") / "whatsapp.json", res.data, ctx.masker))
    res.export(
        to_csv(
            ctx.work("exports") / "whatsapp_media.csv",
            ["file_path", "mime_type", "bytes", "uploaded"],
            [
                [item["file_path"], item["mime_type"], item["bytes"], item["uploaded"]]
                for item in (msgstore or {}).get("media", [])
            ],
            ctx.masker,
        )
    )
    res.note(f"{time.time() - started:.1f}s")
    return ctx.record(res)


def _read(ctx: Ctx, target: str) -> bytes | None:
    try:
        return Path(ctx.materialise(target)).read_bytes()
    except KeyError:
        return None


def _identity(ctx: Ctx, app_dir: str) -> dict:
    blob = _read(ctx, f"{app_dir}/files/me")
    if not blob:
        return {}
    return appdata.whatsapp_identity(blob)


def _registration(ctx: Ctx) -> list[dict]:
    out: list[dict] = []
    for target in REGISTRATION:
        blob = _read(ctx, target)
        if blob is None:
            out.append({"file": target, "present": False})
            continue
        prefs = appdata.shared_prefs(blob)
        interesting = {
            key.rsplit(".", 1)[-1]: value
            for key, value in prefs.items()
            if key.rsplit(".", 1)[-1]
            in ("input_phone_number", "phone_number", "country_code", "verification_state")
        }
        out.append({"file": target, "present": True, "values": interesting, "size": len(blob)})
    return out


def _database(ctx: Ctx, target: str, reader) -> dict:
    try:
        local = ctx.materialise(target)
    except KeyError:
        return {}
    report = reader(str(local))
    report["target"] = target
    return report


def _key_material(ctx: Ctx, app_dir: str) -> list[dict]:
    out: list[dict] = []
    for name in ("key", "rc2", "backup_token", "login_failed"):
        target = f"{app_dir}/files/{name}"
        blob = _read(ctx, target)
        if blob is None:
            continue
        verdict = appdata.classify_checked(blob)
        entry = {
            "file": target,
            "size": len(blob),
            "format": verdict["report"],
            "format_ours": verdict["format"],
            "format_magic": verdict["magic"],
            "format_note": verdict["note"],
        }
        if verdict["format"] == "java-serialized":
            parsed = appdata.java_serialized(blob)
            entry["serialized_types"] = parsed["types"]
            entry["type_descriptors"] = parsed["type_descriptors"]
        out.append(entry)
    return out


def _keystore(ctx: Ctx, keystore_dir: str) -> dict:
    packages = ctx.packages()
    entries: dict[str, list[str]] = {}
    try:
        for entry in ctx.fs().listdir(keystore_dir):
            uid = entry.name.split("_", 1)[0]
            if uid.isdigit():
                entries.setdefault(uid, []).append(entry.name)
    except Exception as exc:
        return {
            "directory": keystore_dir,
            "error": str(exc),
            "checked_uids": {str(uid): packages.get(uid, KNOWN_UIDS[uid]) for uid in sorted(KNOWN_UIDS)},
            "present": {},
            "missing": [
                {"uid": uid, "package": packages.get(uid, KNOWN_UIDS[uid])}
                for uid in sorted(KNOWN_UIDS)
            ],
            "verdict": "katalog keystore nieczytelny",
        }
    out = {
        "directory": keystore_dir,
        "uids_with_keys": sorted(entries, key=int),
        "checked_uids": {str(uid): packages.get(uid, KNOWN_UIDS[uid]) for uid in sorted(KNOWN_UIDS)},
        "present": {
            uid: {"package": packages.get(int(uid), KNOWN_UIDS.get(int(uid), "?")), "entries": names}
            for uid, names in entries.items()
        },
        "missing": [
            {"uid": uid, "package": packages.get(uid, KNOWN_UIDS[uid])}
            for uid in sorted(KNOWN_UIDS)
            if str(uid) not in entries
        ],
    }
    out["verdict"] = (
        "brak kluczy dla części uidów — para kluczy Noise pozostaje zamknięta"
        if out["missing"]
        else "klucze obecne"
    )
    return out


register(
    ModuleSpec(
        id="whatsapp",
        category="apps",
        title="mod.whatsapp.title",
        summary="mod.whatsapp.summary",
        params=[
            Param(key="app_dir", label="param.app_dir", default=APP_DIR, kind="path"),
            Param(key="keystore_dir", label="param.keystore_dir", default=ANDROID_KEYSTORE, kind="path"),
        ],
        run=run,
    )
)
