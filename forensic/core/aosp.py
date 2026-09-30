# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""AOSP lock-screen helpers: locksettings, salt derivation, PIN recovery.

The scheme is the one shipped by AOSP since 4.4 and still in use in Android 7
(MIUI 8 here): ``password.key`` holds ``UPPER(SHA1(pin + salt_text))`` followed
by ``UPPER(MD5(pin + salt_text))`` as ASCII hex, where ``salt_text`` is the
*Java* ``Long.toHexString`` of ``lockscreen.password_salt`` — unsigned, lower
case, no leading zeros.  Knowing the format makes an offline search over the
four-digit space trivial.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from collections.abc import Callable, Iterator

from .sqlite_tools import connect

PASSWORD_KEY_LENGTH = 72
PREFIX_TYPES = {
    0: "brak PIN-u (swipe)",
    65536: "PIN",
    131072: "wzór",
    196608: "PIN",
    262144: "hasło",
    327680: "PIN + hasło",
}


def java_long_to_hex(value: int) -> str:
    """Reproduce ``java.lang.Long.toHexString`` for a signed 64 bit value."""
    if value == 0:
        return "0"
    unsigned = value & 0xFFFFFFFFFFFFFFFF
    digits = "0123456789abcdef"
    out = []
    while unsigned:
        unsigned, remainder = divmod(unsigned, 16)
        out.append(digits[remainder])
    return "".join(reversed(out))


def password_key_hash(pin: str, salt_text: str) -> str:
    """The 72 character value stored in ``/data/system/password.key``.

    SHA-1 and MD5 are not a choice here and not a weakness: Android's
    ``password.key`` *is* the concatenation of those two digests, and a forensic
    reader has to reproduce the on-disk format byte for byte to compare a
    candidate PIN against it.  ``usedforsecurity=False`` says that out loud, so
    the linter does not read it as a password being hashed badly.
    """
    data = (pin + salt_text).encode("ascii")
    sha1 = hashlib.sha1(data, usedforsecurity=False).hexdigest().upper()
    md5 = hashlib.md5(data, usedforsecurity=False).hexdigest().upper()
    return sha1 + md5


def locksettings(path: str | Path) -> dict:
    """Read ``locksettings.db`` into a plain dictionary."""
    path = Path(path)
    out: dict[str, Any] = {"path": str(path), "exists": path.exists()}
    if not out["exists"]:
        return out
    conn = connect(path)
    try:
        tables = [row[0] for row in conn.execute("select name from sqlite_master where type='table'")]
        out["tables"] = tables
        if "locksettings" in tables:
            out["values"] = {
                row[0]: row[1] for row in conn.execute("select name, value from locksettings")
            }
        if "locksettings" in tables:
            out["columns"] = [row[1] for row in conn.execute('pragma table_info("locksettings")')]
    finally:
        conn.close()
    out["lock_state"] = lock_state(out)
    return out


def lock_state(settings: dict) -> dict:
    """Interpret the interesting keys of a locksettings dictionary."""
    values = settings.get("values", {}) if settings else {}
    password_type = _as_int(values.get("lockscreen.password_type"))
    salt = _as_int(values.get("lockscreen.password_salt"))
    salt_text = java_long_to_hex(salt) if salt is not None else None
    return {
        "password_type": password_type,
        "password_type_name": PREFIX_TYPES.get(password_type, "?")
        if password_type is not None
        else "?",
        "salt": salt,
        "salt_text": salt_text,
        "disabled": _as_int(values.get("lockscreen.disabled")),
        "lockout_attempt_deadline": _as_int(values.get("lockscreen.lockoutattemptdeadline")),
        "lock_after_timeout": values.get("lockscreen.lockAfterTimeout"),
        "password_history": values.get("lockscreen.passwordhistory"),
        "trust_agents": values.get("lockscreen.enabledtrustagents"),
        "secure": bool(password_type),
    }


def _as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(str(value).strip())
    except ValueError:
        return None


@dataclass
class PinCandidate:
    pin: str
    match: bool
    length: int


def brute_force_pin(
    target: str,
    salt_text: str,
    length: int = 4,
    digits: str = "0123456789",
    progress: Callable[[int, int], None] | None = None,
    step: int = 10000,
) -> list[PinCandidate]:
    """Search the PIN space; returns the candidates, best match first.

    ``target`` is the 72 character ``password.key`` content (or any substring of
    it, since a partial match is enough to identify a candidate).
    """
    target = (target or "").strip().upper()
    found: list[PinCandidate] = []
    checked = 0
    checked_last = 0
    for pin in _pin_space(length, digits):
        checked += 1
        if progress is not None and checked - checked_last >= step:
            checked_last = checked
            progress(checked, len(digits) ** length)
        digest = password_key_hash(pin, salt_text)
        if target and (target in digest or digest in target):
            found.append(PinCandidate(pin=pin, match=True, length=length))
            if len(found) >= 8:
                break
    return found


def _pin_space(length: int, digits: str) -> Iterator[str]:
    if length <= 0:
        return
    total = len(digits) ** length
    for index in range(total):
        pin = []
        value = index
        for _ in range(length):
            pin.append(digits[value % len(digits)])
            value //= len(digits)
        yield "".join(reversed(pin))


def read_password_key(path: str | Path) -> dict:
    """Read ``password.key`` and the small key files next to it."""
    path = Path(path)
    out: dict[str, Any] = {"path": str(path), "exists": path.exists()}
    if not out["exists"]:
        return out
    raw = path.read_bytes()
    try:
        out["text"] = raw.decode("ascii", "replace").strip()
    except Exception:
        out["text"] = ""
    out["size"] = len(raw)
    out["length"] = len(out["text"])
    out["format_ok"] = len(out["text"]) == PASSWORD_KEY_LENGTH
    out["uppercase_hex"] = all(c in "0123456789ABCDEF" for c in out["text"])
    out["sha1_part"] = out["text"][:40]
    out["md5_part"] = out["text"][40:]
    gesture = path.parent / "gesture.key"
    if gesture.exists():
        blob = gesture.read_bytes()
        out["gesture_key"] = {
            "path": str(gesture),
            "size": len(blob),
            "looks_sha1": len(blob) == 20,
        }
    return out


def keystore_uids(path: str | Path) -> dict:
    """List the UIDs that have key material in a keystore user directory."""
    path = Path(path)
    out: dict[str, Any] = {"path": str(path), "exists": path.is_dir()}
    if not out["exists"]:
        return out
    uids: dict[str, list[str]] = {}
    for entry in sorted(path.iterdir()):
        if entry.name.startswith("."):
            continue
        name = entry.name
        uid = name.split("_", 1)[0]
        if uid.isdigit():
            uids.setdefault(uid, []).append(name)
    out["uids"] = sorted(uids, key=int)
    out["count"] = len(uids)
    out["entries"] = {uid: names for uid, names in sorted(uids.items(), key=lambda item: int(item[0]))}
    out["masterkey"] = (path / ".masterkey").exists()
    return out


def common_android_uids() -> dict[int, str]:
    """UIDs that matter when checking whether an app had keystore access."""
    return {
        1000: "system",
        10010: "wifi",
        10013: "com.google.android.gms",
        1017: "keystore",
        1012: "vpn",
        10084: "com.google.android.inputmethod.latin",
        10092: "com.facebook.lite",
        10112: "com.google.android.gm",
        10123: "com.instagram.android",
        10128: "obuwie_club_app",
        10133: "com.whatsapp",
        10149: "com.facebook.orca",
    }
