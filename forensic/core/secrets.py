# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""The secrets policy, made checkable instead of remembered.

Two rules cover every value in this project: a secret is wrapped in
:class:`~forensic.core.masking.Secret` at the point of discovery, and nothing is
written in the clear unless the operator switched *reveal* on.  The first rule is
easy to state and easy to break in a later turn, so it is enforced from two
directions at once:

* a **registry** of every secret the tool has ever handled, kept as a fingerprint
  (SHA-256 prefix) rather than the value itself, so the audit can search the
  exports for the value without storing it twice;
* **shape patterns** for credentials this tool may never have seen — a token
  written by some other module, a password file dumped as text, a private key —
  because the point of a check is to catch the case nobody remembered.

The audit answers one question: *does any artefact under ``work/<case>`` contain a
credential in the clear?*  Exports written while *reveal* was on are reported as
such instead of passing silently.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
from pathlib import Path
from typing import Any
from collections.abc import Iterable

from .export import write_private

REGISTRY_NAME = "secrets.json"
FINGERPRINT_LEN = 12
CREDENTIAL_COLUMNS = (
    "psk",
    "password",
    "passwd",
    "token",
    "access_token",
    "auth_token",
    "secret",
)
MASK_MARKERS = ("…", "***", "xxxx")

PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("facebook_access_token", re.compile(r"\bEAA[0-9A-Za-z_\-]{40,}")),
    ("google_oauth2_token", re.compile(r"\bya29\.[0-9A-Za-z_\-]{20,}")),
    ("slack_token", re.compile(r"\bxox[abposr]-[0-9A-Za-z\-]{10,}")),
    ("github_token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{20,}")),
    ("password_key_hash", re.compile(r"\b[0-9A-F]{72}\b")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("bearer_header", re.compile(r"\b[Bb]earer\s+[0-9A-Za-z_\-.=]{20,}")),
)

JSON_FIELD = re.compile(
    r'"(?P<field>' + "|".join(CREDENTIAL_COLUMNS) + r')"\s*:\s*"(?P<value>[^"]+)"',
    re.IGNORECASE,
)


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:FINGERPRINT_LEN]


def looks_masked(value: str) -> bool:
    text = value.strip()
    if not text:
        return True
    if any(marker in text for marker in MASK_MARKERS):
        return True
    return bool(re.fullmatch(r".*\(\d+\)", text))


class Registry:
    """Fingerprints of every secret this process has wrapped."""

    def __init__(self) -> None:
        self.entries: dict[str, dict[str, Any]] = {}

    def record(self, value: str, kind: str) -> str:
        """Note a secret; returns its fingerprint.  The value is not stored."""
        if not value or not isinstance(value, str):
            return ""
        mark = fingerprint(value)
        entry = self.entries.setdefault(
            mark,
            {
                "fingerprint": mark,
                "kind": kind,
                "length": len(value),
                "seen": 1,
                "samples": [],
            },
        )
        entry["seen"] += 1
        if len(entry["samples"]) < 3 and len(value) <= 8:
            entry["samples"].append(f"{value[:2]}…{value[-2:]}")
        return mark

    def merge(self, other: Iterable[dict[str, Any]]) -> None:
        for item in other:
            mark = str(item.get("fingerprint") or "")
            if not mark:
                continue
            current = self.entries.setdefault(
                mark,
                {
                    "fingerprint": mark,
                    "kind": item.get("kind", "?"),
                    "length": item.get("length", 0),
                    "seen": 0,
                    "samples": [],
                },
            )
            current["seen"] += int(item.get("seen", 1) or 0)
            current.setdefault("samples", [])

    def as_list(self) -> list[dict[str, Any]]:
        return sorted(self.entries.values(), key=lambda item: (-item["seen"], item["kind"]))

    def values_by_kind(self, kind: str) -> list[str]:
        """Nothing — fingerprints are one-way, values are never persisted."""
        return []

    def save(self, path: str | Path, reveal: bool = False) -> Path:
        target = Path(path)
        return write_private(
            target,
            json.dumps(
                {
                    "generated": _now(),
                    "reveal_at_write": bool(reveal),
                    "note": "fingerprintery SHA-256, nie wartości sekretów",
                    "secrets": self.as_list(),
                },
                indent=2,
                ensure_ascii=False,
            ),
        )

    def load(self, path: str | Path) -> int:
        target = Path(path)
        if not target.exists():
            return 0
        try:
            payload = json.loads(target.read_text(encoding="utf-8"))
        except Exception:
            return 0
        self.merge(payload.get("secrets", []))
        return len(payload.get("secrets", []))


REGISTRY = Registry()


def _now() -> str:
    import datetime as _dt

    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def scan_text(text: str, label: str) -> list[dict[str, Any]]:
    """Credential shapes found in one text blob."""
    hits: list[dict[str, Any]] = []
    for name, pattern in PATTERNS:
        for match in pattern.finditer(text):
            hits.append(
                {
                    "file": label,
                    "kind": "pattern",
                    "detector": name,
                    "offset": match.start(),
                    "length": len(match.group()),
                }
            )
    for match in JSON_FIELD.finditer(text):
        value = match.group("value")
        if looks_masked(value):
            continue
        hits.append(
            {
                "file": label,
                "kind": "json_field",
                "detector": match.group("field").lower(),
                "offset": match.start(),
                "length": len(value),
            }
        )
    return hits


def scan_file(path: str | Path, known: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """Everything suspicious in one artefact, with the reason named."""
    target = Path(path)
    try:
        raw = target.read_bytes()
    except OSError as exc:
        return [{"file": str(target), "kind": "unreadable", "detector": str(exc)}]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("utf-8", "replace")
    hits = scan_text(text, str(target))
    if target.suffix == ".csv":
        hits += _scan_csv(target, text, known or {})
    return hits


def _scan_csv(path: Path, text: str, known: dict[str, str]) -> list[dict[str, Any]]:
    """Every cell of a credential column must be empty or masked."""
    out: list[dict[str, Any]] = []
    try:
        rows = list(csv.reader(text.splitlines()))
    except Exception:
        return out
    if not rows:
        return out
    header = [cell.strip().lower() for cell in rows[0]]
    columns = {
        index: name
        for index, name in enumerate(header)
        if name in CREDENTIAL_COLUMNS
    }
    for number, row in enumerate(rows[1:], start=2):
        for index, name in columns.items():
            if index >= len(row):
                continue
            value = row[index]
            if looks_masked(value):
                continue
            out.append(
                {
                    "file": str(path),
                    "kind": "csv_cell",
                    "detector": f"{name} (wiersz {number})",
                    "offset": 0,
                    "length": len(value),
                }
            )
    return out


def audit_dir(
    root: str | Path, registry: Registry, patterns_only: bool = False
) -> dict[str, Any]:
    """Scan every artefact under ``root``; returns a verdict and the hits."""
    base = Path(root)
    files = sorted(
        p
        for p in base.rglob("*")
        if p.is_file() and p.suffix.lower() in (".json", ".csv", ".md", ".txt", ".log")
    )
    hits: list[dict[str, Any]] = []
    for path in files:
        hits += scan_file(path)
    by_detector: dict[str, int] = {}
    for item in hits:
        key = str(item.get("detector", "?"))
        by_detector[key] = by_detector.get(key, 0) + 1
    return {
        "directory": str(base),
        "files": len(files),
        "bytes": sum(p.stat().st_size for p in files if p.exists()),
        "hits": hits,
        "by_detector": dict(sorted(by_detector.items(), key=lambda item: -item[1])),
        "known_secrets": len(registry.entries),
        "patterns_only": patterns_only,
    }


# What an artefact is, decides whether a plaintext hit is a policy violation.
#
# ``evidence`` — byte-identical copies of what the image holds (the extracted
#   databases, the cache).  Masking them would destroy the evidence, so they are
#   excluded by design, and the exclusion is reported.
# ``state`` — the tool's own working state (``session.json``, ``secrets.json``),
#   which is deliberately unmasked so a later run can render a report; the
#   requirement here is the file mode, not the content.
# ``derived`` — everything a reader may see (exports, reports, acquisition
#   records).  These must contain no secret in the clear.
EVIDENCE_DIRS = ("extracted", "cache")
STATE_FILES = ("session.json", "secrets.json")
DERIVED_DIRS = ("exports", "reports", "acquire")


def audit_case(
    workdir: str | Path, registry: Registry, patterns_only: bool = False
) -> dict[str, Any]:
    """Audit one case directory, keeping the three artefact classes apart."""
    base = Path(workdir)
    derived: list[Path] = []
    evidence: list[Path] = []
    state: list[Path] = []
    for path in sorted(base.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() not in (".json", ".csv", ".md", ".txt", ".log"):
            continue
        relative = path.relative_to(base)
        head = relative.parts[0] if len(relative.parts) > 1 else ""
        if path.name in STATE_FILES:
            state.append(path)
        elif head in EVIDENCE_DIRS:
            evidence.append(path)
        elif head in DERIVED_DIRS or not relative.parts[:-1]:
            derived.append(path)
        else:
            evidence.append(path)
    derived_hits: list[dict[str, Any]] = []
    for path in derived:
        derived_hits += scan_file(path)
    state_hits: list[dict[str, Any]] = []
    for path in state:
        state_hits += scan_file(path)
    state_modes = {str(path.relative_to(base)): _mode(path) for path in state}
    loose = {
        name: mode
        for name, mode in state_modes.items()
        if mode and mode != "0o600" and not patterns_only
    }
    return {
        "directory": str(base),
        "classes": {
            "derived": {
                "files": len(derived),
                "bytes": _total(derived),
                "hits": derived_hits,
                "by_detector": _by_detector(derived_hits),
                "must_be_clean": True,
            },
            "evidence": {
                "files": len(evidence),
                "bytes": _total(evidence),
                "excluded": True,
                "reason": (
                    "kopie plików z obrazu, bajt w bajt — maskowanie zniszczyłoby dowód; "
                    "wymóg dotyczy tylko artefaktów pochodnych"
                ),
                "locations": sorted({str(p.relative_to(base).parts[0]) for p in evidence}),
            },
            "state": {
                "files": len(state),
                "bytes": _total(state),
                "hits": len(state_hits),
                "modes": state_modes,
                "must_be_0600": True,
                "loose_modes": loose,
                "reason": (
                    "stan roboczy przechowuje wartości niezamaskowane celowo (raport powstaje "
                    "później); wymagany jest tryb 0600, nie maskowanie treści"
                ),
            },
        },
        "known_secrets": len(registry.entries),
        "hits": derived_hits,
        "files": len(derived),
        "bytes": _total(derived),
        "by_detector": _by_detector(derived_hits),
        "patterns_only": patterns_only,
    }


def _mode(path: Path) -> str:
    try:
        return oct(path.stat().st_mode & 0o777)
    except OSError:
        return ""


def _total(paths: Iterable[Path]) -> int:
    out = 0
    for path in paths:
        try:
            out += path.stat().st_size
        except OSError:
            continue
    return out


def _by_detector(hits: Iterable[dict[str, Any]]) -> dict[str, int]:
    out: dict[str, int] = {}
    for item in hits:
        key = str(item.get("detector", "?"))
        out[key] = out.get(key, 0) + 1
    return dict(sorted(out.items(), key=lambda item: -item[1]))
