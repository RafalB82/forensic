# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Does any artefact in the work directory contain a credential in the clear?

The policy this project declares is that secrets are masked on the way out and
revealed only on request.  Nothing enforced that: the only check was a manual
``grep`` over ``work/<case>/exports`` after every turn, and a new module could
have written a token in the clear without anybody noticing.

This module closes that gap.  It scans every artefact the tool has produced and
reports three numbers that make the policy falsifiable:

* how many secrets the tool *knows about* — the registry, so an empty registry
  cannot masquerade as a clean run;
* how many artefacts were scanned;
* how many credential shapes were found — a value, a token field, a key file.

Exports written while *reveal* was on are reported as such instead of counting
as leaks, so the audit stays honest when the operator asked for the clear text.
"""

from __future__ import annotations

import time
from pathlib import Path

from ...core import i18n, secrets
from ...core.export import to_json
from ...core.findings import ModuleResult
from ...core.session import Ctx
from ..registry import BOOL, ModuleSpec, Param, register

SCAN_SUFFIXES = (".json", ".csv", ".md", ".txt", ".log")


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("secret_audit")
    subdir = str(params.get("path") or ctx.workdir)
    patterns_only = bool(params.get("patterns_only", False))
    reveal = bool(params.get("reveal", ctx.config.reveal))
    started = time.time()
    registry = secrets.REGISTRY
    stored = registry.load(Path(ctx.workdir) / secrets.REGISTRY_NAME)
    report = secrets.audit_case(subdir, registry, patterns_only)
    registry_path = registry.save(
        Path(ctx.workdir) / secrets.REGISTRY_NAME, reveal=reveal or i18n.reveal()
    )
    hits = report["hits"]
    exempt = bool(reveal or i18n.reveal())
    classes = report["classes"]
    kinds: dict[str, int] = {}
    for item in hits:
        kinds[str(item.get("kind", "?"))] = kinds.get(str(item.get("kind", "?")), 0) + 1
    known = report["known_secrets"]
    loose = classes["state"]["loose_modes"]
    verdict = "no_plaintext_secrets"
    if hits and not exempt:
        verdict = "plaintext_secrets_present"
    elif hits:
        verdict = "plaintext_by_operator_request"
    elif loose:
        verdict = "state_files_too_readable"
    res.add(
        "critical" if (hits and not exempt) or loose else ("info" if hits else "ok"),
        f"Polityka sekretów: {len(hits)} trafień w {report['files']} artefaktach pochodnych",
        detail=(
            f"rejestr zna {known} sekretów (bieżący przebieg + {stored} z {secrets.REGISTRY_NAME}); "
            f"pominięto {classes['evidence']['files']} plików dowodowych (kopie z obrazu) i "
            f"{classes['state']['files']} plików stanu — ich wymogiem jest tryb 0600, nie maskowanie; "
            + (
                "trafienia w artefaktach pochodnych są oczekiwane — sesja odsłaniała sekrety"
                if hits and exempt
                else (f"rodzaje: {kinds}" if hits else "żadnego sekretu w jawnej postaci")
            )
            + (f"; zbyt szeroko czytelne pliki stanu: {sorted(loose)}" if loose else "")
        ),
        values={
            "verdict": verdict,
            "hits": len(hits),
            "by_kind": kinds,
            "by_detector": report["by_detector"],
            "files_scanned": report["files"],
            "bytes_scanned": report["bytes"],
            "derived_files": classes["derived"]["files"],
            "evidence_files_excluded": classes["evidence"]["files"],
            "evidence_locations": classes["evidence"]["locations"],
            "state_files": classes["state"]["files"],
            "state_modes": classes["state"]["modes"],
            "state_loose_modes": sorted(loose),
            "known_secrets": known,
            "known_secrets_stored": stored,
            "by_kind_secret": _kinds(registry),
            "registry": str(registry_path),
            "patterns": [name for name, _ in secrets.PATTERNS],
            "json_fields_watched": list(secrets.CREDENTIAL_COLUMNS),
            "reveal_exempt": exempt,
            "seconds": round(time.time() - started, 2),
        },
        artifacts=[str(registry_path)],
    )
    for item in hits[:20]:
        res.add(
            "critical" if not exempt else "info",
            f"Trafienie: {item.get('kind')} w {Path(str(item.get('file', ''))).name}",
            detail=(
                f"wykrywacz: {item.get('detector')}; długość {item.get('length')} znaków"
                + ("; odsłonięte na życzenie operatora" if exempt else "")
            ),
            values={**item, "exempt": exempt},
        )
    if not hits:
        res.add(
            "ok",
            f"Rejestr: {known} sekretów ({_kinds(registry)})",
            detail=(
                "rejestr przechowuje tylko odciski SHA-256, nigdy wartości; dzięki temu audyt "
                "potrafi odszukać wartość w eksporcie bez podwójnego jej przechowywania"
            ),
            values={"known_secrets": known, "kinds": _kinds(registry), "path": str(registry_path)},
        )
    res.data = {
        **report,
        "verdict": verdict,
        "hits": hits,
        "hit_count": len(hits),
        "derived_files": classes["derived"]["files"],
        "evidence_files_excluded": classes["evidence"]["files"],
        "evidence_locations": classes["evidence"]["locations"],
        "state_files": classes["state"]["files"],
        "state_modes": classes["state"]["modes"],
        "state_loose_modes": sorted(loose),
        "known_secrets": known,
        "known_secrets_stored": stored,
        "kinds": _kinds(registry),
        "registry": str(registry_path),
        "patterns": [name for name, _ in secrets.PATTERNS],
        "json_fields_watched": list(secrets.CREDENTIAL_COLUMNS),
        "reveal_exempt": exempt,
    }
    res.export(
        to_json(ctx.work("exports") / "secret_audit.json", res.data, ctx.masker, indent=1)
    )
    res.note(f"{time.time() - started:.1f}s")
    return ctx.record(res)


def _kinds(registry: secrets.Registry) -> dict[str, int]:
    out: dict[str, int] = {}
    for item in registry.as_list():
        out[item["kind"]] = out.get(item["kind"], 0) + 1
    return dict(sorted(out.items(), key=lambda item: (-item[1], item[0])))


register(
    ModuleSpec(
        id="secret_audit",
        category="report",
        title="mod.secret_audit.title",
        summary="mod.secret_audit.summary",
        params=[
            Param(key="path", label="param.audit_path", default="", kind="path"),
            Param(key="patterns_only", label="param.patterns_only", default=False, kind=BOOL),
            Param(key="reveal", label="param.reveal_audit", default=False, kind=BOOL),
        ],
        run=run,
        needs_image=False,
    )
)
