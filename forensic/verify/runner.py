# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Verify module results against the expected values recorded in a case file.

A case file is JSON: metadata about the image plus a list of checks.  Each check
runs one module with fixed parameters and asserts values against the findings it
produced, so the tool's behaviour is regression-tested against results that were
verified by hand on a real device image.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from collections.abc import Callable

from ..core.evidence import INTEGRITY_FAIL, EvidenceIdentity
from ..core.export import color, render_table, text
from ..core.session import Ctx
from ..modules import registry


@dataclass
class CheckResult:
    check_id: str
    module: str
    passed: bool
    detail: str = ""
    seconds: float = 0.0
    assertions: int = 0
    failures: list[str] = None  # type: ignore[assignment]

    def as_dict(self) -> dict:
        return {
            "check": self.check_id,
            "module": self.module,
            "passed": self.passed,
            "detail": self.detail,
            "seconds": round(self.seconds, 2),
            "assertions": self.assertions,
            "failures": self.failures or [],
        }


def load_case(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def split_path(path: str) -> list[str]:
    """Split a dotted path; ``'a.b'`` is one literal key containing a dot."""
    parts: list[str] = []
    current = ""
    quoted = False
    for char in path:
        if char == "'":
            quoted = not quoted
            continue
        if char == "." and not quoted:
            if current:
                parts.append(current)
            current = ""
            continue
        current += char
    if current:
        parts.append(current)
    return parts


def _dig(finding_values: list[dict], path: str) -> tuple[bool, Any]:
    """Resolve a dotted path across findings.

    Syntax: ``key.nested[.N]`` is looked up in every finding and the matches are
    collected; prefixing with ``#N`` pins the lookup to one finding, e.g.
    ``#0.size`` is the ``size`` value of the first finding.  Paths starting with
    ``data.`` address the module's structured payload instead (see
    ``run_check``).  A key that itself contains dots is quoted:
    ``by_type.'com.google'``.
    """
    parts = split_path(path)
    current: list[Any] = list(finding_values)
    if parts and parts[0].startswith("#"):
        try:
            index = int(parts[0][1:])
        except ValueError:
            return False, None
        if index >= len(finding_values):
            return False, None
        current = [finding_values[index]]
        parts = parts[1:]
    for part in parts:
        nxt: list[Any] = []
        for item in current:
            if isinstance(item, list):
                if part.isdigit() and int(part) < len(item):
                    nxt.append(item[int(part)])
                continue
            if isinstance(item, dict):
                if part in item:
                    nxt.append(item[part])
        if not nxt:
            return False, None
        current = nxt
    return True, (current[0] if len(current) == 1 else current)


def _compare(actual: Any, expect: dict) -> tuple[bool, str]:
    if "equals" in expect:
        target = expect["equals"]
        if isinstance(actual, str) and isinstance(target, str):
            return actual == target, f"{actual!r} != {target!r}"
        if isinstance(actual, (int, float)) and isinstance(target, (int, float)):
            return abs(float(actual) - float(target)) <= float(expect.get("tolerance", 0)), (
                f"{actual} != {target}"
            )
        return actual == target, f"{actual!r} != {target!r}"
    if "contains" in expect:
        needle = expect["contains"]
        if isinstance(actual, (list, tuple, set)):
            return needle in actual, f"{needle!r} not in {actual!r}"
        return needle in str(actual), f"{needle!r} not in {actual!r}"
    if "not_contains" in expect:
        needle = expect["not_contains"]
        if isinstance(actual, (list, tuple, set)):
            return needle not in actual, f"{needle!r} unexpectedly present"
        return needle not in str(actual), f"{needle!r} present"
    if "matches" in expect:
        import re

        return bool(re.search(expect["matches"], str(actual))), f"{actual!r} !~ {expect['matches']}"
    if "gte" in expect:
        try:
            return float(actual) >= float(expect["gte"]), f"{actual} < {expect['gte']}"
        except (TypeError, ValueError):
            return False, f"{actual!r} not numeric"
    if "lte" in expect:
        try:
            return float(actual) <= float(expect["lte"]), f"{actual} > {expect['lte']}"
        except (TypeError, ValueError):
            return False, f"{actual!r} not numeric"
    if "in" in expect:
        return actual in expect["in"], f"{actual!r} not in {expect['in']}"
    return False, "no assertion operator given"


def run_check(ctx: Ctx, check: dict) -> CheckResult:
    module_id = check.get("module", "")
    spec = registry.by_id(module_id)
    started = time.time()
    if spec is None or spec.run is None:
        return CheckResult(
            check.get("id", module_id), module_id, False, f"unknown module {module_id}", failures=[f"unknown module {module_id}"]
        )
    params = spec.defaults()
    params.update(check.get("params", {}))
    try:
        result = spec.run(ctx, params)
    except Exception as exc:
        return CheckResult(
            check.get("id", module_id), module_id, False, f"{type(exc).__name__}: {exc}", failures=[str(exc)]
        )
    collected = [dict(f.values) for f in result.findings]
    failures: list[str] = []
    assertions = 0
    for assertion in check.get("expect", []):
        assertions += 1
        raw_path = assertion["path"]
        if raw_path.startswith("data."):
            found, actual = _dig([result.data], raw_path[5:])
        else:
            found, actual = _dig(collected, raw_path)
        if not found:
            failures.append(f"{assertion['path']}: brak ścieżki w wynikach")
            continue
        ok, why = _compare(actual, assertion)
        if not ok:
            failures.append(f"{assertion['path']}: {why}")
    passed = not failures
    return CheckResult(
        check.get("id", module_id),
        module_id,
        passed,
        check.get("note", ""),
        time.time() - started,
        assertions,
        failures,
    )


SCOPE_ALL = ("all", "full", "")


def case_paths(ctx: Ctx, case_path: str | Path, scope: str) -> list[Path]:
    """Case files that take part in a run.

    ``scope=full`` adds ``cases/<case>.local.json`` next to the public file.
    That split is deliberate: the public case is committed and must not contain
    secret values, so a check that *is* about a secret belongs in the local file,
    which stays untracked.
    """
    public = Path(case_path)
    out = [public]
    if scope == "full":
        for candidate in (
            public.with_name(public.name.replace(".public.json", ".local.json")),
            public.with_name(public.name.replace(".local.json", ".local.json")),
        ):
            if candidate != public and candidate.exists() and candidate not in out:
                out.append(candidate)
    return out


def identify_evidence(
    ctx: Ctx,
    expected_size: int | None,
    expected_sha256: str,
    rehash: bool = False,
    progress: Callable[[str], None] | None = None,
) -> dict:
    """Establish what the evidence is and whether the case agrees.

    The case file's ``image_sha256`` is a **claim**.  It used to be copied into
    the summary as ``image_sha256`` and printed as though the run had confirmed
    it — the runner never opened the image to hash it, so a case file carried
    forward from another device, or edited by hand, or simply stale would
    produce a summary quoting a hash of a file nobody had.  ``report.py`` had
    the same gap from the other side, falling back to the case value whenever the
    ``image_info`` module had not run.

    So the claim is compared against the file the run is actually reading, and
    the result says which of four things happened: the two agree, they disagree,
    there was a claim and we did not check it, or there was nothing to check
    against.  "Did not check" and "checked and fine" must never print the same
    word.

    ``rehash`` is off by default: the reference image is 27 GB and hashes in
    2m51s here.  The size comparison is free and always runs.
    """
    image = ctx.image
    if not image.exists():
        return {
            "path": str(image),
            "size": 0,
            "size_expected": expected_size,
            "size_match": False,
            "sha256": "",
            "sha256_expected": (expected_sha256 or "").strip().lower(),
            "sha256_computed": False,
            "filesystem": "",
            "truncated_bytes": 0,
            "integrity": INTEGRITY_FAIL,
            "detail": f"obraz nie istnieje: {image}",
        }
    if progress:
        progress("identyfikacja obrazu (stat)" + (" + SHA-256" if rehash else ""))
    identity = EvidenceIdentity.identify(
        image,
        hash_image=rehash,
        progress=(lambda done, total: progress(f"SHA-256 {done * 100 // max(total, 1)}%"))  # type: ignore[arg-type]
        if progress and rehash
        else None,
    )
    fs = ctx.fs_handle
    # ``Ext4`` is the only reader today that carries the shortfall, so the
    # attribute is read defensively — a future reader that does not report it
    # must not stop the identity from being established.
    missing = int(getattr(fs, "truncated_bytes", 0) or 0) if fs is not None else 0
    if missing:
        identity = identity.with_truncation(missing)
    return identity.verify_against(
        expected_size=expected_size, expected_sha256=expected_sha256
    )


def run_case(
    ctx: Ctx,
    case_path: str | Path,
    scope: str = "all",
    only: str = "",
    progress: Callable[[str], None] | None = None,
    rehash: bool = False,
) -> dict:
    results: list[CheckResult] = []
    sources: list[str] = []
    image = None
    sha = None
    declared_size = None
    for path in case_paths(ctx, case_path, scope):
        case = load_case(path)
        sources.append(path.name)
        image = image or case.get("image")
        sha = sha or case.get("image_sha256")
        declared_size = declared_size if declared_size is not None else case.get("image_size")
        checks = case.get("checks", [])
        if scope not in SCOPE_ALL:
            checks = [c for c in checks if scope in (c.get("scopes") or ["all"])]
        if only:
            checks = [c for c in checks if only in c.get("id", "")]
        results += [run_check(ctx, check) for check in checks]
    evidence = identify_evidence(ctx, declared_size, sha or "", rehash, progress)
    passed = sum(1 for r in results if r.passed)
    summary = {
        "case": sources[0] if sources else str(case_path),
        "case_files": sources,
        "scope": scope or "all",
        "image": image,
        "image_sha256": sha,
        "evidence": evidence,
        "integrity": evidence["integrity"],
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "checks": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "results": [r.as_dict() for r in results],
    }
    if progress:
        progress(f"{passed}/{len(results)} PASS")
    return summary


def evidence_lines(summary: dict) -> list[tuple[str, str]]:
    """The ``Evidence:`` block, one label per row.

    Printed above the check table because it qualifies every row under it: if the
    image is not the image the case was written against, a green column means
    nothing.  Kept as its own block rather than a check row so it cannot be
    filtered out by ``--only`` or scoped away.
    """
    evidence = summary.get("evidence") or {}
    if not evidence:
        return []
    rows: list[tuple[str, str]] = [
        ("path", str(evidence.get("path", ""))),
        ("size", f"{evidence.get('size', 0)} B"),
    ]
    expected = evidence.get("sha256_expected") or ""
    computed = evidence.get("sha256") or ""
    rows.append(("sha256", computed or "nieobliczony (uruchom verify --rehash)"))
    rows.append(("expected_sha256", expected or "brak w case"))
    rows.append(("integrity", f"{evidence.get('integrity', '?')} — {evidence.get('detail', '')}"))
    if evidence.get("truncated_bytes"):
        rows.append(
            (
                "truncated",
                f"obraz ucięty — brakuje {evidence['truncated_bytes']} B na końcu",
            )
        )
    return rows


def summary_table(summary: dict, color_enabled: bool = True) -> str:
    out = ""
    evidence = evidence_lines(summary)
    if evidence:
        title = color("Evidence:", "bold", color_enabled)
        body = "\n".join(
            f"  {text.pad(label, 17)} {value}" for label, value in evidence
        )
        out = f"{title}\n{body}\n"
    rows = []
    for item in summary.get("results", []):
        rows.append(
            [
                "PASS" if item["passed"] else "FAIL",
                item["check"],
                item["module"],
                item["assertions"],
                f"{item['seconds']:.1f}s",
                "; ".join(item.get("failures", []))[:60],
            ]
        )
    # transliterate=False: this table prints the value an assertion actually
    # read.  Replacing a diacritic here would report a filename that is not in the
    # image, which is the one thing a verification table must not do.
    return out + render_table(
        ["", "check", "module", "assert", "time", "failures"],
        rows,
        color_enabled,
        max_col=60,
        transliterate=False,
    )
