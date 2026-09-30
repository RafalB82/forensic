# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Verification module: run a case file and report PASS/FAIL per check."""

from __future__ import annotations

from ...core import i18n
from ...core.evidence import INTEGRITY_FAIL, INTEGRITY_NOT_CHECKED, INTEGRITY_PASS
from ...core.export import to_json
from ...core.findings import ModuleResult
from ...core.session import Ctx
from ...verify.runner import run_case, summary_table
from ..registry import BOOL, CHOICE, ModuleSpec, Param, register
from ..offline._cases import default_case_path


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("verify")
    case = str(params.get("case") or default_case_path(ctx))
    scope = str(params.get("scope", "all"))
    only = str(params.get("only", ""))
    rehash = bool(params.get("rehash", False))
    try:
        summary = run_case(
            ctx, case, scope=scope, only=only, progress=ctx.log, rehash=rehash
        )
    except FileNotFoundError:
        res.add("critical", f"Brak pliku case: {case}")
        return ctx.record(res)

    # The evidence verdict comes first and is reported separately from the check
    # tally, because it does not average into it.  33 of 33 checks passing on the
    # wrong image is a worse report than 0 of 33 passing on the right one, and a
    # reader scanning for the verdict has to find it without knowing which.
    evidence = summary.get("evidence") or {}
    verdict = evidence.get("integrity", "")
    if verdict == INTEGRITY_FAIL:
        res.add(
            "critical",
            "Integralność dowodu: FAIL",
            detail=evidence.get("detail", ""),
            values=evidence,
        )
    elif verdict == INTEGRITY_NOT_CHECKED:
        res.add(
            "warn",
            "Integralność dowodu: nie sprawdzono",
            detail=evidence.get("detail", "")
            + " — uruchom verify z parametrem rehash=true, aby przeliczyć",
            values=evidence,
        )
    else:
        res.add(
            "ok" if verdict == INTEGRITY_PASS else "info",
            f"Integralność dowodu: {verdict or 'brak danych'}",
            detail=evidence.get("detail", ""),
            values=evidence,
        )
    if evidence.get("truncated_bytes"):
        res.add(
            "critical",
            f"Obraz ucięty: brakuje {evidence['truncated_bytes']} B",
            detail=(
                "geometria filesystemu deklaruje więcej bloków, niż jest w pliku; "
                "pliki za końcem obrazu są NIEODCZYTALNE, nie nieistniejące"
            ),
            values=evidence,
        )

    for item in summary["results"]:
        if item["passed"]:
            res.add(
                "ok",
                f"{i18n.t('msg.verify_pass')}: {item['check']}",
                values={"module": item["module"], "assertions": item["assertions"], "seconds": item["seconds"]},
            )
        else:
            res.add(
                "critical",
                f"{i18n.t('msg.verify_fail')}: {item['check']}",
                detail="; ".join(item.get("failures", [])),
                values={"module": item["module"], "failures": item.get("failures", [])},
            )
    # A failed integrity check makes the whole run inconclusive regardless of how
    # many assertions passed, so the module verdict follows it rather than the
    # assertion tally.
    if summary["failed"] == 0 and verdict != INTEGRITY_FAIL:
        module_verdict = "ok"
    else:
        module_verdict = "critical"
    res.add(
        module_verdict,
        f"{summary['passed']}/{summary['checks']} testów zaliczonych",
        values={k: summary[k] for k in ("case", "image", "checks", "passed", "failed", "generated")},
    )
    res.data = summary
    path = to_json(ctx.work("exports") / "verify.json", summary, ctx.masker)
    res.export(path)
    print(summary_table(summary, ctx.color))
    return ctx.record(res)


register(
    ModuleSpec(
        id="verify",
        category="report",
        title="mod.verify.title",
        summary="mod.verify.summary",
        params=[
            Param(key="case", label="param.case", default="", kind="path"),
            Param(
                key="scope",
                label="param.scope_verify",
                default="all",
                kind=CHOICE,
                choices=("all", "full", "image", "accounts", "apps", "timeline"),
            ),
            Param(key="only", label="Filtr po nazwie testu", default="", kind="str"),
            Param(
                key="rehash",
                label="Przelicz SHA-256 obrazu (wolne: ~3 min na 27 GB)",
                default=False,
                kind=BOOL,
            ),
        ],
        run=run,
    )
)
