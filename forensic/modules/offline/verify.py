# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Verification module: run a case file and report PASS/FAIL per check."""

from __future__ import annotations

from ...core import i18n
from ...core.export import to_json
from ...core.findings import ModuleResult
from ...core.session import Ctx
from ...verify.runner import run_case, summary_table
from ..registry import CHOICE, ModuleSpec, Param, register
from ..offline._cases import default_case_path


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("verify")
    case = str(params.get("case") or default_case_path(ctx))
    scope = str(params.get("scope", "all"))
    only = str(params.get("only", ""))
    try:
        summary = run_case(ctx, case, scope=scope, only=only, progress=ctx.log)
    except FileNotFoundError:
        res.add("critical", f"Brak pliku case: {case}")
        return ctx.record(res)
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
    verdict = "ok" if summary["failed"] == 0 else "critical"
    res.add(
        verdict,
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
        ],
        run=run,
    )
)
