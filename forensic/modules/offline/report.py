# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""The report: a document assembled from what every other module measured.

The findings of a session are a log; this module turns them (and the machine
output they produced) into a document with a headline answer, the accounts
table, the last session and the list of sources.  It works from the exports in
``work/<case>/exports`` so a document can be rebuilt long after the run, and it
names the sources that are missing instead of hiding the gap.
"""

from __future__ import annotations

from ...core import i18n
from ...core.export import to_json
from ...core.findings import ModuleResult
from ...core.reporting import build, to_markdown
from ...core.session import Ctx
from ..registry import BOOL, CHOICE, ModuleSpec, Param, register


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("report")
    fmt = str(params.get("format") or "md")
    title = str(params.get("title") or f"forensic — {ctx.image.name}")
    reveal = bool(params.get("reveal", False))
    previous = i18n.reveal()
    if reveal:
        i18n.set_reveal(True)
    try:
        masker = ctx.masker
        document = build(ctx)
        document["title"] = title
        if fmt == "json":
            path = to_json(ctx.work("reports") / "report.json", document, masker)
        else:
            body = to_markdown(document, masker)
            path = ctx.work("reports") / "report.md"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
    finally:
        i18n.set_reveal(previous)
    complete = not document["missing_sources"]
    res.add(
        "ok" if complete else "warn",
        f"Raport: {len(document['verdicts'])} werdyktów, {len(document['sources'])} źródeł",
        detail=(
            "dokument złożony z eksportów modułów"
            + ("" if complete else f"; brakuje {len(document['missing_sources'])} źródeł")
        ),
        values={
            "path": str(path),
            "format": fmt,
            "language": i18n.get_lang(),
            "title": title,
            "verdicts": len(document["verdicts"]),
            "accounts": len(document["accounts"]),
            "credentials": len(document["credentials"]),
            "sources": len(document["sources"]),
            "missing_sources": document["missing_sources"],
            "complete": complete,
            "findings_total": document["findings_total"],
            "runs": document["runs"],
            "generated": document["generated_utc"],
        },
        artifacts=[str(path)],
    )
    for item in document["verdicts"]:
        res.add(
            "info",
            f"{item['topic']}: {item['answer']}",
            detail=item["evidence"],
            values={**item, "module": "report"},
        )
    res.data = document
    return ctx.record(res)


register(
    ModuleSpec(
        id="report",
        category="report",
        title="mod.report.title",
        summary="mod.report.summary",
        params=[
            Param(key="format", label="param.format", default="md", kind=CHOICE, choices=("md", "json")),
            Param(key="title", label="Tytuł raportu", default="", kind="str"),
            Param(key="reveal", label="param.reveal_report", default=False, kind=BOOL),
        ],
        run=run,
        needs_image=False,
    )
)
