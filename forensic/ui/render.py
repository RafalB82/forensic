# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Rendering of findings and module results, shared by both frontends."""

from __future__ import annotations

from collections.abc import Sequence

from ..core import i18n
from ..core.export import SEVERITY_COLOR, color, hr, render_kv, render_table
from ..core.findings import Finding, ModuleResult
from .base import show_text

ICON = {"info": "·", "ok": "+", "warn": "!", "finding": "»", "critical": "!"}


def status_line(ctx, color_enabled: bool = True) -> str:
    mount = i18n.t("status.not_mounted")
    try:
        from ..core import imagemount

        info = imagemount.find_mount_for(str(ctx.image))
        if info is not None:
            mount = f"{i18n.t('status.mounted_ro')}: {info.mountpoint}"
    except Exception:
        pass
    reveal_state = i18n.t("status.revealed") if i18n.reveal() else i18n.t("status.masked")
    parts = [
        f"{i18n.t('status.image')}: {ctx.image}",
        f"{i18n.t('status.mount')}: {mount}",
        f"{i18n.t('status.work')}: {ctx.workdir}",
        f"{i18n.t('status.lang')}: {i18n.get_lang()}",
        f"{i18n.t('status.reveal')}: {reveal_state}",
    ]
    return color(" | ".join(parts), "grey", color_enabled)


def finding_text(
    finding: Finding, masker, color_enabled: bool = True, index: int = 0
) -> str:
    tone = SEVERITY_COLOR.get(finding.severity, "grey")
    head = color(
        f"{ICON.get(finding.severity, '·')} [{index}] "
        f"{color(finding.severity_label(), tone, color_enabled)}  {finding.title}",
        "bold",
        color_enabled,
    )
    body = [head]
    if finding.detail:
        body.append(color("    " + finding.detail.replace("\n", "\n    ")[:2000], "grey", color_enabled))
    if finding.values:
        rendered = masker.value(finding.values)
        body.append(render_kv(rendered, color_enabled, indent="    "))
    if finding.artifacts:
        for artifact in finding.artifacts[:10]:
            body.append(color(f"    → {artifact}", "cyan", color_enabled))
    return "\n".join(body)


def result_text(result: ModuleResult, masker, color_enabled: bool = True) -> str:
    counts = result.counts()
    summary = "  ".join(
        f"{color(name, SEVERITY_COLOR.get(name, 'grey'), color_enabled)}:{count}"
        for name, count in counts.items()
        if count
    )
    head = color(
        f"{result.module_id}  ({result.seconds:.1f}s)  {summary}", "bold", color_enabled
    )
    lines = [head, color(hr(76), "grey", color_enabled)]
    for index, finding in enumerate(result.findings, start=1):
        lines.append(finding_text(finding, masker, color_enabled, index))
        lines.append("")
    if result.notes:
        for note in result.notes:
            lines.append(color(f"note: {note}", "grey", color_enabled))
    if result.exports:
        lines.append(color(f"{i18n.t('common.exports')}:", "grey", color_enabled))
        for export in result.exports:
            lines.append(color(f"  → {export}", "cyan", color_enabled))
    return "\n".join(lines)


#: Columns of the module list.  The identifier is deliberately not one of them.
#: It is what you type on the command line, so it is useful — and useless to
#: somebody choosing what to run, who reads titles.  Carrying it here cost 16
#: columns that the summary needed, and the summary was the part that explains
#: what a module does.  The identifier is still shown, in the module's own screen.
SPEC_COLUMNS = ("#", "title", "summary")


def specs_table(specs: Sequence, color_enabled: bool = True) -> str:
    rows = []
    for index, spec in enumerate(specs, start=1):
        rows.append([index, i18n.t(spec.title), i18n.t(spec.summary)])
    return render_table(list(SPEC_COLUMNS), rows, color_enabled, max_col=52)


def results_overview(results: Sequence[ModuleResult], color_enabled: bool = True) -> str:
    rows = []
    for result in results:
        counts = result.counts()
        worst = result.worst
        rows.append(
            [
                result.module_id,
                f"{result.seconds:.1f}s",
                color(worst, SEVERITY_COLOR.get(worst, "grey"), color_enabled),
                counts.get("ok", 0),
                counts.get("warn", 0),
                counts.get("finding", 0),
                counts.get("critical", 0),
                result.started,
            ]
        )
    return render_table(
        ["module", "time", "worst", "ok", "warn", "finding", "critical", "started"],
        rows,
        color_enabled,
    )


def print_result(result: ModuleResult, masker, color_enabled: bool = True) -> None:
    show_text(result_text(result, masker, color_enabled), color_enabled)
