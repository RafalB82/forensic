# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Findings, module results and the small vocabulary the report builder uses."""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import i18n
from .masking import Secret

SEVERITIES = ("info", "ok", "warn", "finding", "critical")


def utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


@dataclass
class Finding:
    """One result line: what was found, how certain we are, and the evidence."""

    severity: str
    title: str
    detail: str = ""
    values: dict[str, Any] = field(default_factory=dict)
    artifacts: list[str] = field(default_factory=list)
    module: str = ""

    def severity_label(self) -> str:
        return i18n.t(f"sev.{self.severity}")

    def as_dict(self) -> dict:
        return {
            "severity": self.severity,
            "severity_label": self.severity_label(),
            "title": self.title,
            "detail": self.detail,
            "values": self.values,
            "artifacts": self.artifacts,
            "module": self.module,
        }


@dataclass
class ModuleResult:
    """Everything one module produced: findings, exports and free-form notes."""

    module_id: str
    findings: list[Finding] = field(default_factory=list)
    exports: list[Path] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    started: str = field(default_factory=utc_now)
    seconds: float = 0.0

    def add(
        self,
        severity: str,
        title: str,
        detail: str = "",
        values: dict | None = None,
        artifacts: list | None = None,
    ) -> ModuleResult:
        self.findings.append(
            Finding(
                severity=severity,
                title=title,
                detail=detail,
                values=values or {},
                artifacts=[str(a) for a in (artifacts or [])],
                module=self.module_id,
            )
        )
        return self

    def note(self, text: str) -> ModuleResult:
        self.notes.append(text)
        return self

    def export(self, path: Path) -> ModuleResult:
        self.exports.append(path)
        return self

    @property
    def worst(self) -> str:
        order = list(SEVERITIES)
        if not self.findings:
            return "info"
        return max((f.severity for f in self.findings), key=order.index)

    def counts(self) -> dict[str, int]:
        out = {sev: 0 for sev in SEVERITIES}
        for finding in self.findings:
            out[finding.severity] = out.get(finding.severity, 0) + 1
        return out

    def masked_values(self) -> list[dict]:
        return [dict(f.values) for f in self.findings]

    def secrets(self) -> list[Secret]:
        found: list[Secret] = []
        for finding in self.findings:
            for value in finding.values.values():
                if isinstance(value, Secret):
                    found.append(value)
        return found
