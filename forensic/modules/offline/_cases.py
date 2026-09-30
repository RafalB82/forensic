# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Locating the case file that describes the reference image."""

from __future__ import annotations

from ...core.config import CASES_DIR


def default_case_path(ctx) -> str:
    """``cases/<case>.public.json`` when present, else any case for that name."""
    name = ctx.config.case
    public = CASES_DIR / f"{name}.public.json"
    if public.exists():
        return str(public)
    local = CASES_DIR / f"{name}.local.json"
    if local.exists():
        return str(local)
    return str(public)


def list_cases() -> list[str]:
    if not CASES_DIR.is_dir():
        return []
    return sorted(p.stem for p in CASES_DIR.glob("*.json"))
