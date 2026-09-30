# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Module registry: one declarative entry per analysis module.

Both frontends build their forms from these specs, so adding a module means
adding one file plus one :class:`ModuleSpec` here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from collections.abc import Callable

from ..core.session import Ctx
from ..core.findings import ModuleResult

STR = "str"
INT = "int"
BOOL = "bool"
PATH = "path"
CHOICE = "choice"
LIST = "list"


@dataclass
class Param:
    """One module parameter, shown in the menu form and passed to ``run``."""

    key: str
    label: str
    default: Any = None
    kind: str = STR
    help: str = ""
    choices: tuple = ()

    def hint(self) -> str:
        if self.kind == BOOL:
            return "true/false"
        if self.kind == CHOICE:
            return "|".join(str(c) for c in self.choices)
        if self.default is None or self.default == "":
            return ""
        if self.kind == LIST:
            return ",".join(str(x) for x in self.default) if isinstance(self.default, (list, tuple)) else str(self.default)
        return str(self.default)


@dataclass
class ModuleSpec:
    """Declarative description of a module plus its implementation."""

    id: str
    category: str
    title: str
    summary: str
    params: list[Param] = field(default_factory=list)
    run: Callable[[Ctx, dict], ModuleResult] | None = None
    needs_image: bool = True
    needs_sudo: bool = False

    def defaults(self) -> dict:
        return {p.key: p.default for p in self.params}


REGISTRY: list[ModuleSpec] = []


def register(spec: ModuleSpec) -> ModuleSpec:
    REGISTRY.append(spec)
    return spec


def _ensure_loaded() -> None:
    if not REGISTRY:
        load_modules()


def by_id(module_id: str) -> ModuleSpec | None:
    _ensure_loaded()
    for spec in REGISTRY:
        if spec.id == module_id:
            return spec
    return None


def in_category(category: str) -> list[ModuleSpec]:
    _ensure_loaded()
    return [spec for spec in REGISTRY if spec.category == category]


def load_modules() -> None:
    """Import the module implementations so they register themselves."""
    if REGISTRY:
        return
    from . import offline  # noqa: F401


def all_specs() -> list[ModuleSpec]:
    if not REGISTRY:
        load_modules()
    return list(REGISTRY)
