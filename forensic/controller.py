# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Controller: session lifecycle, module dispatch and non-interactive CLI.

Both frontends call into this object; it owns the config, the context and the
module registry, and it is also the entry point used by ``--cli`` for scripting
and tests.
"""

from __future__ import annotations

from collections.abc import Callable

from .core import config as config_mod
from .core import i18n
from .core.export import color
from .core.findings import ModuleResult
from .core.session import Ctx
from .modules import registry
from .ui import render


class Controller:
    def __init__(self, config: config_mod.Config, color_enabled: bool = True) -> None:
        self.config = config
        self.color = color_enabled
        self.ctx = Ctx(config=config, color=color_enabled)
        self._progress_cb: Callable[[str], None] | None = None

    def set_progress(self, callback: Callable[[str], None] | None) -> None:
        self._progress_cb = callback
        self.ctx.progress_cb = callback

    def banner(self) -> str:
        return f"{i18n.t('app.name')} — {i18n.t('app.tagline')}"

    def run_module(self, module_id: str, params: dict | None = None) -> ModuleResult | None:
        """Run one module by id; prints errors instead of raising."""
        spec = registry.by_id(module_id)
        if spec is None or spec.run is None:
            print(color(f"{i18n.t('common.error')}: {module_id}", "red", self.color))
            return None
        payload = spec.defaults()
        payload.update(params or {})
        if self._progress_cb:
            self._progress_cb(f"{i18n.t('common.run')}: {spec.id} …")
        try:
            result = spec.run(self.ctx, payload)
        except FileNotFoundError as exc:
            print(color(f"{i18n.t('msg.no_image')}: {exc}", "red", self.color))
            return None
        except KeyboardInterrupt:
            print()
            print(color(i18n.t("common.cancelled"), "yellow", self.color))
            return None
        except Exception as exc:  # pragma: no cover - defensive
            print(color(f"{i18n.t('common.error')}: {type(exc).__name__}: {exc}", "red", self.color))
            import traceback

            traceback.print_exc()
            return None
        finally:
            self._progress_cb = None
            self.ctx.progress_cb = None
        return result

    def save(self) -> None:
        self.ctx.save()

    def close(self) -> None:
        self.ctx.close()

    def run_menu(self) -> int:
        from .ui.menu import MenuUI

        return MenuUI(self).run()

    def run_curses(self) -> int:
        from .ui.curses_ui import CursesUI

        return CursesUI(self).run()

    def run_cli(self, module_id: str, params: dict, show: bool = True) -> int:
        result = self.run_module(module_id, params)
        if result is None:
            return 2
        if show:
            render.print_result(result, self.ctx.masker, self.color)
        worst = SEVERITY_RANK.get(result.worst, 0)
        return 1 if worst >= 3 else 0


SEVERITY_RANK = {"info": 0, "ok": 1, "warn": 2, "finding": 3, "critical": 4}
