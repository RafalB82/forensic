#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""forensic — offline forensics toolkit for Android partition images.

Two frontends (numbered menu, curses TUI) plus a non-interactive CLI share one
controller.  Nothing in the analysis layer imports the external EDL toolchain and
nothing in this tool talks to the network.
"""

from __future__ import annotations

import argparse

from .core import config as config_mod
from .core import i18n
from .core.export import color, render_kv, set_color
from .modules import registry
from .ui import base


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="forensic",
        description="Offline forensics for Android partition images (ext4, SQLite, Chromium, AOSP).",
        epilog="Try: forensic.py --ui menu   |   forensic.py --cli image_info",
    )
    parser.add_argument("--ui", choices=("auto", "menu", "curses"), default="auto")
    parser.add_argument("--lang", choices=("pl", "en"), default=None)
    parser.add_argument("--image", default=None, help="path to the partition image")
    parser.add_argument("--mountpoint", default=None)
    parser.add_argument("--workdir", default=None)
    parser.add_argument("--edl-dir", default=None, help="external edl toolchain directory")
    parser.add_argument("--case", default=None, help="case name, e.g. redmi3")
    parser.add_argument("--reveal", action="store_true", help="print secrets in the clear")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--no-hash", action="store_true", help="skip image SHA-256 by default")
    parser.add_argument("--cli", default=None, help="run one module and exit")
    parser.add_argument("--param", action="append", default=[], metavar="KEY=VALUE")
    parser.add_argument("--list", action="store_true", help="list modules and exit")
    parser.add_argument("--preflight", action="store_true", help="environment check and exit")
    parser.add_argument("--version", action="store_true")
    return parser


def coerce(value: str) -> object:
    """Turn a --param string into bool / list / int / text."""
    import json

    lowered = value.strip()
    if lowered.lower() in ("true", "false"):
        return lowered.lower() == "true"
    if lowered.startswith("[") or lowered.startswith("{"):
        try:
            return json.loads(lowered)
        except Exception:
            pass
    if lowered.startswith("[") and lowered.endswith("]"):
        lowered = lowered[1:-1]
    if "," in lowered:
        return [part.strip() for part in lowered.split(",") if part.strip()]
    try:
        return int(lowered)
    except ValueError:
        return lowered


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.version:
        from .core.reporting import LICENSE, VERSION

        print(f"forensic {VERSION} — {LICENSE}")
        return 0
    color_enabled = base.supports_color() and not args.no_color
    config = config_mod.from_args(args)
    if args.lang:
        i18n.set_lang(args.lang)
        config.lang = args.lang
    if args.no_color:
        color_enabled = False
    set_color(color_enabled)
    from forensic.controller import Controller

    controller = Controller(config, color_enabled=color_enabled)
    try:
        if args.list:
            specs = registry.all_specs()
            for spec in specs:
                print(f"{spec.id:20s} [{spec.category:9s}] {i18n.t(spec.title)}")
            return 0
        if args.preflight:
            from forensic.acquisition import preflight
            from forensic.modules.offline._cases import default_case_path

            report = preflight.collect(config.edl_dir, config.image, hash_image=False)
            report["case_file"] = default_case_path(controller.ctx)
            print(render_kv(report, color_enabled))
            issues = preflight.problems(report)
            for issue in issues:
                print(color("  ! " + issue, "yellow", color_enabled))
            return 0 if not issues else 1
        if args.cli:
            params: dict = {}
            for item in args.param:
                if "=" in item:
                    key, value = item.split("=", 1)
                    params[key.strip()] = coerce(value)
            code = controller.run_cli(args.cli, params)
            controller.save()
            return code
        choice = args.ui
        if choice == "auto":
            choice = "curses" if base.is_tty() and base.supports_color() else "menu"
        if choice == "curses":
            try:
                return controller.run_curses()
            except Exception as exc:  # pragma: no cover - terminal dependent
                print(color(f"curses niedostępne ({exc}); przechodzę na menu", "yellow", color_enabled))
        return controller.run_menu()
    finally:
        controller.save()
        controller.close()


if __name__ == "__main__":
    raise SystemExit(main())
