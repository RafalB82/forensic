# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Configuration: defaults, ``config.toml`` beside the data, CLI overrides.

The tool has to work in two situations: from a source checkout, where the case
files and the work directory belong to the repository, and from an installed
package, where they must not be written inside ``site-packages``.  So the data
directory is resolved once, here, and everything else asks for it.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field, asdict
from pathlib import Path

from . import i18n
from .imagemount import DEFAULT_OPTIONS

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def data_root() -> Path:
    """Where cases, work and the config file live.

    A source checkout keeps them in the repository; an installed package uses
    the directory the tool was started from, so nothing is ever written into
    ``site-packages``.
    """
    if (REPO_ROOT / "cases").is_dir() and (REPO_ROOT / ".git").exists():
        return REPO_ROOT
    return Path.cwd()


DATA_ROOT = data_root()
CONFIG_PATH = DATA_ROOT / "config.toml"
CASES_DIR = DATA_ROOT / "cases"

# No image and no EDL directory out of the box: a checkout must not carry a
# path to somebody else's evidence.  Both are filled in from config.toml, from
# --image/--edl-dir, or per case file.
DEFAULT_EDL_DIR = ""
DEFAULT_IMAGE = ""
DEFAULT_MOUNTPOINT = Path("/mnt/forensic")
DEFAULT_WORKDIR = DATA_ROOT / "work"

CATEGORIES = (
    ("image", "menu.category.image"),
    ("accounts", "menu.category.accounts"),
    ("apps", "menu.category.apps"),
    ("timeline", "menu.category.timeline"),
    ("tools", "menu.category.tools"),
    ("report", "menu.category.report"),
)


@dataclass
class Config:
    image: str = str(DEFAULT_IMAGE)
    mountpoint: str = str(DEFAULT_MOUNTPOINT)
    workdir: str = str(DEFAULT_WORKDIR)
    edl_dir: str = str(DEFAULT_EDL_DIR)
    case: str = "default"
    lang: str = i18n.DEFAULT_LANG
    reveal: bool = False
    hash_image_by_default: bool = True
    blockmap_scope: list[str] = field(default_factory=list)
    default_mount_options: str = DEFAULT_OPTIONS
    json_indent: int = 2

    def path(self, key: str) -> Path:
        return Path(getattr(self, key)).expanduser()

    def work(self, *parts: str) -> Path:
        target = Path(self.workdir).expanduser().joinpath(self.case, *parts)
        target.mkdir(parents=True, exist_ok=True)
        return target

    def export_dir(self) -> Path:
        return self.work("exports")

    def as_dict(self) -> dict:
        return asdict(self)


def load(path: Path | None = None) -> Config:
    """Read config.toml if present, otherwise return the defaults."""
    target = path or CONFIG_PATH
    config = Config()
    if target.exists():
        data = tomllib.loads(target.read_text(encoding="utf-8"))
        for key, value in data.get("forensic", {}).items():
            if hasattr(config, key):
                setattr(config, key, value)
        for key, value in data.get("paths", {}).items():
            if hasattr(config, key):
                setattr(config, key, value)
    return config


def template() -> str:
    return """\
# forensic configuration (edit, then re-run the tool)
#
# image and edl_dir are empty on purpose: a checkout carries no path to
# somebody else's evidence.  Fill them in, or pass --image / --edl-dir.
[forensic]
image = "%(image)s"
mountpoint = "%(mountpoint)s"
workdir = "%(workdir)s"
edl_dir = "%(edl_dir)s"
case = "default"
lang = "pl"
reveal = false
hash_image_by_default = true
default_mount_options = "%(mount_options)s"

[blockmap]
# empty = built-in default scope
scope = []
""" % {
        "image": DEFAULT_IMAGE,
        "mountpoint": DEFAULT_MOUNTPOINT,
        "workdir": DEFAULT_WORKDIR,
        "edl_dir": DEFAULT_EDL_DIR,
        "mount_options": DEFAULT_OPTIONS,
    }


def ensure_config(path: Path | None = None) -> Path:
    """Create a starter config.toml when missing; return its path."""
    target = path or CONFIG_PATH
    if not target.exists():
        target.write_text(template(), encoding="utf-8")
    return target


def from_args(args) -> Config:
    """Apply CLI overrides on top of the config file."""
    config = load()
    for name in ("image", "mountpoint", "workdir", "edl_dir", "case", "lang"):
        value = getattr(args, name, None)
        if value:
            setattr(config, name, str(value))
    if getattr(args, "reveal", False):
        config.reveal = True
    if getattr(args, "no_hash", False):
        config.hash_image_by_default = False
    i18n.set_lang(config.lang)
    i18n.set_reveal(config.reveal)
    return config
