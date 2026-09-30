# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Configuration defaults, private files, and the report's honesty rules.

Three things that fail quietly, checked together because they are all about the
same property: what the tool says when it does not know something.

* a checkout ships no image path, and ``Path("")`` is ``"."`` — which exists —
  so "not configured" has to be decided from the string, not from the filesystem;
* ``secrets.json`` and ``session.json`` are written 0600, including when the file
  was already there with looser permissions;
* records a module could not read are counted in the report rather than dropped.
"""

from __future__ import annotations

import os
import stat


from forensic.acquisition import preflight
from forensic.core import config as config_mod
from forensic.core.export import write_private
from forensic.core.reporting import Builder


def test_no_image_or_edl_path_ships_with_the_tool():
    """A checkout must not carry a path to somebody else's evidence."""
    assert config_mod.DEFAULT_IMAGE == ""
    assert config_mod.DEFAULT_EDL_DIR == ""
    assert config_mod.Config().image == ""
    assert config_mod.Config().edl_dir == ""


def test_unconfigured_image_is_not_the_current_directory():
    """``Path("")`` is ``.`` and ``.`` exists, so emptiness is read from the config."""
    assert str(config_mod.Config().path("image")) == "."


def test_preflight_says_the_image_is_not_configured(ctx):
    report = preflight.collect("", "", hash_image=False)
    assert report["image"]["configured"] is False
    assert report["image"]["exists"] is False
    problems = preflight.problems(report)
    assert any("nie skonfigurowano obrazu" in item for item in problems), problems


def test_preflight_does_not_stat_the_current_directory_as_an_image():
    """Without the guard the report would claim a 4 KiB image that is a folder."""
    report = preflight.image_info("")
    assert "size" not in report
    assert report["exists"] is False


def test_preflight_reports_a_directory_as_not_an_image(tmp_path):
    assert preflight.image_info(str(tmp_path))["exists"] is False


def test_preflight_keeps_a_real_image(tmp_path):
    image = tmp_path / "userdata.img"
    image.write_bytes(b"\0" * 4096)
    report = preflight.image_info(str(image))
    assert report["exists"] is True
    assert report["size"] == 4096


def test_preflight_edl_dir_empty_is_not_the_repository():
    """``Path("")`` is ``.``, which is a directory — and has a pyproject.toml."""
    report = preflight.edl_info("")
    assert report["configured"] is False
    assert report["exists"] is False
    assert "version" not in report


def test_mount_options_are_hardened():
    """The one place the kernel parses the image mounts it as noexec, nosuid, nodev."""
    from forensic.core.imagemount import DEFAULT_OPTIONS

    for flag in ("ro", "nodev", "nosuid", "noexec", "norecovery"):
        assert flag in DEFAULT_OPTIONS.split(","), DEFAULT_OPTIONS
    assert config_mod.Config().default_mount_options == DEFAULT_OPTIONS


def test_write_private_creates_0600(tmp_path):
    path = write_private(tmp_path / "sub" / "secrets.json", "{}")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.read_text() == "{}"


def test_write_private_tightens_an_existing_loose_file(tmp_path):
    """``os.open``'s mode only applies to a file it creates, so the chmod matters."""
    path = tmp_path / "session.json"
    path.write_text("stale")
    os.chmod(path, 0o644)
    write_private(path, "fresh")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.read_text() == "fresh"


def test_report_counts_records_that_were_skipped(ctx):
    """A module that could not read something says so in the document.

    The export shape is the module's own ``res.data``, which is what
    ``to_json`` writes — no wrapper.
    """
    exports = ctx.work("exports")
    (exports / "fs_timeline.json").write_text(
        '{"since": 0, "scan": {"walk_errors": 3, '
        '"walk_error_detail": [{"path": "/data/a", "error": "boom"}]}}'
    )
    doc = Builder(ctx).build()
    assert doc["skipped_total"] == 3
    assert doc["skipped"][0]["module"] == "fs_timeline"
    assert doc["skipped"][0]["detail"][0]["path"] == "/data/a"
    markdown = __import__(
        "forensic.core.reporting", fromlist=["to_markdown"]
    ).to_markdown(doc)
    assert "Pominięte rekordy: 3" in markdown


def test_report_has_no_skipped_section_when_nothing_was_skipped(ctx):
    doc = Builder(ctx).build()
    assert doc["skipped"] == []
    assert doc["skipped_total"] == 0
