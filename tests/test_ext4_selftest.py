# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""The ext4 reader against images it builds itself.

This is the module the README offers as ``ext4_selftest``, called here as a test
rather than through the menu.  It needs no evidence image: it runs ``mke2fs`` to
build a set of ext2/3/4 variants — including ones the reader is supposed to
*refuse* — and checks our reading against ``dumpe2fs`` and, for the carved
fixtures, against a known PNG and gzip written into the image beforehand.

Without ``e2fsprogs`` the module reports itself unavailable instead of failing,
because a parser test that needs a filesystem tool is not a unit test; on CI the
package is installed rather than skipped.
"""

from __future__ import annotations

import pytest

from forensic.modules.offline import ext4_selftest


def _tools() -> tuple[bool, str]:
    missing = [
        name for name in ("mke2fs", "dumpe2fs", "debugfs") if not ext4_selftest._tool(name)
    ]
    return not missing, ", ".join(missing)


requires_e2fsprogs = pytest.mark.skipif(
    not _tools()[0], reason=f"brak narzędzi e2fsprogs: {_tools()[1]}"
)


@pytest.fixture(scope="module")
def selftest_result(tmp_path_factory):
    """Run the whole self-test once; it builds dozens of images."""
    from forensic.core.config import Config
    from forensic.core.session import Ctx

    workdir = tmp_path_factory.mktemp("selftest")
    ctx = Ctx(config=Config(image="", workdir=str(workdir), case="pytest"), color=False)
    result = ext4_selftest.run(ctx, {})
    return result.data


@requires_e2fsprogs
def test_no_silent_emptiness(selftest_result):
    """A variant the reader accepts must not report an empty tree."""
    assert selftest_result["silent"] == 0, [
        e["name"] for e in selftest_result["results"] if e.get("silent")
    ]


@requires_e2fsprogs
def test_acceptance_matches_expectation(selftest_result):
    """Every variant is either accepted or refused, as declared — never both ways."""
    assert selftest_result["unexpected"] == []
    assert selftest_result["accepted"] > 0, "żaden wariant nie został przyjęty"


@requires_e2fsprogs
def test_geometry_agrees_with_dumpe2fs(selftest_result):
    assert selftest_result["geometry_mismatched"] == []


@requires_e2fsprogs
def test_format_detection(selftest_result):
    formats = selftest_result["formats"]
    assert formats["ok"], formats["wrong"]
    # A file with no magic must come back as "not recognised", never as a guess.
    assert formats["unknown_kind"] == "nieznany"


@requires_e2fsprogs
def test_free_space_matches_blockmap(selftest_result):
    freespace = selftest_result["free_space"]
    assert freespace["ok"], freespace


@requires_e2fsprogs
def test_unwritten_bitmap_group_still_agrees_with_dumpe2fs(selftest_result):
    """A BLOCK_UNINIT group without the feature must not be read as all-free.

    e2fsprogs 1.47.0 (which is what the CI runner ships) leaves the block bitmaps
    of the sparse-super groups unwritten and sets ``BLOCK_UNINIT`` on them
    *without* the ``uninit_bg`` feature.  The bitmap on disk is then all zeros,
    and inverting it counts the backup superblock, the backup descriptor table
    and the reserved GDT area as free: 56 797 against the 56 023 that
    ``dumpe2fs`` and ``e2fsck -fn`` both report for a volume both call clean.

    Where that state occurs the two tools and this reader are answering the same
    question, so they must give the same number.  This is the assertion that
    failed in CI, and it is kept separate from ``ok`` because it is about *which*
    variants are comparable rather than about the reader in general.
    """
    for variant in selftest_result["free_space"]["variants"]:
        if not variant.get("uninit_untrusted"):
            continue
        assert not variant.get("uninit_feature"), (
            f"{variant['name']}: uninit_bg włączone, grupa nie jest podejrzana"
        )
        assert variant["dumpe2fs_agrees"] is True, (
            f"{variant['name']}: mamy {variant['free_blocks']} wolnych, "
            f"dumpe2fs {variant['dumpe2fs_free']} "
            f"(grupy bez zapisanego bitmapy: {variant['uninit_untrusted']})"
        )


@requires_e2fsprogs
def test_written_bitmap_groups_agree_with_the_bitmap_bytes(selftest_result):
    """The second opinion on our own loop, over the groups where it applies."""
    for variant in selftest_result["free_space"]["variants"]:
        assert variant["count_agrees"], (
            f"{variant['name']}: {variant['measured_blocks']} vs "
            f"{variant['measured_zero_bits']} zerowych bitów w mierzonych grupach"
        )
        assert variant["zero_bits"] >= variant["measured_zero_bits"]


@requires_e2fsprogs
def test_carving_finds_the_planted_objects(selftest_result):
    """The PNG and gzip written into a free run come back byte for byte."""
    carve = selftest_result["carve_test"]
    if not carve.get("available"):
        pytest.skip(f"carve self-test unavailable: {carve.get('why', '')}")
    assert carve["ok"], carve
    content = carve["content"]
    assert content["png_recovered_exact"] is True, "wyryzowany PNG nie jest bajt w bajt"
    assert content["gzip_recovered_exact"] is True, "wyryzowany gzip nie jest bajt w bajt"
    # The names the carver recovers must not include the impostor planted to
    # prove that a signature match alone is not an attribution.
    assert content["impostor_carved"] is False


@requires_e2fsprogs
def test_erofs_and_f2fs_when_the_tools_are_there(selftest_result):
    """EROFS and F2FS readers are checked the same way, if the tools exist."""
    for key in ("erofs", "f2fs"):
        part = selftest_result[key]
        if not part.get("available"):
            continue
        assert part["ok"], part
