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


# --- corrupted bytes ---------------------------------------------------------
# The variants above test *formats* the reader should handle or refuse.  These
# test the reader against an image whose bytes have been damaged, where the one
# invariant is that it never opens without complaint and returns nothing — the
# silent failure a report cannot tell from an empty filesystem.


@requires_e2fsprogs
def test_corrupted_image_is_never_silently_empty(selftest_result):
    """The invariant, over every corruption case.

    Not "it does not crash" — that was always true.  ``silent`` is the bucket
    where the reader opened the image, raised nothing, and produced an empty
    tree.
    """
    corruption = selftest_result["corruption"]
    if not corruption.get("available"):
        pytest.skip(corruption.get("why", "brak e2fsprogs"))
    assert corruption["cases"] >= 8, corruption["cases"]
    assert corruption["silent"] == [], [
        e["name"] for e in corruption["detail"] if e.get("silent")
    ]


@requires_e2fsprogs
def test_each_corruption_meets_its_own_expectation(selftest_result):
    """Per-case: refuse where the bytes cannot be trusted, accept where they can.

    A zeroed block bitmap is readable and the bitmap really does say what the
    reader will report, so refusing it would be refusing the truth.  A superblock
    whose magic is gone is not readable and must be refused.
    """
    corruption = selftest_result["corruption"]
    if not corruption.get("available"):
        pytest.skip(corruption.get("why", "brak e2fsprogs"))
    assert corruption["wrong"] == [], [
        e["name"] for e in corruption["detail"] if e.get("unexpected")
    ]


@requires_e2fsprogs
def test_extent_past_end_of_image_is_truncation_not_padding(selftest_result):
    """The regression this whole turn started from, in the self-test's own terms.

    An extent claiming 32768 blocks on a 16384-block volume reaches past the end
    of the image.  Zero-filling those blocks would give the reader a directory of
    NULs and no error; the read has to say the evidence stops there.
    """
    corruption = selftest_result["corruption"]
    if not corruption.get("available"):
        pytest.skip(corruption.get("why", "brak e2fsprogs"))
    by_name = {e["name"]: e for e in corruption["detail"]}
    extent = by_name["extent_count_huge"]
    assert extent["truncated"] is True, extent
    assert "TruncatedEvidenceError" in extent["error"], extent


@requires_e2fsprogs
def test_inode_table_beyond_end_of_image_is_truncation(selftest_result):
    corruption = selftest_result["corruption"]
    if not corruption.get("available"):
        pytest.skip(corruption.get("why", "brak e2fsprogs"))
    by_name = {e["name"]: e for e in corruption["detail"]}
    entry = by_name["inode_table_past_eof"]
    assert entry["truncated"] is True, entry
    assert "TruncatedEvidenceError" in entry["error"], entry


@requires_e2fsprogs
def test_truncation_is_its_own_bucket_and_not_a_format_error(selftest_result):
    """``TruncatedEvidenceError`` must not be reported as "wrong filesystem".

    If the harness lumped it in with ``Ext4Error``, a reader could later start
    reporting missing evidence as a damaged format and this self-test would keep
    passing — it would only be counting refusals either way.
    """
    corruption = selftest_result["corruption"]
    if not corruption.get("available"):
        pytest.skip(corruption.get("why", "brak e2fsprogs"))
    truncated = [e for e in corruption["detail"] if e.get("truncated")]
    assert truncated, "żaden przypadek ucięcia nie został rozpoznany"
    for entry in truncated:
        assert entry["refused"] is True
        assert entry["silent"] is False


@requires_e2fsprogs
def test_zeroed_block_bitmap_is_accepted_not_refused(selftest_result):
    """The case where refusing would be refusing the truth.

    A zeroed bitmap says every block in the group is free, and that is a
    statement about the image rather than a defect in the reader.  The self-test
    records this as accepted on purpose, so a later change that starts rejecting
    it fails here rather than in the field.
    """
    corruption = selftest_result["corruption"]
    if not corruption.get("available"):
        pytest.skip(corruption.get("why", "brak e2fsprogs"))
    by_name = {e["name"]: e for e in corruption["detail"]}
    bitmap = by_name["block_bitmap_zeroed"]
    assert bitmap["expect_refuse"] is False
    assert bitmap["opened"] is True
    assert bitmap["refused"] is False
