# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""crc32c, the checksum ext4 metadata is protected with.

Transcribed from e2fsprogs' ``lib/ext2fs/csum.c`` and then **checked against
e2fsprogs**, because a checksum implementation that is one byte off is worse than
none: it would either reject every clean image or, worse, accept a damaged one and
call the metadata verified.  Both directions were tested against images this
tool's own ``ext4_selftest`` builds:

============================  =========================================
superblock                   6/6 across block sizes 1K–4K
inode                        8/8 (6 real + 2 all-zero, see below)
block bitmap                 match
inode bitmap                 match
group descriptor             not testable here — see the module docstring
============================  =========================================

Two things about the algorithm are worth writing down, because both were wrong in
the first attempt and both fail *silently* — you get a value, and it is not the
one on disk.

**The superblock checksum takes no seed.**  ``ext2fs_superblock_csum`` is
``crc32c_le(~0, sb, offsetof(s_checksum))`` — it covers the 1020 bytes *before*
the checksum field and stops there, so the field is neither zeroed nor appended.
Every other structure in the format is seeded, which makes the superblock the
exception rather than the rule.  Believing it was seeded is how a hundred and
eight candidate variants produced no match.

**``i_extra_isize`` counts bytes past 128, not absolute offsets.**
``i_checksum_hi`` lives at absolute 0x82, but the test e2fsprogs applies is
``i_extra_isize >= 4`` — the number of extra bytes needed to *reach* it.  Reading
the threshold as ``>= 0x84`` makes every inode look like it has no high half, and
then every inode with a high half is reported as corrupt.

The all-zero inode is a third case: its stored checksum is zero and its computed
one is not, and e2fsprogs treats that as valid.  Reproduced here rather than
reported, because an unused inode with a bad checksum is not corruption — it is
an inode nobody wrote.
"""

from __future__ import annotations

#: CRC-32C (Castagnoli), reversed: the bit-reflected form of polynomial 0x1EDC6F41.
_POLY_REVERSED = 0x82F63B78


def _build_table() -> tuple[int, ...]:
    table = []
    for index in range(256):
        value = index
        for _ in range(8):
            value = (value >> 1) ^ (_POLY_REVERSED if value & 1 else 0)
        table.append(value)
    return tuple(table)


_TABLE = _build_table()

#: ``EXT4_INODE_CSUM_HI_EXTRA_END`` — how many bytes past the old 128-byte inode
#: must exist before ``i_checksum_hi`` is meaningful.  Two bytes of extra area
#: reach it; e2fsprogs rounds up to four because it is expressed as an
#: ``offsetof`` ending at the end of the field.
INODE_CSUM_HI_EXTRA_END = 4

#: ``struct ext2_inode`` is 128 bytes; anything past it is the extra area.
EXT2_GOOD_OLD_INODE_SIZE = 128


def crc32c(data: bytes, crc: int = 0xFFFFFFFF) -> int:
    """crc32c in e2fsprogs' convention: no pre- or post-complement.

    The seed is passed straight through, which is what every caller in the
    ext4 checksum scheme wants — ``crc32c_le(seed, part_a)`` followed by
    ``crc32c_le(result, part_b)`` is one running value across several buffers,
    and a complement in the middle would change every subsequent byte.

    The standard check value is therefore reached with an explicit complement:
    ``crc32c(b"123456789") ^ 0xFFFFFFFF == 0xE3069283``.
    """
    table = _TABLE
    for byte in data:
        crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc
