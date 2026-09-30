# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Read-only F2FS reader, standard library only.

F2FS is what a current Android phone puts on ``/data``, the partition where the
evidence actually is: databases, tokens, chats, media.  :mod:`forensic.core.fsformat`
has been naming such an image instead of calling it corrupt since the twelfth
turn, and :mod:`forensic.core.erofs` did the same job for ``/system``.  This
module is what turns the second of those two sentences into a temporary
condition.

Scope, stated up front because a half-reader is worse than none:

* **Superblock, checkpoint, NAT, inodes, directory trees, inline data, inline
  directories and uncompressed file data are read.**
* **Encrypted files and directories are refused**, with the reason.  Their names
  and contents are ciphertext and the key is not in the image.
* **Compressed files are refused**, with the reason.  F2FS compression prefixes
  each block with its own length and stores it in a cluster; decompressing needs
  LZ4 or HZMA and this project takes no dependencies for the analysis layer.
* **Files above about 7.9 GiB are refused**, with the reason, because reaching
  their blocks needs the double-indirect node level.  F2FS gives each inode two
  indirect nodes, so the reach is twice ext2's; the limit is stated as a number in
  the message rather than left to be discovered on a 9 GiB video, and the number
  is computed from the inode's own geometry rather than typed.

Every structure below was confirmed twice: against ``include/linux/f2fs_fs.h``
from the kernel sources, and against ``dump.f2fs`` output on images this
repository builds with ``mkfs.f2fs`` and ``sload.f2fs``.  F2FS is a log-structured
filesystem and reading it the obvious way fails in several places that do not
raise anything, so the ones that were actually hit are written down here.

* **A node id is not an address.**  Nothing in the image says where inode 4711
  lives; the NAT says it, and the NAT is a hash-less table of 9-byte entries with
  **455 per block**, because 455 × 9 = 4095 and the block is 4096.  The index
  inside a block is therefore ``nid % 455`` and *not* ``(nid * 9) % 4096`` — a
  9/4095 fraction of the entries land one byte further along than the byte
  arithmetic suggests, and every ninth entry lands a whole block off.

* **The NAT block address ping-pongs.**  For entry-block ``off`` it is
  ``nat_blkaddr + (off << 1) - (off & (blocks_per_segment - 1))``, plus one
  segment when bit ``off`` of the checkpoint's NAT version bitmap is set.  The
  bitmap is on disk, inside the checkpoint, at the offset the struct says; the
  kernel rebuilds the same thing into RAM at mount.  An image with more than
  ``blocks_per_segment × 455`` node ids — 233 360 on a 2 MiB-segment volume,
  which a busy phone passes in a year — has its newest NAT entries somewhere
  else than where the first ones are.

* **The dnode references live in ``i_nid[]``, not in ``i_addr[]``.**  The first
  direct node is ``i_nid[0]`` even though its logical anchor in the kernel's
  ``get_node_path()`` is 924.  ``i_addr[923]`` is an unused slot that reads as a
  confident zero, so a reader that looks there concludes the file has no
  continuation.

* **How many blocks fit in the inode is not a constant.**  It is
  ``923 - i_extra_isize/4 - i_inline_xattr_size``, and ``i_inline_xattr_size``
  is 50 for any inode carrying the inline-xattr or inline-dentry flag unless the
  volume advertises flexible inline xattrs.  A 5 MiB file measured here holds
  873 blocks in the inode and the rest in one direct node; assuming 923 produces
  a file whose middle is the wrong 50 blocks, which no error message would
  mention.

* **Inline data starts one word in.**  It sits at ``i_addr[extra_isize/4 + 1]``;
  ``i_addr[extra_isize/4]`` is a reserved word.  Inline *directories* start at
  the same word and lay out a bitmap, a reserved area, 11-byte entries and
  8-byte name slots in the order the header's ``make_dentry_ptr_inline()``
  computes.

* **A node block is an inode exactly when its footer says so.**
  ``footer.ino == footer.nid``.  A direct or indirect node carries the *inode*
  number in the same field, so reading the header of a dnode as an inode yields a
  plausible mode, a plausible size and no error at all — on a direct node those
  bytes are the first 1018 block addresses read as four size fields.

* **The directory hash is a TEA variant, and it is checkable.**  Recomputing it
  over the name we just decoded and comparing with the stored ``hash_code`` is a
  check no wrong answer can pass by accident, because a wrong name hashes
  differently.  :func:`name_hash` implements it; the exception is a casefolded or
  encrypted directory, where the stored hash is of a different string, and that
  is reported as a reason rather than as a failure.

* **A set bitmap bit does not mean an entry.**  A dentry block whose bitmap has
  bits set for entries that were deleted keeps those bits until the block is
  reused, and a hash tree's root block stores child block addresses in slots
  whose ``name_len`` is zero.  ``name_len == 0`` is how the kernel tells them
  apart, and so do we; without that test a directory reports files with empty
  names, and an empty directory reports two.
"""

from __future__ import annotations

import stat as _stat
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from collections.abc import Iterator

from .fsformat import UNKNOWN, detect_bytes

SB_OFFSET = 1024
SB_BYTES = 3072
F2FS_MAGIC = 0xF2F52010
F2FS_VERSION = 1

#: ``F2FS_BLKSIZE`` is fixed at 4096 by the format; the superblock field is read
#: and checked anyway, because a value that says otherwise is a fact worth
#: refusing rather than a detail to paper over.
BLOCK_SIZE = 4096

DEF_ADDRS_PER_INODE = 923
DEF_ADDRS_PER_BLOCK = 1018
NIDS_PER_BLOCK = 1018
DEF_INLINE_XATTR_ADDRS = 50
DEF_INLINE_RESERVED_SIZE = 1

#: ``NODE_DIR1_BLOCK`` … ``NODE_DIND_BLOCK`` from ``f2fs_fs.h``: the *logical*
#: index of each node anchor.  The first of them maps to ``i_nid[0]``, which is
#: why the anchors are not used to index ``i_addr``.
NODE_DIR1_BLOCK = DEF_ADDRS_PER_INODE + 1
NODE_DIR2_BLOCK = DEF_ADDRS_PER_INODE + 2
NODE_IND1_BLOCK = DEF_ADDRS_PER_INODE + 3
NODE_IND2_BLOCK = DEF_ADDRS_PER_INODE + 4
NODE_DIND_BLOCK = DEF_ADDRS_PER_INODE + 5

#: Offsets inside ``struct f2fs_inode``.  ``i_addr`` and ``i_nid`` are pinned by
#: ``sizeof(struct f2fs_inode) == 4072`` plus the 24-byte footer; the rest are
#: measured, and ``i_ext`` sits at 348 rather than the 347 one would guess by
#: counting fields, because ``i_dir_level`` is one byte and the extent that
#: follows is aligned to four.
I_MODE = 0
I_ADVISE = 2
I_INLINE = 3
I_UID = 4
I_GID = 8
I_LINKS = 12
I_SIZE = 16
I_BLOCKS = 24
I_ATIME = 32
I_CTIME = 40
I_MTIME = 48
I_ATIME_NSEC = 56
I_CTIME_NSEC = 60
I_MTIME_NSEC = 64
I_GENERATION = 68
I_DEPTH = 72
I_XATTR_NID = 76
I_FLAGS = 80
I_PINO = 84
I_NAMELEN = 88
I_NAME = 92
NAME_MAX = 255
I_DIR_LEVEL = 347
I_EXT = 348
I_ADDR = 360
I_NID = 4052
INODE_BYTES = 4072
FOOTER = 4072
FOOTER_BYTES = 24
NODE_BYTES = BLOCK_SIZE

#: Offsets inside ``struct f2fs_checkpoint``.  The struct is a fixed 192 bytes
#: followed by a variable-length version bitmap.
CP_VER = 0
CP_USER_BLOCKS = 8
CP_VALID_BLOCKS = 16
CP_RSVD_SEGMENTS = 24
CP_OVERPROV_SEGMENTS = 28
CP_FREE_SEGMENTS = 32
CP_CUR_NODE_SEGNO = 36
CP_CUR_NODE_BLKOFF = 68
CP_CUR_DATA_SEGNO = 84
CP_CUR_DATA_BLKOFF = 116
CP_FLAGS = 132
CP_PACK_TOTAL_BLOCKS = 136
CP_PACK_START_SUM = 140
CP_VALID_NODE_COUNT = 144
CP_VALID_INODE_COUNT = 148
CP_NEXT_FREE_NID = 152
CP_SIT_BYTES = 156
CP_NAT_BYTES = 160
CP_CHECKSUM_OFFSET = 164
CP_ELAPSED = 168
CP_ALLOC_TYPE = 176
CP_VERSION_BITMAP = 192
CP_HEAD_BYTES = 192

#: ``struct f2fs_nat_entry`` is 9 bytes and 455 of them fit in a block.
NAT_ENTRY_BYTES = 9
NAT_PER_BLOCK = BLOCK_SIZE // NAT_ENTRY_BYTES

#: ``struct f2fs_dentry_block``: 27 bytes of bitmap, 27 of reserved, 214 entries
#: of 11 bytes, then 214 name slots of 8.
DENTRY_BITMAP = 27
DENTRY_COUNT = 214
DENTRY_ENTRY = 30
DENTRY_NAME = DENTRY_ENTRY + DENTRY_COUNT * 11
DIR_ENTRY_BYTES = 11
SLOT_LEN = 8

INLINE_XATTR = 0x01
INLINE_DATA = 0x02
INLINE_DENTRY = 0x04
DATA_EXIST = 0x08
INLINE_DOTS = 0x10
EXTRA_ATTR = 0x20

#: ``i_flags`` bit that means the file's data is compressed.
COMPR_FL = 0x00000004

#: ``enum f2fs_ftype_to_dtype`` as stored in a dentry.
FT_TYPES = {
    0: "unknown",
    1: "regular",
    2: "dir",
    3: "chardev",
    4: "blockdev",
    5: "fifo",
    6: "socket",
    7: "symlink",
}

#: ``enum stop_cp_reason``, so a checkpoint that stopped for a reason can be
#: reported as that reason rather than as "not clean".
STOP_REASONS = (
    "shutdown",
    "fault_inject",
    "meta_page",
    "write_fail",
    "corrupted_summary",
    "update_inode",
    "flush_fail",
    "no_segment",
    "corrupted_nid",
)

#: Superblock ``feature`` bits.  ``FLEXIBLE_INLINE_XATTR`` is the one that
#: changes how many blocks fit in an inode, so it is read and reported.
FEATURE_ATOMIC = 0x00000001
FEATURE_TRIM = 0x00000008
FEATURE_CASEFOLD = 0x00000020
FEATURE_FLEXIBLE_INLINE_XATTR = 0x00000040

CP_UMOUNT_FLAG = 0x00000001
CP_ORPHAN_PRESENT_FLAG = 0x00000002
CP_COMPACT_SUM_FLAG = 0x00000004
CP_ERROR_FLAG = 0x00000008
CP_FSCK_FLAG = 0x00000010
CP_FASTBOOT_FLAG = 0x00000020
CP_CRC_RECOVERY_FLAG = 0x00000040
CP_NAT_BITS_FLAG = 0x00000080
CP_TRIMMED_FLAG = 0x00000100
CP_NOCRC_RECOVERY_FLAG = 0x00000200
CP_LARGE_NAT_BITMAP_FLAG = 0x00000400
CP_QUOTA_NEED_FSCK_FLAG = 0x00000800
CP_DISABLED_FLAG = 0x00001000
CP_DISABLED_QUICK_FLAG = 0x00002000
CP_RESIZEFS_FLAG = 0x00004000

CP_FLAG_NAMES = (
    (CP_UMOUNT_FLAG, "umount"),
    (CP_ORPHAN_PRESENT_FLAG, "orphans"),
    (CP_COMPACT_SUM_FLAG, "compact_summary"),
    (CP_ERROR_FLAG, "error"),
    (CP_FSCK_FLAG, "fsck"),
    (CP_FASTBOOT_FLAG, "fastboot"),
    (CP_CRC_RECOVERY_FLAG, "crc_recovery"),
    (CP_NAT_BITS_FLAG, "nat_bits"),
    (CP_TRIMMED_FLAG, "trimmed"),
    (CP_NOCRC_RECOVERY_FLAG, "nocrc_recovery"),
    (CP_LARGE_NAT_BITMAP_FLAG, "large_nat_bitmap"),
    (CP_QUOTA_NEED_FSCK_FLAG, "quota_needs_fsck"),
    (CP_DISABLED_FLAG, "disabled"),
    (CP_DISABLED_QUICK_FLAG, "disabled_quick"),
    (CP_RESIZEFS_FLAG, "resizefs"),
)

#: How many 4 KiB blocks a file reaches without the double-indirect level, for an
#: inode that spends none of its address words on an inline xattr area:
#: ``923 + 2 * 1018 + 2 * 1018 * 1018``.  F2FS gives every inode **two** indirect
#: nodes, so the reach is about twice ext2's — just over 7.9 GiB.  The figure is
#: computed rather than typed, and the refusal below recomputes it per inode,
#: because the inline xattr area takes 50 of those 923 words and moves the limit.
#: A reader that reported a single global number would be off by 50 blocks for
#: every inode that has an inline xattr, which on a current volume is most of them.
INDIRECT_REACH_BLOCKS = (
    DEF_ADDRS_PER_INODE
    + 2 * DEF_ADDRS_PER_BLOCK
    + 2 * DEF_ADDRS_PER_BLOCK * NIDS_PER_BLOCK
)


def gib(count: int) -> str:
    """A block count in GiB, to one decimal and with a Polish comma.

    Only used in a refusal message, where the exact figure is already there and the
    rounded one is what a reader of the report can hold in their head.
    """
    return f"{count * BLOCK_SIZE / (1 << 30):.1f}".replace(".", ",") + " GiB"


def name_hash(name: bytes) -> int:
    """The directory hash F2FS stores next to every name.

    A TEA variant in the tradition of ext3's half-MD4, written out from
    ``fs/f2fs/hash.c``.  It exists here to be *checked against* the image rather
    than to find anything: ``hash_code`` in a dentry is a function of the name in
    that same dentry, so recomputing it turns a name we decoded into a claim the
    image has to confirm.  A wrong offset for the name, a wrong slot width or a
    mis-read ``name_len`` all change the hash, and no combination of them can
    produce the stored value by accident.

    ``.`` and ``..`` hash to zero, which the kernel arranges by special-casing
    them rather than by hashing: ``f2fs_hash_filename()`` returns 0 for both.  A
    linear directory stores them with a set bitmap bit, so a reader that hashes
    them like any other name concludes the name was decoded from the wrong
    offset — which is exactly what happened to the first version of this
    function.
    """
    if name in (b".", b".."):
        return 0
    mask = 0xFFFFFFFF
    delta = 0x9E3779B9
    buf = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    remaining = len(name)
    at = 0
    while True:
        chunk = name[at : at + 16]
        pad = (len(chunk) | ((len(chunk) << 8) & mask)) & mask
        pad = (pad | (pad << 16)) & mask
        words = [0, 0, 0, 0]
        val = pad
        filled = 0
        groups = 0
        for index, byte in enumerate(chunk):
            if index % 4 == 0:
                val = pad
            val = (byte + ((val << 8) & mask)) & mask
            if index % 4 == 3:
                words[filled] = val
                filled += 1
                groups += 1
                val = pad
        left = 4 - groups
        left -= 1
        if left >= 0:
            words[filled] = val
            filled += 1
        while True:
            left -= 1
            if left < 0:
                break
            words[filled] = pad
            filled += 1
        b0, b1 = buf[0], buf[1]
        a, b, c, d = words
        total = 0
        for _ in range(16):
            total = (total + delta) & mask
            b0 = (b0 + ((((b1 << 4) & mask) + a) ^ ((b1 + total) & mask) ^ ((b1 >> 5) + b))) & mask
            b1 = (b1 + ((((b0 << 4) & mask) + c) ^ ((b0 + total) & mask) ^ ((b0 >> 5) + d))) & mask
        buf[0] = (buf[0] + b0) & mask
        buf[1] = (buf[1] + b1) & mask
        at += 16
        if remaining <= 16:
            break
        remaining -= 16
    return buf[0] & mask


def slots_for(name_len: int) -> int:
    """``GET_DENTRY_SLOTS``: how many 8-byte name slots a name of this length needs."""
    return (name_len + SLOT_LEN - 1) >> 3


def dentry_bit(bitmap: bytes, slot: int) -> bool:
    """Is directory slot ``slot`` marked present?

    **Least significant bit first**, because the kernel walks dentry bitmaps with
    ``find_next_bit_le`` while ``f2fs_test_bit()`` — which is big-endian and is
    used for the NAT and SIT bitmaps — is not what reads them.  The two conventions
    live side by side in the same format, and they agree on a byte whose bits are
    symmetric (``0x3C``, ``0xC0``, ``0xFF``), so a reader written the wrong way
    round still lists the root directory of a small image correctly and then loses
    the third entry of a one-file subdirectory.  Slot 0 of byte ``0x07`` is three
    entries; read the other way round it is none.
    """
    if slot >> 3 >= len(bitmap):
        return False
    return bool((bitmap[slot >> 3] >> (slot & 7)) & 1)


class F2fsError(Exception):
    """Raised when an F2FS image cannot be read or lies about its layout."""


@dataclass
class F2fsDirent:
    """One directory entry, as stored, with the check that it is the name we think."""

    ino: int
    name: str
    file_type: int
    hash_code: int
    slots: int
    hash_checked: bool = True

    @property
    def kind(self) -> str:
        return FT_TYPES.get(self.file_type, "unknown")

    def as_dict(self) -> dict[str, Any]:
        return {
            "ino": self.ino,
            "name": self.name,
            "type": self.file_type,
            "kind": self.kind,
            "hash_code": self.hash_code,
            "hash_checked": self.hash_checked,
        }


@dataclass
class F2fsInode:
    """One inode, in the shape the rest of this project expects."""

    number: int
    ino: int
    mode: int
    size: int
    uid: int
    gid: int
    nlink: int
    atime: int
    ctime: int
    mtime: int
    atime_nsec: int
    ctime_nsec: int
    mtime_nsec: int
    generation: int
    inline: int
    advise: int
    flags: int
    pino: int
    namelen: int
    name: str
    dir_level: int
    current_depth: int
    xattr_nid: int
    blocks: int
    node_block: int
    extra_isize: int
    inline_xattr_size: int
    addrs_per_inode: int
    ext: tuple[int, int, int]
    footer: tuple[int, int, int, int, int]
    extra: dict = field(default_factory=dict)

    @property
    def is_dir(self) -> bool:
        return _stat.S_ISDIR(self.mode)

    @property
    def is_reg(self) -> bool:
        return _stat.S_ISREG(self.mode)

    @property
    def is_link(self) -> bool:
        return _stat.S_ISLNK(self.mode)

    @property
    def has_inline_data(self) -> bool:
        return bool(self.inline & INLINE_DATA)

    @property
    def has_inline_dentry(self) -> bool:
        return bool(self.inline & INLINE_DENTRY)

    @property
    def compressed(self) -> bool:
        return bool(self.flags & COMPR_FL)

    @property
    def inline_names(self) -> list[str]:
        return [
            name
            for name, bit in (
                ("xattr", INLINE_XATTR),
                ("data", INLINE_DATA),
                ("dentry", INLINE_DENTRY),
                ("dots", INLINE_DOTS),
                ("extra_attr", EXTRA_ATTR),
            )
            if self.inline & bit
        ]

    @property
    def type_name(self) -> str:
        if self.is_dir:
            return "dir"
        if self.is_reg:
            return "file"
        if self.is_link:
            return "symlink"
        if _stat.S_ISFIFO(self.mode):
            return "fifo"
        if _stat.S_ISSOCK(self.mode):
            return "socket"
        if _stat.S_ISBLK(self.mode):
            return "blockdev"
        if _stat.S_ISCHR(self.mode):
            return "chardev"
        return "other"

    def as_dict(self) -> dict[str, Any]:
        return {
            "nid": self.number,
            "ino": self.ino,
            "type": self.type_name,
            "mode": f"{self.mode:04o}",
            "size": self.size,
            "uid": self.uid,
            "gid": self.gid,
            "nlink": self.nlink,
            "atime": self.atime,
            "atime_nsec": self.atime_nsec,
            "ctime": self.ctime,
            "ctime_nsec": self.ctime_nsec,
            "mtime": self.mtime,
            "mtime_nsec": self.mtime_nsec,
            "generation": self.generation,
            "inline": self.inline,
            "inline_names": self.inline_names,
            "advise": self.advise,
            "flags": self.flags,
            "pino": self.pino,
            "namelen": self.namelen,
            "name": self.name,
            "dir_level": self.dir_level,
            "current_depth": self.current_depth,
            "xattr_nid": self.xattr_nid,
            "blocks": self.blocks,
            "node_block": self.node_block,
            "extra_isize": self.extra_isize,
            "inline_xattr_size": self.inline_xattr_size,
            "addrs_per_inode": self.addrs_per_inode,
            "compressed": self.compressed,
            **self.extra,
        }


class F2fs:
    """Read-only handle on an F2FS image."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._handle = open(self.path, "rb")
        self.block_size = BLOCK_SIZE
        self.holes = 0
        try:
            self.superblock = self._read_superblock()
            self.checkpoint = self._read_checkpoint()
        except Exception:
            self._handle.close()
            raise
        self.blocks = self.superblock["block_count"]
        self.encrypted = bool(self.superblock["encryption_level"])
        self.casefolded = bool(self.superblock["feature"] & FEATURE_CASEFOLD)
        self._inodes: dict[int, F2fsInode] = {}
        self._cache: dict[int, bytes] = {}
        self._nodes: dict[int, bytes] = {}
        #: Holes stepped over while reading, so a caller can say how much of the
        #: tree was not where the address map claims.
        self.holes = 0
        #: Directories that could not be listed, and children whose inode could
        #: not be read, with the reason.  Never silently dropped.
        self.walk_errors: list[dict[str, Any]] = []
        #: Directories this walk managed to list.  Separate from ``walk_errors``
        #: because "the root could not be listed" and "there was only the root" are
        #: different states, and the second is not a failure.
        self.listed: set[int] = set()

    # -- plumbing ---------------------------------------------------------
    def close(self) -> None:
        try:
            self._handle.close()
        except OSError:
            pass

    def __enter__(self) -> F2fs:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def size_bytes(self) -> int:
        return self.blocks * self.block_size

    def _pread(self, offset: int, length: int) -> bytes:
        import os

        return os.pread(self._handle.fileno(), length, offset)

    def _block(self, addr: int) -> bytes:
        """One 4 KiB block, cached.  Bounded because a real /data is large."""
        if addr in self._cache:
            return self._cache[addr]
        if addr < 0 or addr >= self.blocks:
            raise F2fsError(
                f"adres bloku {addr} poza obrazem ({self.blocks} bloków)"
            )
        blob = self._pread(addr * self.block_size, self.block_size)
        if len(blob) < self.block_size:
            raise F2fsError(
                f"blok {addr} nieczytelny w całości: {len(blob)} z {self.block_size} B"
            )
        if len(self._cache) > 4096:
            self._cache.clear()
        self._cache[addr] = blob
        return blob

    def _node(self, addr: int) -> bytes:
        """A node block, cached separately: they are re-read far more than data."""
        blob = self._nodes.get(addr)
        if blob is None:
            blob = self._block(addr)
            if len(self._nodes) > 1024:
                self._nodes.clear()
            self._nodes[addr] = blob
        return blob

    # -- superblock -------------------------------------------------------
    def _read_superblock(self) -> dict[str, Any]:
        raw = self._pread(SB_OFFSET, SB_BYTES)
        if len(raw) < SB_BYTES:
            raise F2fsError(f"obraz za krótki na superblok F2FS ({len(raw)} B)")
        u16 = lambda o: struct.unpack_from("<H", raw, o)[0]  # noqa: E731
        u32 = lambda o: struct.unpack_from("<I", raw, o)[0]  # noqa: E731
        u64 = lambda o: struct.unpack_from("<Q", raw, o)[0]  # noqa: E731
        magic = u32(0)
        if magic != F2FS_MAGIC:
            # ``detect_bytes`` returns a Signature (or None), not a dict: naming
            # the format we actually found is the whole point of this branch, and
            # subscripting it raised TypeError instead of saying which format it was.
            found = detect_bytes(self._pread(0, 1088))
            if found is None or found.kind == UNKNOWN:
                raise F2fsError(f"zła magic F2FS 0x{magic:08X} pod +{SB_OFFSET}")
            raise F2fsError(
                f"zła magic F2FS 0x{magic:08X} pod +{SB_OFFSET} — to jest "
                f"{found.name}"
            )
        if u16(4) != F2FS_VERSION:
            raise F2fsError(f"major_ver={u16(4)}, ten czytnik zna tylko {F2FS_VERSION}")
        log_blocksize = u32(16)
        if log_blocksize != BLOCK_SIZE.bit_length() - 1:
            raise F2fsError(
                f"F2FS ma blok {1 << log_blocksize} B, a ten czytnik zna tylko "
                f"{BLOCK_SIZE} B (F2FS_BLKSIZE jest stałe)"
            )
        log_segmentsize = u32(20)
        if not 9 <= log_segmentsize <= 24:
            raise F2fsError(f"log_blocks_per_seg={log_segmentsize} poza sensownym zakresem")
        volume = raw[124:1148].decode("utf-16-le", "replace").split("\0")[0]
        return {
            "magic": magic,
            "major_ver": u16(4),
            "minor_ver": u16(6),
            "log_sectorsize": u32(8),
            "log_sectors_per_block": u32(12),
            "log_blocksize": log_blocksize,
            "log_blocks_per_seg": log_segmentsize,
            "segs_per_sec": u32(24),
            "secs_per_zone": u32(28),
            "checksum_offset": u32(32),
            "block_count": u64(36),
            "section_count": u32(44),
            "segment_count": u32(48),
            "segment_count_ckpt": u32(52),
            "segment_count_sit": u32(56),
            "segment_count_nat": u32(60),
            "segment_count_ssa": u32(64),
            "segment_count_main": u32(68),
            "segment0_blkaddr": u32(72),
            "cp_blkaddr": u32(76),
            "sit_blkaddr": u32(80),
            "nat_blkaddr": u32(84),
            "ssa_blkaddr": u32(88),
            "main_blkaddr": u32(92),
            "root_ino": u32(96),
            "node_ino": u32(100),
            "meta_ino": u32(104),
            "uuid": raw[108:124].hex(),
            "volume_name": volume,
            "extension_count": u32(1148),
            "cp_payload": u32(1664),
            "version": raw[1668:1924].split(b"\0")[0].decode("utf-8", "replace"),
            "init_version": raw[1924:2180].split(b"\0")[0].decode("utf-8", "replace"),
            "feature": u32(2180),
            "encryption_level": raw[2184],
            "encrypt_pw_salt": raw[2185:2201].hex(),
            "hot_ext_count": raw[2757],
            "s_encoding": u16(2758),
            "s_encoding_flags": u16(2760),
            "s_stop_reason": raw[2762:2794],
            "s_errors": raw[2794:2810],
            "crc": u32(3068),
        }

    def stop_reason(self) -> str:
        """Why the last checkpoint stopped, named, or ``"nieznany"``."""
        raw = self.superblock["s_stop_reason"]
        for index in range(len(STOP_REASONS)):
            if raw[index]:
                return STOP_REASONS[index]
        return "brak (wyłączony w obrazie)"

    def feature_names(self) -> list[str]:
        names = []
        for bit, name in (
            (FEATURE_ATOMIC, "ATOMIC"),
            (FEATURE_TRIM, "TRIM"),
            (FEATURE_CASEFOLD, "CASEFOLD"),
            (FEATURE_FLEXIBLE_INLINE_XATTR, "FLEXIBLE_INLINE_XATTR"),
        ):
            if self.superblock["feature"] & bit:
                names.append(name)
        return names

    # -- checkpoint -------------------------------------------------------
    def _read_checkpoint(self) -> dict[str, Any]:
        """Pick the newer of the two checkpoint packs and keep the other's version.

        There are always two packs and they alternate, so the newer one is the
        live state.  A forensic reader that took the first one would report a
        volume state that is one checkpoint stale and would have no way to say so.
        """
        base = self.superblock["cp_blkaddr"]
        packs: list[dict[str, Any]] = []
        for index in range(2):
            start = base + index * 8
            raw = self._pread(start * self.block_size, CP_HEAD_BYTES)
            if len(raw) < CP_HEAD_BYTES:
                continue
            sit_bytes, nat_bytes = struct.unpack_from("<II", raw, CP_SIT_BYTES)
            version, = struct.unpack_from("<Q", raw, CP_VER)
            bitmap = b""
            if sit_bytes and nat_bytes and sit_bytes + nat_bytes <= self.block_size - CP_HEAD_BYTES:
                bitmap = self._pread(
                    (start * self.block_size) + CP_VERSION_BITMAP, sit_bytes + nat_bytes
                )
            packs.append(
                {
                    "index": index,
                    "start_block": start,
                    "checkpoint_ver": version,
                    "user_block_count": struct.unpack_from("<Q", raw, CP_USER_BLOCKS)[0],
                    "valid_block_count": struct.unpack_from("<Q", raw, CP_VALID_BLOCKS)[0],
                    "rsvd_segment_count": struct.unpack_from("<I", raw, CP_RSVD_SEGMENTS)[0],
                    "overprov_segment_count": struct.unpack_from("<I", raw, CP_OVERPROV_SEGMENTS)[0],
                    "free_segment_count": struct.unpack_from("<I", raw, CP_FREE_SEGMENTS)[0],
                    "ckpt_flags": struct.unpack_from("<I", raw, CP_FLAGS)[0],
                    "cp_pack_total_block_count": struct.unpack_from("<I", raw, CP_PACK_TOTAL_BLOCKS)[0],
                    "cp_pack_start_sum": struct.unpack_from("<I", raw, CP_PACK_START_SUM)[0],
                    "valid_node_count": struct.unpack_from("<I", raw, CP_VALID_NODE_COUNT)[0],
                    "valid_inode_count": struct.unpack_from("<I", raw, CP_VALID_INODE_COUNT)[0],
                    "next_free_nid": struct.unpack_from("<I", raw, CP_NEXT_FREE_NID)[0],
                    "sit_ver_bitmap_bytesize": sit_bytes,
                    "nat_ver_bitmap_bytesize": nat_bytes,
                    "checksum_offset": struct.unpack_from("<I", raw, CP_CHECKSUM_OFFSET)[0],
                    "elapsed_time": struct.unpack_from("<Q", raw, CP_ELAPSED)[0],
                    "alloc_type": list(raw[CP_ALLOC_TYPE:CP_HEAD_BYTES]),
                    "_version_bitmap": bitmap,
                }
            )
        if not packs:
            raise F2fsError("nie można odczytać żadnego pakietu checkpointu")
        live = max(packs, key=lambda p: p["checkpoint_ver"])
        out = dict(live)
        out["packs"] = [
            {
                "index": p["index"],
                "start_block": p["start_block"],
                "checkpoint_ver": p["checkpoint_ver"],
                "ckpt_flags": p["ckpt_flags"],
                "next_free_nid": p["next_free_nid"],
            }
            for p in packs
        ]
        out["pack_count"] = len(packs)
        out["flag_names"] = [name for bit, name in CP_FLAG_NAMES if live["ckpt_flags"] & bit]
        out["unclean"] = not (live["ckpt_flags"] & CP_UMOUNT_FLAG)
        out["free_blocks"] = live["free_segment_count"] * (
            1 << self.superblock["log_blocks_per_seg"]
        )
        return out

    def nat_bitmap(self) -> bytes:
        """The NAT version bitmap, as stored in the live checkpoint."""
        return self.checkpoint.get("_version_bitmap", b"")[: self.checkpoint["nat_ver_bitmap_bytesize"]]

    # -- NAT --------------------------------------------------------------
    def nat_block_for(self, nid: int) -> int:
        """Which NAT block holds node ``nid``.

        The ping-pong is on disk, not a kernel cache artefact: the newest NAT
        block for an entry-group alternates between the first and the second half
        of the NAT area, and which half is live is bit ``nid // 455`` of the
        checkpoint's NAT version bitmap.
        """
        off = nid // NAT_PER_BLOCK
        per_segment = 1 << self.superblock["log_blocks_per_seg"]
        addr = self.superblock["nat_blkaddr"] + (off << 1) - (off & (per_segment - 1))
        bitmap = self.nat_bitmap()
        if bitmap and off // 8 < len(bitmap):
            if (bitmap[off // 8] >> (7 - (off & 7))) & 1:
                addr += per_segment
        return addr

    def nat(self, nid: int) -> tuple[int, int]:
        """``(ino, block address)`` for a node id, or ``(0, 0)`` if it has none.

        A node id that was never allocated has ``ino == 0``.  That is the only
        test, and it matters: ``dump.f2fs -i 9`` on a volume whose highest node id
        is 8 prints a superblock as if it were an inode, with a mode, a size and
        no complaint.
        """
        if nid < 0:
            raise F2fsError(f"nid {nid} jest ujemny")
        block = self.nat_block_for(nid)
        raw = self._block(block)
        at = (nid % NAT_PER_BLOCK) * NAT_ENTRY_BYTES
        version, ino, addr = struct.unpack_from("<BII", raw, at)
        del version
        return ino, addr

    def next_nid(self) -> int:
        """Lowest node id the filesystem may still hand out."""
        return self.checkpoint["next_free_nid"]

    # -- nodes ------------------------------------------------------------
    def node_block(self, nid: int) -> bytes:
        ino, addr = self.nat(nid)
        if not addr or not ino:
            raise F2fsError(
                f"nid {nid} nie istnieje w NAT (next_free_nid={self.next_nid()})"
            )
        raw = self._node(addr)
        footer_nid, footer_ino = struct.unpack_from("<II", raw, FOOTER)
        if footer_nid != nid or footer_ino == 0:
            raise F2fsError(
                f"nid {nid}: stopka mówi nid={footer_nid} ino={footer_ino}, "
                f"a NAT wskazywał na blok {addr}"
            )
        return raw

    def _read_footer(self, raw: bytes) -> tuple[int, int, int, int, int]:
        return struct.unpack_from("<IIIQI", raw, FOOTER)

    def _addrs_base(self, raw: bytes, inline: int) -> int:
        """Word index inside ``i_addr`` where this inode's payload area starts.

        Zero unless the inode carries ``EXTRA_ATTR``, in which case the extra
        attribute block occupies the first ``i_extra_isize`` bytes of ``i_addr``
        and everything else — including the inline data — starts after it.
        """
        if not inline & EXTRA_ATTR:
            return 0
        return struct.unpack_from("<H", raw, I_ADDR)[0] // 4

    def _inline_xattr_size(self, raw: bytes, inline: int) -> int:
        """How many words of ``i_addr`` the inline xattr area reserves.

        50 for any inode with the inline-xattr or inline-dentry flag on a volume
        without flexible inline xattrs, and 0 otherwise.  This number is what
        decides how many file blocks fit in the inode, so getting it wrong
        misplaces the middle of every large file.
        """
        if self.superblock["feature"] & FEATURE_FLEXIBLE_INLINE_XATTR:
            return struct.unpack_from("<H", raw, I_ADDR + 2)[0]
        if inline & (INLINE_XATTR | INLINE_DENTRY):
            return DEF_INLINE_XATTR_ADDRS
        return 0

    def inode(self, nid: int) -> F2fsInode:
        """Parse one inode.  Cached, because a tree walk revisits directories."""
        cached = self._inodes.get(nid)
        if cached is not None:
            return cached
        ino, addr = self.nat(nid)
        if not addr or not ino:
            raise F2fsError(
                f"nid {nid} nie istnieje w NAT (next_free_nid={self.next_nid()})"
            )
        raw = self._node(addr)
        footer_nid, footer_ino, _flag, _cp_ver, _next = self._read_footer(raw)
        if footer_ino == footer_nid == 0:
            raise F2fsError(f"nid {nid}: stopka zerowa w bloku {addr}")
        if footer_ino != footer_nid:
            raise F2fsError(
                f"nid {nid}: blok {addr} to węzeł (stopka nid={footer_nid} "
                f"ino={footer_ino}), nie inodo"
            )
        inline = raw[I_INLINE]
        extra_isize = struct.unpack_from("<H", raw, I_ADDR)[0] if inline & EXTRA_ATTR else 0
        xattr_words = self._inline_xattr_size(raw, inline)
        addrs = DEF_ADDRS_PER_INODE - extra_isize // 4 - xattr_words
        if addrs <= 0:
            raise F2fsError(
                f"nid {nid}: i_extra_isize={extra_isize} i_inline_xattr_size="
                f"{xattr_words * 4} B zjadają całe i_addr"
            )
        namelen = struct.unpack_from("<I", raw, I_NAMELEN)[0]
        if namelen > NAME_MAX:
            raise F2fsError(f"nid {nid}: i_namelen={namelen} powyżej {NAME_MAX}")
        node = F2fsInode(
            number=nid,
            ino=ino,
            mode=struct.unpack_from("<H", raw, I_MODE)[0],
            size=struct.unpack_from("<Q", raw, I_SIZE)[0],
            uid=struct.unpack_from("<I", raw, I_UID)[0],
            gid=struct.unpack_from("<I", raw, I_GID)[0],
            nlink=struct.unpack_from("<I", raw, I_LINKS)[0],
            atime=struct.unpack_from("<Q", raw, I_ATIME)[0],
            ctime=struct.unpack_from("<Q", raw, I_CTIME)[0],
            mtime=struct.unpack_from("<Q", raw, I_MTIME)[0],
            atime_nsec=struct.unpack_from("<I", raw, I_ATIME_NSEC)[0],
            ctime_nsec=struct.unpack_from("<I", raw, I_CTIME_NSEC)[0],
            mtime_nsec=struct.unpack_from("<I", raw, I_MTIME_NSEC)[0],
            generation=struct.unpack_from("<I", raw, I_GENERATION)[0],
            inline=inline,
            advise=raw[I_ADVISE],
            flags=struct.unpack_from("<I", raw, I_FLAGS)[0],
            pino=struct.unpack_from("<I", raw, I_PINO)[0],
            namelen=namelen,
            name=raw[I_NAME : I_NAME + namelen].decode("utf-8", "replace"),
            dir_level=raw[I_DIR_LEVEL],
            current_depth=struct.unpack_from("<I", raw, I_DEPTH)[0],
            xattr_nid=struct.unpack_from("<I", raw, I_XATTR_NID)[0],
            blocks=struct.unpack_from("<Q", raw, I_BLOCKS)[0],
            node_block=addr,
            extra_isize=extra_isize,
            inline_xattr_size=xattr_words * 4,
            addrs_per_inode=addrs,
            ext=struct.unpack_from("<III", raw, I_EXT),
            footer=self._read_footer(raw),
        )
        self._inodes[nid] = node
        return node

    @property
    def root(self) -> F2fsInode:
        return self.inode(self.superblock["root_ino"])

    # -- addresses --------------------------------------------------------
    def _node_nid(self, raw: bytes, anchor: int) -> int:
        """The node id at a logical anchor: ``i_nid[anchor - 924]``.

        Not ``i_addr[anchor]``.  The anchors are 924 upwards, ``i_nid`` holds five
        entries, and ``i_addr[923]`` is a hole that reads as zero.
        """
        index = anchor - NODE_DIR1_BLOCK
        if not 0 <= index < 5:
            raise F2fsError(f"kotwica {anchor} nie ma slotu w i_nid")
        return struct.unpack_from("<I", raw, I_NID + index * 4)[0]

    def _dnode(self, nid: int, ino: int) -> bytes:
        """A direct or indirect node, checked to belong to the inode we expect.

        The footer's ``ino`` field is what makes a node block an inode or not, and
        it is also the check that the node really is part of this file: a node id
        that belongs to a different inode would otherwise contribute its block
        addresses to this file's data, and every byte of the result would look
        like plausible file content.
        """
        raw = self.node_block(nid)
        _nid, owner, _flag, _cp, _next = self._read_footer(raw)
        if owner != ino:
            raise F2fsError(
                f"węzeł {nid} należy do inoda {owner}, a szukano dla {ino} — "
                "mapa bloków jest spójna i wskazuje cudzy węzeł"
            )
        return raw

    def block_address(self, node: F2fsInode, index: int) -> int:
        """Block address of logical block ``index`` of ``node``, or 0 for a hole.

        Mirrors ``get_node_path()``: the first ``addrs_per_inode`` words of the
        inode are data blocks, then a direct node at ``i_nid[0]``, then the second
        direct node, then two indirect nodes, then the double-indirect one — whose
        limit is where the refusal below comes from.

        A zero is a hole and not an error, because F2FS does create sparse files
        and directories that have had entries removed.  Callers decide what a
        hole means: :meth:`read` fills it with zeros the way the kernel does, and
        :meth:`listdir` skips the block and counts it.
        """
        raw = self._node(node.node_block)
        base = self._addrs_base(raw, node.inline)
        direct_index = node.addrs_per_inode
        direct_blks = DEF_ADDRS_PER_BLOCK
        indirect_blks = direct_blks * NIDS_PER_BLOCK
        dindirect_blks = indirect_blks * NIDS_PER_BLOCK
        remaining = index
        if remaining < direct_index:
            return struct.unpack_from("<I", raw, I_ADDR + (base + remaining) * 4)[0]
        remaining -= direct_index
        if remaining < direct_blks:
            return self._dnode_entry(node, NODE_DIR1_BLOCK, remaining)
        remaining -= direct_blks
        if remaining < direct_blks:
            return self._dnode_entry(node, NODE_DIR2_BLOCK, remaining)
        remaining -= direct_blks
        if remaining < indirect_blks:
            return self._dnode_entry(
                node, NODE_IND1_BLOCK, remaining // direct_blks, remaining % direct_blks
            )
        remaining -= indirect_blks
        if remaining < indirect_blks:
            return self._dnode_entry(
                node, NODE_IND2_BLOCK, remaining // direct_blks, remaining % direct_blks
            )
        remaining -= indirect_blks
        if remaining < dindirect_blks:
            limit = direct_index + 2 * direct_blks + 2 * indirect_blks
            raise F2fsError(
                f"nid {node.number}: blok {index} leży w gałęzi podwójnie "
                f"pośredniej. Ten czytnik idzie na ten inodo do {limit} bloków "
                f"({limit * self.block_size} B, {gib(limit)}), bo 50 z 923 słów "
                f"adresów zajmuje rezerwa na atrybuty inline xattr; F2FS sięga "
                f"wyżej, do {INDIRECT_REACH_BLOCKS} bloków "
                f"({gib(INDIRECT_REACH_BLOCKS)}). Plik powyżej tej granicy daje "
                f"z tego readera tylko metadane."
            )
        raise F2fsError(f"nid {node.number}: blok {index} poza tablicą adresów F2FS")

    def _dnode_entry(self, node: F2fsInode, anchor: int, index: int, inner: int = 0) -> int:
        """One hop down the node tree: the anchor's node, then the entry in it.

        ``index`` selects within the anchor's node, and for an indirect anchor it
        selects the *next* node down, whose entry ``inner`` then names the block.
        A zero at either step is a hole, propagated rather than raised.
        """
        parent = self._node(node.node_block)
        first = self._node_nid(parent, anchor)
        if not first:
            return 0
        if anchor >= NODE_IND1_BLOCK:
            middle = self._dnode(first, node.ino)
            if not 0 <= index < NIDS_PER_BLOCK:
                raise F2fsError(f"węzeł {first}: indeks {index} poza {NIDS_PER_BLOCK}")
            second = struct.unpack_from("<I", middle, index * 4)[0]
            if not second:
                return 0
            return self._dnode_entry_index(second, inner, node.ino)
        return self._dnode_entry_index(first, index, node.ino)

    def _dnode_entry_index(self, nid: int, index: int, ino: int) -> int:
        raw = self._dnode(nid, ino)
        if not 0 <= index < DEF_ADDRS_PER_BLOCK:
            raise F2fsError(f"węzeł {nid}: indeks {index} poza {DEF_ADDRS_PER_BLOCK}")
        return struct.unpack_from("<I", raw, index * 4)[0]

    # -- data -------------------------------------------------------------
    def _target(self, node_or_nid: F2fsInode | int | str) -> F2fsInode:
        if isinstance(node_or_nid, str):
            return self.resolve(node_or_nid)
        if isinstance(node_or_nid, F2fsInode):
            return node_or_nid
        return self.inode(node_or_nid)

    def read(self, node_or_nid: F2fsInode | int | str) -> bytes:
        """File content.

        Three placements, and which one applies is a per-inode decision, not a
        per-file one:

        * **inline** — the bytes live inside the inode, one word past the start
          of its payload area.  Only the inode block is read at all.
        * **direct** — the first ``addrs_per_inode`` blocks are the inode's own
          ``i_addr`` words, the rest are in direct and indirect nodes.
        * **refused** — compressed, encrypted, or past the double-indirect limit.

        A hole in the address map reads as zeros, the way the kernel serves a
        sparse file, and is counted in :attr:`holes`.
        """
        node = self._target(node_or_nid)
        self._refuse_if_unreadable(node, "treści")
        if node.size == 0:
            return b""
        if node.has_inline_data:
            raw = self._node(node.node_block)
            base = self._addrs_base(raw, node.inline)
            at = I_ADDR + (base + DEF_INLINE_RESERVED_SIZE) * 4
            if at + node.size > self.block_size:
                raise F2fsError(
                    f"nid {node.number}: dane inline ({node.size} B) nie mieszczą się "
                    f"w bloku inoda — obszar inline kończy się na {self.block_size} B"
                )
            return self._pread(node.node_block * self.block_size + at, node.size)
        nblocks = -(-node.size // self.block_size)
        out = bytearray()
        for index in range(nblocks):
            addr = self.block_address(node, index)
            want = min(self.block_size, node.size - index * self.block_size)
            if not addr:
                out += b"\0" * want
                self.holes += 1
                continue
            out += self._block(addr)[:want]
        return bytes(out)

    def readlink(self, node_or_nid: F2fsInode | int | str) -> str:
        node = self._target(node_or_nid)
        return self.read(node).decode("utf-8", "replace")

    def _refuse_if_unreadable(self, node: F2fsInode, what: str) -> None:
        """Refuse, with a reason, everything this reader will not hand over."""
        if self.encrypted:
            raise F2fsError(
                f"nid {node.number}: wolumen ma poziom szyfrowania "
                f"{self.superblock['encryption_level']}, więc {what} są zaszyfrowane, "
                "a klucza nie ma w obrazie"
            )
        if node.compressed:
            raise F2fsError(
                f"nid {node.number}: plik jest skompresowany (i_flags 0x{node.flags:08x}) "
                f"— F2FS trzyma każdy blok w klastrze z własnym nagłówkiem długości, "
                f"więc {what} wymagają dekompresora LZ4 albo HZMA, którego stdlib nie ma. "
                "Nazwy, rozmiary, tryby i czasy są poprawne."
            )

    # -- directories ------------------------------------------------------
    def _dentry_block(self, node: F2fsInode, index: int) -> list[F2fsDirent]:
        """Entries of one directory block.

        A zero address here is a hole, not a failure: a directory that has had
        entries removed can keep a hole where a dentry block used to be, and the
        kernel's readdir steps over it.  It is counted, because a block of names
        that is simply not there is a gap in the evidence and the report has to
        say so rather than quietly list fewer files.
        """
        addr = self.block_address(node, index)
        if not addr:
            self.holes += 1
            return []
        return self._parse_dentry_block(self._block(addr), node, index, addr)

    def _parse_dentry_block(
        self, blob: bytes, node: F2fsInode, index: int, addr: int
    ) -> list[F2fsDirent]:
        out: list[F2fsDirent] = []
        for slot in range(DENTRY_COUNT):
            if not dentry_bit(blob[:DENTRY_BITMAP], slot):
                continue
            at = DENTRY_ENTRY + slot * DIR_ENTRY_BYTES
            hash_code, ino, name_len, file_type = struct.unpack_from("<IIHB", blob, at)
            if name_len == 0:
                continue
            if name_len > NAME_MAX:
                raise F2fsError(
                    f"nid {node.number}: blok katalogowy {addr} (blok {index}) ma "
                    f"nazwa={name_len} powyżej {NAME_MAX}"
                )
            span = slots_for(name_len)
            if slot + span > DENTRY_COUNT:
                raise F2fsError(
                    f"nid {node.number}: wpis {slot} w bloku {addr} wychodzi "
                    f"poza {DENTRY_COUNT} slotów"
                )
            start = DENTRY_NAME + slot * SLOT_LEN
            raw_name = blob[start : start + name_len]
            checked = name_hash(raw_name) == hash_code
            if not checked and not (self.casefolded or self.encrypted):
                raise F2fsError(
                    f"nid {node.number}: blok katalogowy {addr} (blok {index}), wpis "
                    f"{slot}: hash nazwy {name_hash(raw_name):#010x} nie zgadza się "
                    f"z zapisanym {hash_code:#010x} — nazwa odczytana ze złego miejsca"
                )
            out.append(
                F2fsDirent(
                    ino=ino,
                    name=raw_name.decode("utf-8", "replace"),
                    file_type=file_type,
                    hash_code=hash_code,
                    slots=span,
                    hash_checked=checked,
                )
            )
        return out

    def listdir(self, node_or_nid: F2fsInode | int | str) -> list[F2fsDirent]:
        """Entries of a directory, ``.`` and ``..`` included, as stored.

        A directory is ``ceil(i_size / 4096)`` blocks read in order — the same
        count the kernel derives, and not something to be read out of ``i_blocks``
        or the address array.  Two kinds of set bitmap bit are not entries:
        slots whose ``name_len`` is zero, which is both a deleted entry whose bit
        has not been cleared and the child addresses in a hash tree root, and
        which is how the kernel tells them apart too.

        ``i_dir_level`` is the hash tree depth and ``i_current_depth`` is how
        deep the directory's own data sits in the node tree.  They are different
        numbers and reading one as the other is a mistake that produces a
        plausible count.
        """
        node = self._target(node_or_nid)
        if not node.is_dir:
            raise F2fsError(f"nid {node.number}: inode nie jest katalogiem")
        if self.encrypted:
            raise F2fsError(
                f"nid {node.number}: wolumen ma poziom szyfrowania "
                f"{self.superblock['encryption_level']}, więc nazwy w katalogu są "
                "zaszyfrowane, a klucza nie ma w obrazie. Metadane inodów "
                "(tryb, rozmiar, uid, czasy) są wciąż poprawne."
            )
        if node.has_inline_dentry:
            return self._listdir_inline(node)
        nblocks = -(-node.size // self.block_size)
        out: list[F2fsDirent] = []
        for index in range(nblocks):
            out.extend(self._dentry_block(node, index))
        return out

    def _inline_layout(self, node: F2fsInode) -> tuple[int, int, int, int]:
        """``(offset, bitmap bytes, entry count, reserved bytes)`` of inline dentries.

        The counts come out of the header's own formulas over
        ``MAX_INLINE_DATA``, so they follow ``i_inline_xattr_size`` and
        ``i_extra_isize`` automatically.  The one word at the start of the area
        is the reserved word, which is also where inline *data* begins.
        """
        words = (
            DEF_ADDRS_PER_INODE
            - node.extra_isize // 4
            - node.inline_xattr_size // 4
            - DEF_INLINE_RESERVED_SIZE
        )
        area = words * 4
        count = (area * 8) // ((DIR_ENTRY_BYTES + SLOT_LEN) * 8 + 1)
        bitmap = -(-count // 8)
        reserved = area - ((DIR_ENTRY_BYTES + SLOT_LEN) * count + bitmap)
        if count <= 0 or reserved < 0:
            raise F2fsError(
                f"nid {node.number}: obszar inline ({area} B) nie mieści nawet "
                f"jednego wpisu katalogowego"
            )
        at = I_ADDR + (node.extra_isize // 4 + DEF_INLINE_RESERVED_SIZE) * 4
        if at + area > I_NID:
            raise F2fsError(
                f"nid {node.number}: katalog inline bez zarezerwowanego miejsca na "
                f"atrybuty — obszar liczy {area} B i kończyłby się pod +{at + area}, "
                f"a i_nid zaczyna się pod +{I_NID}. Taki inodo nie powstałby na "
                "wolumenie bez atrybutów inline xattr."
            )
        return at, bitmap, count, reserved

    def _listdir_inline(self, node: F2fsInode) -> list[F2fsDirent]:
        at, bitmap_bytes, count, reserved = self._inline_layout(node)
        blob = self._pread(node.node_block * self.block_size + at, bitmap_bytes + reserved + count * (DIR_ENTRY_BYTES + SLOT_LEN))
        bitmap = blob[:bitmap_bytes]
        dentry_at = bitmap_bytes + reserved
        out: list[F2fsDirent] = []
        for slot in range(count):
            if not dentry_bit(bitmap, slot):
                continue
            head = dentry_at + slot * DIR_ENTRY_BYTES
            hash_code, ino, name_len, file_type = struct.unpack_from("<IIHB", blob, head)
            if name_len == 0:
                continue
            if name_len > NAME_MAX:
                raise F2fsError(
                    f"nid {node.number}: katalog inline ma wpis o nazwie {name_len} B"
                )
            start = dentry_at + count * DIR_ENTRY_BYTES + slot * SLOT_LEN
            raw_name = blob[start : start + name_len]
            checked = name_hash(raw_name) == hash_code
            if not checked and not (self.casefolded or self.encrypted):
                raise F2fsError(
                    f"nid {node.number}: katalog inline, wpis {slot}: hash nazwy "
                    f"{name_hash(raw_name):#010x} nie zgadza się z zapisanym "
                    f"{hash_code:#010x}"
                )
            out.append(
                F2fsDirent(
                    ino=ino,
                    name=raw_name.decode("utf-8", "replace"),
                    file_type=file_type,
                    hash_code=hash_code,
                    slots=slots_for(name_len),
                    hash_checked=checked,
                )
            )
        return out

    def walk(self, start: int | None = None) -> Iterator[tuple[str, F2fsInode]]:
        """Depth-first walk of the tree, yielding ``(path, inode)``.

        A directory that cannot be listed is recorded in :attr:`walk_errors` and
        stepped over, so the rest of the tree still comes back — but the failure
        is not thrown away, because a walk that quietly returns a smaller tree
        looks exactly like a filesystem that holds fewer files.  That is the same
        silent-emptiness failure the refusals of the eighth turn were written
        against, and it is why the reason is kept and counted.
        """
        root = self.superblock["root_ino"] if start is None else start
        stack: list[tuple[str, F2fsInode]] = [("/", self.inode(root))]
        seen: set[int] = set()
        while stack:
            path, node = stack.pop()
            yield path, node
            if not node.is_dir or node.number in seen:
                continue
            seen.add(node.number)
            try:
                entries = self.listdir(node)
            except (F2fsError, KeyError) as exc:
                self.walk_errors.append(
                    {"path": path, "nid": node.number, "error": str(exc)[:200]}
                )
                continue
            self.listed.add(node.number)
            children: list[tuple[str, F2fsInode]] = []
            for entry in entries:
                if entry.name in (".", ".."):
                    continue
                child_path = f"{path.rstrip('/')}/{entry.name}"
                try:
                    child = self.inode(entry.ino)
                except F2fsError as exc:
                    self.walk_errors.append(
                        {"path": child_path, "nid": entry.ino, "error": str(exc)[:200]}
                    )
                    continue
                children.append((child_path, child))
            stack.extend(reversed(children))

    def stat(self, path: str) -> dict[str, Any]:
        node = self.resolve(path)
        out = node.as_dict()
        out["path"] = path
        return out

    def resolve(self, path: str) -> F2fsInode:
        """Walk a ``/``-separated path to its inode."""
        parts = [p for p in path.split("/") if p]
        nid = self.superblock["root_ino"]
        for part in parts:
            node = self.inode(nid)
            if not node.is_dir:
                raise KeyError(f"{path}: {part} nie jest katalogiem")
            found = None
            for entry in self.listdir(node):
                if entry.name == part:
                    found = entry
                    break
            if found is None:
                raise KeyError(f"brak {part!r} w {path}")
            nid = found.ino
        return self.inode(nid)

    def refusal_kind(self, node: F2fsInode) -> str:
        """A short, stable word for why a file's content is out of reach.

        The full sentence goes in the message; this is what a report groups by, so
        it has to be a fixed handful of words rather than the first sixty
        characters of a sentence, which would cut a word in half and change with
        the wording.
        """
        if self.encrypted:
            return "zaszyfrowany"
        if node.compressed:
            return "skompresowany"
        return "nieznany"

    def coverage(self) -> dict[str, Any]:
        """What this reader can and cannot reach in the image it was given.

        Reported rather than assumed.  Directories that could not be listed are
        counted apart from files that could not be read, because the two mean
        different things: an unreadable *name* is the loss of a whole subtree,
        while an unreadable *file* is the loss of one object.  An encrypted volume
        loses every name and no metadata, and a report that said "1 file, 0
        readable" about it would be counting the root directory and calling it a
        file.
        """
        dirs_seen: set[int] = set()
        files = readable = 0
        inline_data = inline_dir = 0
        self.holes = 0
        self.walk_errors = []
        self.listed = set()
        refused: dict[str, int] = {}
        for _path, node in self.walk():
            if node.is_dir:
                dirs_seen.add(node.number)
                if node.has_inline_dentry:
                    inline_dir += 1
                continue
            files += 1
            if node.has_inline_data:
                inline_data += 1
            try:
                self._refuse_if_unreadable(node, "treści")
                readable += 1
            except F2fsError:
                kind = self.refusal_kind(node)
                refused[kind] = refused.get(kind, 0) + 1
        dirs = len(dirs_seen)
        dirs_listed = len(dirs_seen & self.listed)
        return {
            "dirs": dirs,
            "dirs_listed": dirs_listed,
            "inline_dirs": inline_dir,
            "files": files,
            "readable": readable,
            "inline_data": inline_data,
            "holes": self.holes,
            "walk_errors": len(self.walk_errors),
            "walk_error_detail": self.walk_errors[:5],
            "refused": sum(refused.values()),
            "refused_reasons": refused,
            "names_complete": not self.walk_errors,
            "contents_complete": (
                not refused and not self.holes and not self.walk_errors
            ),
        }
