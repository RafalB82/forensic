# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Map byte offsets in an ext4 image back to the files that own them.

The image is the primary artifact, so the common forensic question is the
reverse of the usual one: "I found these bytes at image offset N — which file
are they in, and at which offset inside that file?".  Building the answer means
building a block-to-file index, which this module does for a chosen scope and
caches to disk as JSON.

Typical use::

    from forensic.core.ext4 import Ext4
    from forensic.core.blockmap import BlockIndex

    with Ext4(image) as fs:
        index = BlockIndex.build(fs, scope=["/data/com.android.browser"])
        print(index.lookup(13720525449))
"""

from __future__ import annotations

import json
import os
import struct
import time
from dataclasses import dataclass

from .ext4 import Ext4, Ext4Error, Inode

DEFAULT_SCOPE = [
    "/data/com.android.browser",
    "/data/com.chrome.dev",
    "/data/com.facebook.orca",
    "/data/com.facebook.lite",
    "/data/com.whatsapp",
    "/data/com.google.android.gm",
    "/system",
]


@dataclass
class BlockOwner:
    """Which file owns a physical block, and where the block starts in the file."""

    path: str
    inode: int
    file_offset: int
    size: int


class BlockIndex:
    """physical block -> file mapping for a set of directory subtrees."""

    def __init__(self, block_size: int, image: str, image_size: int = 0) -> None:
        self.block_size = block_size
        self.image = image
        self.image_size = image_size
        self._blocks: dict[int, BlockOwner] = {}
        self.files: int = 0
        self.dirs: int = 0
        self.build_seconds: float = 0.0
        #: Files whose inode could not be read, and roots that could not be
        #: resolved.  A missing inode means the block map has a hole, and a
        #: block map with a hole answers "what is at this offset" with "nothing
        #: is" — so the hole is reported, not absorbed.
        self.skipped: list[dict] = []
        #: Directories the walk could not list, carried over from the reader.
        self.walk_errors: list[dict] = []

    def matches(self, image: str, image_size: int = 0) -> bool:
        """Is this index a reading of *this* image?

        The cache lives beside the case, not beside the image, so it survives
        switching images.  Loading it anyway answers "which file owns this offset"
        with another filesystem's answer, confidently and without an error — the
        failure mode this project keeps paying for.  Size is compared as well as
        path, so an image rewritten in place does not inherit the old index either.
        """
        if self.image != image:
            return False
        if self.image_size and image_size and self.image_size != image_size:
            return False
        return True

    @property
    def block_count(self) -> int:
        return len(self._blocks)

    def add_inode(self, path: str, inode: Inode, is_dir: bool) -> None:
        if is_dir or not inode.is_reg:
            if is_dir:
                self.dirs += 1
            return
        self.files += 1
        for extent in inode.extents:
            for i in range(extent.count):
                block = extent.physical + i
                previous = self._blocks.get(block)
                if previous is not None:
                    previous.path = f"{previous.path},{path}"
                    continue
                self._blocks[block] = BlockOwner(
                    path=path,
                    inode=inode.number,
                    file_offset=(extent.logical + i) * self.block_size,
                    size=inode.size,
                )

    def lookup(self, offset: int) -> BlockOwner | None:
        """Return the owner of the block holding image byte ``offset``."""
        return self._blocks.get(offset // self.block_size)

    def owner_at(self, offset: int) -> dict | None:
        """Human-friendly lookup result with the in-file offset resolved."""
        owner = self.lookup(offset)
        if owner is None:
            return None
        return {
            "image_offset": offset,
            "block": offset // self.block_size,
            "path": owner.path,
            "inode": owner.inode,
            "file_offset": owner.file_offset + (offset % self.block_size),
            "file_size": owner.size,
        }

    def files_containing(self, offset: int) -> list[BlockOwner]:
        """All owners of a block, in case of duplicate/competing mappings."""
        owner = self._blocks.get(offset // self.block_size)
        if owner is None:
            return []
        return [owner]

    def summary(self) -> dict:
        return {
            "image": self.image,
            "image_size": self.image_size,
            "block_size": self.block_size,
            "blocks_indexed": self.block_count,
            "bytes_indexed": self.block_count * self.block_size,
            "files": self.files,
            "dirs": self.dirs,
            "build_seconds": round(self.build_seconds, 2),
            "skipped": len(self.skipped) + len(getattr(self, "walk_errors", [])),
            "skipped_detail": self.skipped[:5],
            "walk_errors": len(getattr(self, "walk_errors", [])),
            "complete": not self.skipped and not getattr(self, "walk_errors", []),
        }

    def save(self, path: str) -> str:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        payload = {
            "version": 2,
            "block_size": self.block_size,
            "image": self.image,
            "image_size": self.image_size,
            "summary": self.summary(),
            "blocks": {
                str(block): [owner.path, owner.inode, owner.file_offset, owner.size]
                for block, owner in self._blocks.items()
            },
        }
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)
        return path

    @classmethod
    def load(cls, path: str) -> BlockIndex:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
        index = cls(
            payload["block_size"],
            payload.get("image", ""),
            int(payload.get("image_size", 0)),
        )
        for block, (owner_path, inode, file_offset, size) in payload["blocks"].items():
            index._blocks[int(block)] = BlockOwner(owner_path, inode, file_offset, size)
        summary = payload.get("summary", {})
        index.files = summary.get("files", 0)
        index.dirs = summary.get("dirs", 0)
        index.build_seconds = summary.get("build_seconds", 0.0)
        return index

    @classmethod
    def build(
        cls,
        fs: Ext4,
        scope: list[str] | None = None,
        progress=None,
        include_dirs: bool = False,
    ) -> BlockIndex:
        """Walk the given subtrees and index every regular file's data blocks.

        ``progress`` is called with (files_done, current_path).
        """
        started = time.time()
        try:
            image_size = os.path.getsize(fs.path)
        except OSError:
            image_size = 0
        index = cls(fs.block_size, fs.path, image_size)
        for root in scope or DEFAULT_SCOPE:
            try:
                root_inode = fs.resolve(root)
            except KeyError as exc:
                index.skipped.append({"path": root, "error": str(exc)[:200]})
                continue
            if not root_inode.is_dir:
                index.add_inode(root, root_inode, False)
                continue
            if include_dirs:
                index.add_inode(root, root_inode, True)
            for path, entry in fs.walk(root, include_files=True):
                if not entry.is_reg:
                    continue
                try:
                    inode = fs.inode(entry.inode)
                except (Ext4Error, KeyError, struct.error, ValueError, OSError) as exc:
                    index.skipped.append({"path": path, "error": str(exc)[:200]})
                    continue
                index.add_inode(path, inode, False)
                if progress is not None and index.files % 500 == 0:
                    progress(index.files, path)
        index.walk_errors = list(getattr(fs, "walk_errors", []))
        index.build_seconds = time.time() - started
        return index
