# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""What the evidence *is* — the bytes under examination, named exactly once.

Two things live here and they are the same question seen from two ends.

:class:`EvidenceIdentity` answers *which file was examined*: resolved once, at
the start of a run, and handed to everything downstream instead of being
re-derived by each module that happens to need a path, a size or a hash.  Two
modules deriving it separately is how one of them ends up describing a different
file than the other — and a report that quotes a size from one and a hash from
the other is worse than a report that quotes neither, because it looks checked.

:class:`TruncatedEvidenceError` is the answer to the question the identity
raises: what happens when the file is **not** the whole filesystem it claims to
be?  The answer is never "pad the rest with zeros".  A short read at the end of
a truncated image used to be completed with ``b"\\0"`` up to the block size, and
because :meth:`forensic.core.ext4.Ext4.read_at` clips the result to the size the
inode declares, the caller received a buffer of *exactly* the right length,
full of zeros where the evidence used to be.  Nothing downstream could tell it
from real content, and ``extract_file`` went on to hash it and record the hash
in its manifest.  A fabricated SHA-256 in a forensic manifest is worse than no
manifest, so a short read is now an error the whole way up.

The distinction the error type carries is the one an analyst needs:

* ``Ext4Error`` and friends — *this is not a filesystem we can read*.
* :class:`TruncatedEvidenceError` — *this was a filesystem, and part of it is
  missing*.  Every byte past the cut is a file whose content is unknown, and the
  report has to say so rather than invent it.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: Streaming chunk for hashing and for block reads.  8 MiB is the size at which
#: a 27 GB image finishes in under three minutes on spinning storage while
#: staying small enough to not disturb the page cache of the evidence file.
CHUNK_BYTES = 8 * 1024 * 1024


class TruncatedEvidenceError(Exception):
    """The image ends before the structures inside it say it should.

    Deliberately **not** a subclass of the filesystem-specific errors: a caller
    that catches ``Ext4Error`` to say "this is not an ext4 I can read" would
    otherwise swallow truncation and report a whole-filesystem failure for a
    filesystem whose first half is perfectly legible.  The two want opposite
    answers — one says "wrong format", the other says "missing evidence" — and
    they must not collapse into one ``except`` arm.
    """


def sha256_file(
    path: Path,
    chunk: int = CHUNK_BYTES,
    progress: Callable[[int, int], None] | None = None,
) -> str:
    """Streaming SHA-256 with byte-level progress.

    Lives here rather than in the module that first needed it because hashing is
    a property of the *evidence*, not of any one module: acquisition, ``newcase``
    and ``verify`` all want it and none of them should have to reach sideways
    into another module to get it.
    """
    digest = hashlib.sha256()
    total = path.stat().st_size
    done = 0
    with open(path, "rb") as handle:
        while True:
            block = handle.read(chunk)
            if not block:
                break
            digest.update(block)
            done += len(block)
            if progress is not None:
                progress(done, total)
    return digest.hexdigest()


def read_exact(fd: int, length: int, offset: int, *, what: str = "blok") -> bytes:
    """``pread`` that refuses to come back short.

    ``os.pread`` returns fewer bytes than asked for at end-of-file and that is
    correct behaviour for it; for evidence it means the bytes are not there.  The
    only legitimate short read is a request that straddles the end, and for a
    filesystem the request size comes from the filesystem's own geometry, so a
    straddle here is truncation rather than a design.

    Kept as one function so that every reader in the package — ext4, F2FS,
    EROFS — fails the same way and with the same words.
    """
    data = os.pread(fd, length, offset)
    if len(data) < length:
        raise TruncatedEvidenceError(
            f"{what} nieczytelny w całości: {len(data)} z {length} B "
            f"przy offsiecie {offset} — obraz kończy się wcześniej, niż "
            f"deklaruje jego własna geometria"
        )
    return data


#: What :meth:`EvidenceIdentity.verify_against` concluded.  Four states, because
#: "we did not look" and "we looked and it was fine" must never print the same
#: word — see the module docstring for why that distinction is the whole point.
INTEGRITY_UNVERIFIED = "UNVERIFIED"
INTEGRITY_NOT_CHECKED = "NOT_CHECKED"
INTEGRITY_PASS = "PASS"
INTEGRITY_FAIL = "FAIL"

#: Ceiling on a single streamed extraction, 4 GiB.  Not a policy about what may be
#: extracted — a 10 GB file is legitimate evidence — but a stop on *corrupt*
#: metadata: ``i_size`` is a field in the image, and a corrupted one that reads as
#: four terabytes would otherwise have the tool write terabytes of zeros on the
#: analyst's disk.  A file that trips this is reported as not fully extracted
#: rather than quietly truncated to a prefix, which would be the sparse-read
#: mistake wearing a different hat.
DEFAULT_STREAM_LIMIT = 4 * 1024 * 1024 * 1024


def copy_stream(
    read_at: Callable[[int, int], bytes],
    out_path: Path,
    *,
    size: int,
    limit: int | None = None,
    chunk: int = CHUNK_BYTES,
) -> dict[str, Any]:
    """Copy ``size`` bytes read through ``read_at`` to ``out_path``, hashing as it goes.

    ``RAM ≈ 1 chunk`` whatever the artifact weighs, which is the whole point: the
    old path was ``blob = fs.read(path)`` then ``write_bytes`` then
    ``sha256(blob)``, so a 10 GB file was held in memory twice and hashed from
    there — and a truncated image produced a correctly-sized buffer of zeros whose
    hash went into a manifest.

    Three things this does that a hand-rolled loop would not:

    **The output is atomic.**  Bytes land in ``<name>.part`` and the finished file
    is renamed into place.  A failure part-way leaves nothing at the path the
    manifest names, so a half-written artifact can never be mistaken for an
    extracted one — and ``extract_file`` lists outputs before it writes them.

    **A short read is a failure, not a file.**  :class:`TruncatedEvidenceError`
    from the underlying reader propagates and the ``.part`` file is removed.

    **The declared size is bounded, and saying so.**  ``i_size`` comes from the
    image.  If it exceeds ``limit`` the copy stops there and the result carries
    ``complete: False`` — because handing back a prefix silently is precisely the
    defect this function was written to end.
    """
    ceiling = size if limit is None else min(size, limit)
    partial = out_path.with_name(out_path.name + ".part")
    digest = hashlib.sha256()
    written = 0
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(partial, "wb") as handle:
            while written < ceiling:
                block = read_at(written, min(chunk, ceiling - written))
                if not block:
                    break
                handle.write(block)
                digest.update(block)
                written += len(block)
        partial.replace(out_path)
    except BaseException:
        # Includes KeyboardInterrupt: a partial file left behind would be read by
        # the next run as a complete extraction of something smaller.
        partial.unlink(missing_ok=True)
        raise
    return {
        "path": str(out_path),
        "bytes": written,
        "sha256": digest.hexdigest(),
        "declared_size": size,
        "complete": written >= size,
        "chunk": chunk,
    }



@dataclass(frozen=True)
class EvidenceIdentity:
    """The one answer to "which bytes are these", for the whole run.

    ``size`` comes from ``stat`` and is therefore free, so it is always here and
    always true.  ``sha256`` is empty unless somebody asked for it, and hashing
    a 27 GB image takes minutes — see :meth:`identify`.  An empty ``sha256`` is
    a statement that nothing was computed, and every consumer below is written to
    say exactly that rather than to fall back to a remembered value.
    """

    path: Path
    size: int
    sha256: str = ""
    filesystem: str = ""
    #: Set when the file is shorter than the filesystem inside it claims to be.
    #: Kept as data rather than as an exception so the report can name the
    #: shortfall instead of only saying that reading failed.
    truncated_bytes: int = 0

    @classmethod
    def identify(
        cls,
        path: Path | str,
        *,
        hash_image: bool = False,
        filesystem: str = "",
        progress: Callable[[int, int], None] | None = None,
    ) -> EvidenceIdentity:
        """Identify ``path`` once, for everything downstream to share.

        ``hash_image`` is off by default and that is a cost decision, not a
        caution one: the reference image is 27 GB and hashes in 2m51s here, which
        is fine once and ruinous on every keystroke-driven run.  Callers that
        want the hash ask for it, and a run that did not ask reports the size
        check alone rather than implying more.
        """
        target = Path(path)
        stat = target.stat()
        return cls(
            path=target,
            size=stat.st_size,
            sha256=sha256_file(target, progress=progress) if hash_image else "",
            filesystem=filesystem,
        )

    def with_truncation(self, missing: int) -> EvidenceIdentity:
        return EvidenceIdentity(
            path=self.path,
            size=self.size,
            sha256=self.sha256,
            filesystem=self.filesystem,
            truncated_bytes=missing,
        )

    @property
    def truncated(self) -> bool:
        return self.truncated_bytes > 0

    def verify_against(
        self,
        *,
        expected_size: int | None = None,
        expected_sha256: str = "",
    ) -> dict:
        """Compare this identity with what a case file claims, and say which.

        Returns a dict rather than a bool because a bool cannot express the
        difference between "the recorded hash does not match" and "no hash was
        recorded and none was computed", and a verification report that prints
        the same word for both is asserting something it does not know.

        The size check runs unconditionally and is free.  The hash check runs
        only when there is something on both sides to compare.
        """
        size_ok = expected_size is None or expected_size == self.size
        expected = (expected_sha256 or "").strip().lower()
        computed = self.sha256.strip().lower()
        if not size_ok:
            verdict = INTEGRITY_FAIL
            why = (
                f"rozmiar {self.size} B różni się od zapisanego w case "
                f"{expected_size} B"
            )
        elif expected and not computed:
            verdict = INTEGRITY_NOT_CHECKED
            why = "case zawiera SHA-256, ale nie przeliczono go w tym przebiegu"
        elif not expected:
            verdict = INTEGRITY_UNVERIFIED
            why = "brak SHA-256 w case — rozmiar zgodny, zawartość niesprawdzona"
        elif computed == expected:
            verdict = INTEGRITY_PASS
            why = "rozmiar i SHA-256 zgodne"
        else:
            verdict = INTEGRITY_FAIL
            why = "SHA-256 obliczonego obrazu różni się od zapisanego w case"
        return {
            "path": str(self.path),
            "size": self.size,
            "size_expected": expected_size,
            "size_match": size_ok,
            "sha256": computed,
            "sha256_expected": expected,
            "sha256_computed": bool(computed),
            "filesystem": self.filesystem,
            "truncated_bytes": self.truncated_bytes,
            "integrity": verdict,
            "detail": why,
        }
