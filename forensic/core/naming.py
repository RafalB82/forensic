# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Naming files that come out of the image.

One rule, stated once: **one in-image path, one output file, and two different
in-image paths never share one.**  Both halves matter, and the second is the one
that was missing.

The first half is the flattening — an absolute path has to become a single
component under ``work/<case>/extracted/``, because a ``/`` in an extracted name
would put the file somewhere else than the manifest says, and ``..`` would climb
out of it entirely.  The second half cannot come from flattening at all:
``/a/b`` and ``/a_b`` both flatten to ``a_b``, so the second extraction overwrote
the first and the manifest went on to list two different SHA-256 values pointing
at one file on disk.  A manifest that certifies bytes it does not have is worse
than no manifest.

So a short digest of the original path is appended, and :func:`unique_names` does
not rely on the digest's margin: it checks, and extends with an ordinal if two
sources ever did land on one name.  The guarantee is structural.
"""

from __future__ import annotations

import hashlib
import re

#: Hex characters of the source-path digest.  Twelve is 48 bits, which makes a
#: collision between the handful of files one case extracts not a thing to reason
#: about — and :func:`unique_names` does not depend on it, so even a collision
#: cannot put two sources in one file.
DIGEST_CHARS = 12


def flat_name(path: str) -> str:
    """The readable part: one path component, with the separators flattened.

    Every character outside ``[A-Za-z0-9._-]`` becomes an underscore.  A name of
    ``.`` or ``..`` is the one case the substitution cannot catch, because dots
    are allowed — and as a path component ``..`` *is* the parent directory — so
    those two go to ``root`` like an empty path does.
    """
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", path.strip("/")) or "root"
    return "root" if name in (".", "..") else name


def safe_name(path: str) -> str:
    """The filename an in-image path is written to: readable **and** unique.

    Deterministic and stable across runs, which matters more than it sounds:
    re-running a case must not rename an artifact that a previous report, a court
    exhibit list or another tool's notes already refer to.
    """
    digest = hashlib.sha256(path.encode("utf-8", "surrogateescape")).hexdigest()
    return f"{flat_name(path)}--{digest[:DIGEST_CHARS]}"


def unique_names(paths: list[str]) -> dict[str, str]:
    """Map every source path to a distinct output filename.

    :func:`safe_name` makes a collision a 48-bit coincidence away; this makes it
    impossible.  Two *identical* sources keep one name — that is the point, and
    it is why the caller should decide the whole batch before writing the first
    file rather than naming as it goes.
    """
    out: dict[str, str] = {}
    taken: dict[str, str] = {}
    for path in paths:
        if path in out:
            continue
        name = safe_name(path)
        if taken.get(name, path) != path:
            ordinal = 2
            while f"{name}--{ordinal}" in taken:
                ordinal += 1
            name = f"{name}--{ordinal}"
        taken[name] = path
        out[path] = name
    return out