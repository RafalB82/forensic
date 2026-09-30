# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""A reader pointed at the wrong filesystem must say which one it found.

Both dedicated readers take the same shape: they check their own magic at their
own offset, and when it is wrong they call ``detect_bytes`` to name the format
that is actually there.  That branch used to subscript the result, which is a
``Signature`` dataclass, so pointing ``--image`` at a squashfs partition raised
``TypeError: 'Signature' object is not subscriptable`` — the one input an analyst
is most likely to try — instead of the sentence naming the real format.
"""

from __future__ import annotations

import pytest

from forensic.core.erofs import Erofs, ErofsError
from forensic.core.f2fs import F2fs, F2fsError
from forensic.core.fsformat import SIGNATURES, detect_bytes

READERS = ((F2fs, F2fsError, "F2FS"), (Erofs, ErofsError, "EROFS"))


def _image_with(path, kind: str, size: int = 8192) -> None:
    signature = next(s for s in SIGNATURES if s.kind == kind)
    head = bytearray(size)
    head[signature.offset : signature.offset + len(signature.magic)] = signature.magic
    path.write_bytes(bytes(head))


def test_detect_bytes_returns_an_object_not_a_mapping():
    """The premise of the two tests below, stated as its own assertion."""
    import tempfile
    from pathlib import Path

    directory = Path(tempfile.mkdtemp())
    image = directory / "x.img"
    _image_with(image, "squashfs")
    found = detect_bytes(image.read_bytes())
    assert found is not None
    assert found.kind == "squashfs"
    assert found.name == "SquashFS"


@pytest.mark.parametrize("reader, error, label", READERS)
def test_names_the_format_that_is_actually_there(tmp_path, reader, error, label):
    image = tmp_path / "system.squashfs.img"
    _image_with(image, "squashfs")
    with pytest.raises(error) as caught:
        reader(str(image))
    assert "to jest SquashFS" in str(caught.value)


@pytest.mark.parametrize("reader, error, label", READERS)
def test_unrecognised_bytes_give_the_bare_magic_message(tmp_path, reader, error, label):
    """Nothing matches any signature, so there is no format to name."""
    image = tmp_path / "random.img"
    image.write_bytes(b"\x11" * 8192)
    with pytest.raises(error) as caught:
        reader(str(image))
    assert label in str(caught.value)
    assert "to jest" not in str(caught.value)
