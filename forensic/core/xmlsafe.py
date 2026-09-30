# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""A size limit in front of every XML parse, and why it is enough.

Three places in the tool parse XML that came out of an evidence image: two
Android ``shared_prefs`` / ``backup_record`` files and one Qualcomm
``rawprogram*.xml``.  All three hand the bytes to :mod:`xml.etree.ElementTree`,
which is :mod:`expat` underneath.

**What this does not defend against.**  Entity expansion — the "billion laughs"
shape — needs a parser that resolves external or recursively defined entities,
and expat in CPython does not: ``ET.fromstring`` raises on an undefined entity
rather than fetching it, and there is no DTD retrieval to disable.  The
vulnerable builds are the ones carrying a pre-2.4.1 expat, where the billion
laughs protections were incomplete; CPython has required 2.4.1+ since 3.9 and
this project requires 3.10+, so that floor is what the size limit is leaning on.
``defusedxml`` would say so explicitly, at the cost of the "no dependencies"
property the rest of the project keeps.

**What it does defend against.**  A 200 MB file inside an image being turned
into a 200 MB string and then a tree of objects, in a tool whose whole point is
to walk hostile input.  Every parse the tool does is of a small preference or
configuration file; 5 MiB is already three orders of magnitude above the largest
one seen on a real device, so the limit costs nothing and bounds the work.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

MAX_XML = 5 * 1024 * 1024


def safe_fromstring(text: str) -> ET.Element:
    """Parse XML, refusing anything over :data:`MAX_XML`."""
    if len(text) > MAX_XML:
        raise ET.ParseError(f"XML > {MAX_XML} B")
    return ET.fromstring(text)
