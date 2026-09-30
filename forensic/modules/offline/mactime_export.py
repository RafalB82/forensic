# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""The image exported in the format the rest of the world already reads.

A body file is not a report.  It is the inventory every timeline tool in this
field expects: one line per file with its four timestamps, and nothing else.
The Sleuth Kit writes it, ``mactime`` reads it, spreadsheets import ``mactime -d``.
A forensic report that cannot be dropped into those tools has to be re-typed by
somebody before it can be examined, and every re-typing is a chance to introduce
an error that is invisible afterwards.

The format was established by feeding candidate lines to ``mactime`` and reading
what it complained about, because three details differ from the obvious guess and
none of them produce an error:

* the **name is the second field**, not the last, and a name containing ``|`` is
  fine because the reader splits only as many times as the format has fields;
* the four times are **seconds since the epoch** — ``mactime`` rejects a
  formatted date with "isn't numeric in numeric lt";
* the mode column is ``type/permissions`` as **one** field, with the type letter
  repeated inside it, and for a socket the repeated letter is ``h`` rather than
  ``s``.

The first column is MD5.  We leave it as ``0``, meaning "not computed": this
tool hashes with SHA-256 and an MD5 in a forensic report is a liability, so the
honest marker is no marker.  It is stated rather than hidden, because a reader
comparing against ``fls -m`` will see the difference.

The second half of the module is a **disclosure, not a check**.  ``fls -r -m``
lists deleted entries as well and this reader does not, so the two inventories
differ, and the difference is the number stated in ``tsk_crosscheck --param
check=coverage``.  Writing our own inventory without saying so would let a reader
assume the two are the same set.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from ...core import i18n, timeline
from ...core.findings import ModuleResult
from ...core.session import Ctx
from ..registry import BOOL, ModuleSpec, Param, register

#: TSK's mount-point argument to ``fls -m``, which is what makes the names
#: absolute.  Without it the output carries the recursive depth marker instead
#: (``-p/lost+found``), which is a TSK artefact and not a path.
TSK_MOUNT = "/"


def inventory(ctx: Ctx) -> tuple[list[str], list[dict]]:
    """One body-file line per allocated file, in walk order, plus what was refused.

    Deleted entries are absent, not because they are missed but because this
    reader does not enumerate unlinked directory entries; the count is reported
    next to TSK's so the gap is visible.

    A name containing a newline cannot go into a body file without splitting one
    record into two, so those files are **refused and returned**, never dropped
    quietly.  The reference image has 102 of them — all in one application's
    image cache, all with a trailing newline, which is itself a finding about
    the device rather than about the export.
    """
    fs = ctx.fs()
    lines: list[str] = []
    refused: list[dict] = []
    for path, entry in fs.walk("/"):
        node = fs.inode(entry.inode)
        try:
            lines.append(
                timeline.body_line(
                    path,
                    node.number,
                    node.mode,
                    node.uid,
                    node.gid,
                    node.size,
                    node.atime,
                    node.mtime,
                    node.ctime,
                    node.crtime,
                )
            )
        except ValueError as exc:
            refused.append(
                {
                    "path": path,
                    "inode": entry.inode,
                    "size": node.size,
                    "why": str(exc),
                }
            )
    return lines, refused


def _tsk_body(image: str, timeout: int = 3600) -> tuple[int, str, str]:
    """``fls -r -m / image`` — TSK's own inventory, for the coverage comparison."""
    from ...core.imagemount import tool_path

    fls = tool_path("fls")
    if not fls:
        return 127, "", "fls nie jest zainstalowany"
    import subprocess

    try:
        proc = subprocess.run(  # noqa: S603 - argv built here, never a shell string
            [fls, "-r", "-m", TSK_MOUNT, image],
            capture_output=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 126, "", str(exc)
    # Names are raw bytes; decoding them here would lose the ones that are not
    # valid UTF-8, and the count is all this comparison needs.
    return proc.returncode, proc.stdout.decode("utf-8", "surrogateescape"), proc.stderr.decode(
        "utf-8", "replace"
    )


#: TSK's virtual ``$OrphanFiles`` container.  It has no directory entry on the
#: disk — it is a place TSK puts unallocated inodes — and its body-file line
#: carries the type letter ``V``.  Counting it as a live file would invent a
#: one-file coverage gap that does not exist.
TSK_VIRTUAL_MARK = "V|"


def _count_tsk(text: str) -> dict[str, int]:
    live = unlinked = malformed = virtual = 0
    for line in text.splitlines():
        if len(line.split("|", 11)) < 11:
            malformed += 1
            continue
        if line.startswith(TSK_VIRTUAL_MARK) or "$OrphanFiles" in line:
            virtual += 1
            continue
        if " (deleted" in line:
            unlinked += 1
        else:
            live += 1
    return {"live": live, "unlinked": unlinked, "malformed": malformed, "virtual": virtual}


def _validate_with_mactime(body_path: Path, timeout: int = 3600) -> dict[str, Any]:
    """Run the exported body file through ``mactime`` and report what happened.

    This is the acceptance test that matters: a body file that no timeline tool
    can read is not an export, however plausible it looks.  ``mactime`` is asked
    for its daily index in comma-separated form, which is the form a spreadsheet
    import would use, so the check exercises the same path an examiner would.
    """
    from ...core.imagemount import tool_path

    mactime = tool_path("mactime")
    if not mactime:
        return {"available": False, "accepted": None, "why": "mactime nie jest zainstalowany"}
    import subprocess
    import tempfile

    out: dict[str, Any] = {"available": True}
    with tempfile.TemporaryDirectory(prefix="forensic-mactime-") as tmp:
        index = Path(tmp) / "index.csv"
        try:
            proc = subprocess.run(  # noqa: S603 - argv built here, never a shell string
                [mactime, "-b", str(body_path), "-i", "day", str(index), "-d"],
                capture_output=True, timeout=timeout, check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            out.update({"accepted": False, "why": str(exc)})
            return out
        err = (proc.stderr or b"").decode("utf-8", "replace")
        # mactime warns loudly about a deprecated package separator on Debian and
        # still exits 0; that warning is not a rejection and is filtered out so a
        # real complaint is visible.
        complaints = [
            line
            for line in err.splitlines()
            if line.strip() and "deprecated" not in line
        ]
        rows = 0
        if index.exists():
            rows = sum(1 for _ in index.read_text(encoding="utf-8", errors="replace").splitlines())
        out.update(
            {
                "returncode": proc.returncode,
                "accepted": proc.returncode == 0 and not complaints,
                "complaints": complaints[:5],
                "index_days": rows,
            }
        )
    return out


def _package_of(refused: list[dict]) -> str:
    """Which application the unwriteable names came from, if they share one."""
    packages = set()
    for item in refused:
        parts = item["path"].split("/")
        packages.add(parts[2] if len(parts) > 2 and parts[1] == "data" else "/".join(parts[1:3]))
    return ", ".join(sorted(packages)) if len(packages) <= 3 else f"{len(packages)} pakietów"


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("mactime_export")
    if not ctx.image.exists():
        res.add("critical", i18n.t("msg.image_missing"), str(ctx.image))
        return ctx.record(res)
    started = time.time()
    want_tsk = bool(params.get("compare_tsk", True))
    lines, refused = inventory(ctx)
    walked = len(lines) + len(refused)
    if not lines:
        res.add("critical", "Wędrówka nie zwróciła żadnego pliku", values={"lines": 0})
        return ctx.record(res)
    body = timeline.body_file(
        lines,
        comment=(
            f"forensic {ctx.config.case} — {len(lines)} przydzielonych plików; "
            "MD5=0 (nie liczymy); czasy w sekundach od epoki"
        ),
    )
    body_path = ctx.work("exports") / "mactime.body"
    body_path.write_text(body, encoding="utf-8")
    res.export(body_path)
    # A CSV in the same order, because a spreadsheet is what most people open,
    # and a second rendering costs nothing while a body file alone is opaque.
    csv_path = ctx.work("exports") / "mactime.csv"
    csv_lines = ["md5,name,inode,mode,uid,gid,size,atime,mtime,ctime,crtime"]
    for line in lines:
        fields = line.split("|", 11)
        cells = [f'"{f}"' if ("," in f or '"' in f) else f for f in fields]
        csv_lines.append(",".join(cells))
    csv_path.write_text("\n".join(csv_lines) + "\n", encoding="utf-8")
    res.export(csv_path)
    validation = _validate_with_mactime(body_path) if params.get("validate", True) else {
        "available": False, "accepted": None, "why": "walidacja wyłączona"
    }
    parts: dict[str, Any] = {
        "entries": len(lines),
        "refused": len(refused),
        "refused_detail": refused[:20],
        "body": str(body_path),
        "csv": str(csv_path),
        "md5": "0 — nie liczymy MD5; SHA-256 jest w raporcie i w manifestach",
        "format": "MD5|name|inode|mode|type_as|uid|gid|size|atime|mtime|ctime|crtime",
        "mactime": validation,
    }
    if want_tsk:
        code, text, err = _tsk_body(str(ctx.image))
        if code != 0:
            parts["tsk_error"] = (err or "").strip()[:200]
        else:
            counts = _count_tsk(text)
            parts["tsk"] = counts
            parts["tsk_total"] = counts["live"] + counts["unlinked"]
            parts["coverage_gap"] = counts["unlinked"]
            res.add(
                "ok" if counts["live"] == walked else "finding",
                f"TSK wymienia {counts['live']} przydzielonych plików, my {walked}"
                + (f" (bez {len(refused)} odrzuconych nazw z końcem wiersza)"
                   if refused else ""),
                detail=(
                    f"TSK dodatkowo {counts['virtual']} wpisów wirtualnych "
                    f"($OrphanFiles, nie ma ich na dysku) i {counts['unlinked']} "
                    "niepodlinkowanych, których nie enumerujemy"
                ),
                values={
                    "tsk_live": counts["live"],
                    "our_walk": walked,
                    "tsk_virtual": counts["virtual"],
                    "tsk_unlinked": counts["unlinked"],
                    "refused": len(refused),
                },
            )
    parts["seconds"] = round(time.time() - started, 1)
    res.data = parts
    from ...core.export import to_json

    res.export(to_json(ctx.work("exports") / "mactime_export.json", parts))
    if validation.get("accepted") is True:
        res.add(
            "ok",
            f"mactime przyjął plik body: {len(lines)} wpisów, "
            f"{validation.get('index_days')} dni w indeksie",
            detail="format potwierdzony przez mactime, nie tylko zgodny z opisem",
            values={"entries": len(lines), "index_days": validation.get("index_days")},
        )
    elif validation.get("accepted") is False:
        res.add(
            "critical",
            "mactime odrzucił plik body",
            detail="; ".join(validation.get("complaints", []))[:400] or str(validation.get("why")),
            values=validation,
        )
    if refused:
        res.add(
            "finding",
            f"{len(refused)} plików nie da się zapisać w pliku body — nazwa zawiera "
            "znak końca wiersza",
            detail=(
                "Format body nie ma sposobu na zakodowanie znaku nowej linii w nazwie, "
                "a dopisanie go rozerwałoby jeden rekord na dwa. Pliki są pomijane, "
                "nie pomijane po cichu. Wszystkie z jednego pakietu "
                f"({_package_of(refused) or '?'}) — to cecha urządzenia, nie eksportu."
            ),
            values={
                "refused": len(refused),
                "examples": [item["path"] for item in refused[:5]],
                "sizes": [item["size"] for item in refused[:5]],
            },
        )
    gap = parts.get("coverage_gap")
    if gap:
        res.add(
            "warn",
            f"TSK wymienia dodatkowo {gap} niepodlinkowanych wpisów, których ten "
            "eksport nie zawiera",
            detail=(
                f"nasz eksport: {parts.get('tsk', {}).get('live', 0)} przydzielonych; "
                f"TSK łącznie {parts.get('tsk_total', 0)}. Luka jest jawna i taka sama, "
                "jak raportowana przez tsk_crosscheck --param check=coverage."
            ),
            values={
                "our_live": parts.get("tsk", {}).get("live"),
                "tsk_total": parts.get("tsk_total"),
                "gap": gap,
            },
        )
    res.add(
        "info",
        f"Eksport body: {len(lines)} przydzielonych plików"
        + (f" (z {len(refused)} odrzuconych)" if refused else "")
        + ", MD5=0 (nie liczymy)",
        detail=(
            "kolumna trybu to litera + '/' + typ + uprawnienia, zgodnie z tym, co "
            "pisze fls -m; czasy w sekundach od epoki"
        ),
        values={
            "entries": len(lines),
            "refused": len(refused),
            "body": str(body_path),
            "csv": str(csv_path),
        },
    )
    res.note(f"{parts['seconds']}s")
    return ctx.record(res)


register(
    ModuleSpec(
        id="mactime_export",
        category="timeline",
        title="mod.mactime_export.title",
        summary="mod.mactime_export.summary",
        params=[
            Param(key="validate", label="Sprawdź mactime", default=True, kind=BOOL),
            Param(key="compare_tsk", label="Porównaj z fls -m", default=True, kind=BOOL),
        ],
        run=run,
    )
)
