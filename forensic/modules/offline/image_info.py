# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Image overview: size, ext4 geometry, feature flags, fs state, checksums."""

from __future__ import annotations

import time
from pathlib import Path

from ...core import fsformat, i18n
from ...core.evidence import CHUNK_BYTES as MB, sha256_file
from ...core.export import human_bytes, to_json
from ...core.ext4 import Ext4Error
from ...core.findings import ModuleResult
from ...core.session import Ctx
from ..registry import BOOL, ModuleSpec, Param, register

__all__ = ["MB", "sha256_file", "looks_like_gpt_or_mbr", "run"]


def looks_like_gpt_or_mbr(path: Path) -> dict:
    """Detect a whole-disk image (GPT/MBR) rather than a bare partition."""
    out = {"gpt": False, "mbr": False, "partitions": 0}
    with open(path, "rb") as handle:
        first = handle.read(512)
    if len(first) >= 512 and first[510:512] == b"\x55\xaa":
        out["mbr"] = True
    if len(first) >= 512 and first[446:462].rstrip(b"\0"):
        out["mbr"] = True
    with open(path, "rb") as handle:
        handle.seek(512)
        header = handle.read(512)
    if len(header) >= 92 and header[0:8] == b"EFI PART":
        import struct

        entries, entry_size = struct.unpack_from("<II", header, 80)
        out["gpt"] = True
        out["partitions"] = entries
        out["entry_size"] = entry_size
        out["disk_guid"] = header[56:72].hex()
    return out


def _erofs_overview(ctx: Ctx, res: ModuleResult, kind: dict, exc: Exception) -> ModuleResult:
    """Describe an EROFS image: what the tree says and how much of it we can read.

    The coverage line is the point.  A compressed ``/system`` — the normal case on
    a current device — yields a complete, correct tree of names, sizes, modes and
    timestamps, and no file contents at all.  Reporting that as a successful
    read would be the same mistake as an empty directory that is not empty: the
    analyst has to be told which half of the evidence is in hand.
    """
    from ...core.erofs import Erofs, ErofsError

    try:
        fs = Erofs(ctx.image)
    except ErofsError as inner:
        res.add("critical", f"EROFS: {inner}", detail=str(exc)[:200])
        return res
    sb = fs.superblock
    coverage = fs.coverage()
    res.add(
        "ok",
        f"EROFS: blok {1 << sb['blkszbits']} B, {sb['inos']} inodów, "
        f"{sb['blocks']} bloków, UUID {sb['uuid'][:8]}…",
        detail=(
            f"volume: {sb['volume_name'] or '(bez nazwy)'}; meta_blkaddr={sb['meta_blkaddr']}; "
            f"pakietów w superbloku: {sb['feature_compat']:#x}"
        ),
        values={
            "block_size": 1 << sb["blkszbits"],
            "inodes": sb["inos"],
            "blocks": sb["blocks"],
            "uuid": sb["uuid"],
            "volume_name": sb["volume_name"],
            "meta_blkaddr": sb["meta_blkaddr"],
            "feature_compat": f"0x{sb['feature_compat']:08x}",
            "root_nid": sb["root_nid"],
        },
    )
    severity = "ok" if coverage["contents_complete"] else "warn"
    res.add(
        severity,
        f"Pokrycie EROFS: {coverage['files']} plików, "
        f"{coverage['readable_inline'] + coverage['readable_plain']} z odczytaną treścią, "
        f"{coverage['compressed']} skompresowanych",
        detail=(
            "wszystkie nazwy, rozmiary, tryby i czasy są poprawne; treści plików "
            "skompresowanych wymagają dekompresora LZ4, którego stdlib nie ma"
            if not coverage["contents_complete"]
            else "drzewo i treści w całości dostępne bez dekompresji"
        ),
        values=coverage,
    )
    fs.close()
    return res


def _f2fs_overview(ctx: Ctx, res: ModuleResult, kind: dict, exc: Exception) -> ModuleResult:
    """Describe an F2FS image: the volume, the checkpoint, and how much we can read.

    F2FS is the format of ``/data`` on a current phone, so this is the branch an
    analyst hits most often once they leave ext4 behind.  Three things have to be
    said, and each is a different kind of fact:

    * **the volume** — geometry, uuid, which kernel made it;
    * **the checkpoint** — which of the two packs is live, whether it recorded a
      clean unmount, and *why* it stopped, because a checkpoint that stopped for a
      fault is a different volume from one that stopped for a shutdown;
    * **the coverage** — what fraction of the tree this reader can hand over, and
      why the rest is out of reach.  A compressed or encrypted file gives correct
      names, sizes, modes and times and no content, and saying "12 files
      unreadable" without saying why would be the same mistake as an empty
      directory that is not empty.
    """
    from ...core.f2fs import F2fs, F2fsError

    try:
        fs = F2fs(ctx.image)
    except F2fsError as inner:
        res.add("critical", f"F2FS: {inner}", detail=str(exc)[:200])
        return res
    sb = fs.superblock
    cp = fs.checkpoint
    coverage = fs.coverage()
    res.add(
        "ok",
        f"F2FS: blok {1 << sb['log_blocksize']} B, {sb['block_count']} bloków "
        f"({fs.size_bytes} B), {sb['segment_count']} segmentów, "
        f"{sb['section_count']} sekcji, UUID {sb['uuid'][:8]}…",
        detail=(
            f"wersja {sb['major_ver']}.{sb['minor_ver']}; jądro: {sb['version'][:120]}; "
            f"segment = {1 << sb['log_blocks_per_seg']} bloków, "
            f"segs/section = {sb['segs_per_sec']}, sections/zone = {sb['secs_per_zone']}; "
            f"główny obszar od bloku {sb['main_blkaddr']}"
        ),
        values={
            "block_size": 1 << sb["log_blocksize"],
            "block_count": sb["block_count"],
            "size_bytes": fs.size_bytes,
            "segment_count": sb["segment_count"],
            "section_count": sb["section_count"],
            "blocks_per_segment": 1 << sb["log_blocks_per_seg"],
            "uuid": sb["uuid"],
            "volume_name": sb["volume_name"],
            "version": sb["version"],
            "feature": f"0x{sb['feature']:08x}",
            "features": fs.feature_names(),
            "encryption_level": sb["encryption_level"],
            "root_ino": sb["root_ino"],
            "main_blkaddr": sb["main_blkaddr"],
        },
    )
    packs = ", ".join(
        f"pakiet {p['index']} wersja 0x{p['checkpoint_ver']:x}"
        + (" (żywy)" if p["index"] == cp["index"] else "")
        for p in cp["packs"]
    )
    res.add(
        "ok" if not cp["unclean"] else "warn",
        f"Checkpoint: wersja 0x{cp['checkpoint_ver']:x}, {cp['flag_names']}, "
        f"następny wolny nid {cp['next_free_nid']}, "
        f"{cp['valid_node_count']} węzłów i {cp['valid_inode_count']} inodów",
        detail=(
            f"{packs}; powód zatrzymania: {fs.stop_reason()}; "
            f"segmentów wolnych {cp['free_segment_count']} "
            f"({cp['free_blocks']} B), zarezerwowanych {cp['rsvd_segment_count']}, "
            f"nadmiarowych {cp['overprov_segment_count']}"
        ),
        values={
            "checkpoint_ver": cp["checkpoint_ver"],
            "live_pack": cp["index"],
            "pack_count": cp["pack_count"],
            "ckpt_flags": f"0x{cp['ckpt_flags']:08x}",
            "ckpt_flag_names": cp["flag_names"],
            "unclean": cp["unclean"],
            "stop_reason": fs.stop_reason(),
            "valid_node_count": cp["valid_node_count"],
            "valid_inode_count": cp["valid_inode_count"],
            "next_free_nid": cp["next_free_nid"],
            "free_segment_count": cp["free_segment_count"],
            "free_blocks": cp["free_blocks"],
            "valid_block_count": cp["valid_block_count"],
        },
    )
    severity = "ok" if coverage["contents_complete"] else "warn"
    if coverage["walk_errors"]:
        headline = (
            f"Pokrycie F2FS: {coverage['dirs']} katalogów, z czego "
            f"{coverage['dirs_listed']} wypisano; {coverage['files']} plików, "
            f"{coverage['readable']} z odczytaną treścią"
        )
    else:
        headline = (
            f"Pokrycie F2FS: {coverage['dirs']} katalogów, {coverage['files']} plików, "
            f"{coverage['readable']} z odczytaną treścią, "
            f"{coverage['refused']} odmówionych, "
            f"{coverage['inline_data']} z danymi inline"
        )
    res.add(
        severity,
        headline,
        detail=(
            (
                f"nie wypisano {coverage['walk_errors']} katalogów: "
                + "; ".join(
                    f"{e['path']}: {e['error'].split(': ', 1)[-1]}"
                    for e in coverage["walk_error_detail"]
                )
                + " — "
            )
            if coverage["walk_errors"]
            else ""
        )
        + (
            "nazw nie da się tu czytać, metadane inodów są poprawne; "
            if not coverage["names_complete"]
            else "wszystkie nazwy, rozmiary, tryby i czasy są poprawne; "
        )
        + (
            "powody odmowy treści: "
            + (
                ", ".join(
                    f"{kind} × {count}"
                    for kind, count in sorted(coverage["refused_reasons"].items())
                )
                or "brak"
            )
        )
        + (
            f"; luk w mapie bloków: {coverage['holes']}" if coverage["holes"] else ""
        ),
        values=coverage,
    )
    fs.close()
    return res


def _xattr_census(fs, cap: int = 0) -> dict:
    """Count inodes that point at an extended-attribute block, and what is in them.

    The scan reads inode tables sequentially, which on a 25 GiB image is a few
    seconds, so it is bounded by ``cap`` when a caller wants an answer faster
    than completeness.  Distinct SELinux labels are reported as counts, because
    a volume with a hundred thousand *identical* labels is a different finding
    from one with a hundred thousand distinct ones.
    """
    import struct

    sb = fs.superblock
    size = sb["inode_size"]
    per_block = sb["block_size"] // size
    per_group = sb["inodes_per_group"]
    names: dict[str, int] = {}
    selinux: dict[str, int] = {}
    with_block = 0
    scanned = 0
    for group in fs._groups:
        first = group["group"]
        if cap and scanned >= cap:
            break
        table = group["inode_table"]
        wanted = min(per_group, max(0, sb["inodes_count"] - first * per_group))
        for start in range(0, wanted, per_block * 256):
            if cap and scanned >= cap:
                break
            count = min(per_block * 256, wanted - start)
            data = b"".join(
                fs._cache.get(table + (start // per_block) + offset)
                for offset in range(-(-count // per_block))
            )
            for index in range(count):
                at = index * size
                if at + 0x6A > len(data):
                    break
                low = struct.unpack_from("<I", data, at + 0x68)[0]
                high = struct.unpack_from("<H", data, at + 0x76)[0] if size > 0x78 else 0
                scanned += 1
                if not (low or high):
                    continue
                with_block += 1
                try:
                    node = fs.inode(first * per_group + start + index + 1)
                except Exception:  # noqa: BLE001 - census must not abort the module
                    continue
                for key, value in node.xattrs.items():
                    names[key] = names.get(key, 0) + 1
                    if key == "security.selinux":
                        label = node.xattr_text(key)
                        selinux[label] = selinux.get(label, 0) + 1
    return {
        "scanned": scanned,
        "inodes_with_block": with_block,
        "names": sorted(names),
        "name_counts": names,
        "selinux": selinux,
        "selinux_distinct": len(selinux),
    }


def run(ctx: Ctx, params: dict) -> ModuleResult:
    started = time.time()
    res = ctx.new_result("image_info")
    image = ctx.image
    if not image.exists():
        res.add("critical", i18n.t("msg.image_missing"), str(image))
        return ctx.record(res)
    size = image.stat().st_size
    res.add(
        "info",
        f"{i18n.t('status.image')}: {image.name}",
        detail=str(image),
        values={"path": str(image), "size_bytes": size, "size": human_bytes(size)},
    )
    partition = looks_like_gpt_or_mbr(image)
    if partition["gpt"] or partition["mbr"]:
        res.add(
            "warn",
            "Obraz wygląda na obraz całego dysku (GPT/MBR), nie partycję",
            detail="Użyj offsetu partycji, aby analizować fragment.",
            values=partition,
        )
    try:
        fs = ctx.fs()
    except Ext4Error as exc:
        # The identification is worth more than the failure.  A "/system" on
        # EROFS is not a broken image, and saying so is the whole difference
        # between an analyst who knows what to do next and one who goes looking
        # for a corrupt partition that is perfectly fine.
        kind = fsformat.detect(ctx.image)
        if kind["kind"] == "erofs":
            return _erofs_overview(ctx, res, kind, exc)
        if kind["kind"] == "f2fs":
            return _f2fs_overview(ctx, res, kind, exc)
        res.add(
            "critical" if kind["kind"] == fsformat.UNKNOWN else "warn",
            f"Format systemu plików: {kind['name']}"
            + ("" if kind["readable"] else " — nieobsługiwany"),
            detail=f"{kind['verdict']}. {exc}",
            values={
                "kind": kind["kind"],
                "name": kind["name"],
                "readable": kind["readable"],
                "magic": kind.get("magic", ""),
                "offset": kind.get("offset", -1),
                "supported": kind["supported"],
                "error": str(exc),
            },
        )
        return ctx.record(res)
    sb = fs.superblock
    features = sb["features"]
    geometry = {
        "block_size": sb["block_size"],
        "blocks_count": sb["blocks_count"],
        "size_bytes": fs.size_bytes,
        "inodes_count": sb["inodes_count"],
        "inode_size": sb["inode_size"],
        "blocks_per_group": sb["blocks_per_group"],
        "inodes_per_group": sb["inodes_per_group"],
        "desc_size": sb["desc_size"],
        "groups": -(-sb["blocks_count"] // sb["blocks_per_group"]),
        "first_data_block": sb["first_data_block"],
    }
    geometry["size"] = human_bytes(geometry["size_bytes"])
    res.add(
        "ok",
        "Geometria ext4",
        values=geometry,
    )
    flags = {
        "features": features,
        "has_extents": "EXTENTS" in features,
        "has_inline_data": "INLINE_DATA" in features,
        "has_metadata_csum": "METADATA_CSUM" in features,
        "has_dir_index": "DIR_INDEX" in features,
        "has_64bit": "64BIT" in features,
        "recover_needed": "RECOVER" in features,
        "feature_compat": f"0x{sb['feature_compat']:08x}",
        "feature_incompat": f"0x{sb['feature_incompat']:08x}",
        "feature_ro_compat": f"0x{sb['feature_ro_compat']:08x}",
    }
    res.add("ok", "Flagi systemu plików", values=flags)
    # Extended attributes, counted over the whole inode table.  This is cheap —
    # the tables are sequential — and it answers a question a report should
    # answer rather than leave open: on this volume the SELinux labels of the
    # /system files come from the mount context and the policy, not from stored
    # attributes, so a reader that looked for `security.selinux` per file would
    # find nothing and might conclude there were no labels at all.
    xattr = _xattr_census(fs)
    res.add(
        "ok" if xattr["inodes_with_block"] else "info",
        f"Atrybuty rozszerzone: {xattr['inodes_with_block']} inodów ma blok atrybutów"
        + (f", etykiety SELinux: {len(xattr['selinux'])} różnych" if xattr["selinux"] else
           ", brak zapisanych etykiet SELinux (kontekst z polityki, nie atrybut)"),
        detail=(
            f"przeskanowano {xattr['scanned']} inodów; nazwy: "
            f"{', '.join(xattr['names']) or '—'}"
        ),
        values=xattr,
    )
    state = {
        "state": sb["state"],
        "state_name": sb["state_name"],
        "errors": sb["errors"],
        "uuid": sb["uuid"],
        "volume_name": sb["volume_name"],
        "last_mounted": sb["last_mounted"],
        "mkfs_time": i18n.t("common.unknown"),
        "journal_inode": sb["journal_inum"],
        "last_orphan": sb["last_orphan"],
        "free_blocks": sb["free_blocks"],
        "free_inodes": sb["free_inodes"],
        "reserved_blocks": sb.get("r_blocks_count"),
        "extra_isize": sb.get("min_extra_isize"),
        "fs_flags": f"0x{sb.get('flags', 0):08x}",
    }
    mkfs = sb["mkfs_time"]
    if 100_000_000 < mkfs < 2_000_000_000:
        try:
            from datetime import datetime, timezone

            state["mkfs_time"] = (
                datetime.fromtimestamp(mkfs, timezone.utc)
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z")
            )
        except Exception:
            pass
    severity = "ok" if sb["state"] == 1 else "warn"
    res.add(severity, "Stan systemu plików", values=state)

    # Metadata checksums, verified here rather than left to ``e2fsck -fn``: the
    # metadata_csum implementation is stdlib-only and needs neither root nor
    # e2fsprogs, so the answer is available on a machine that has neither.  The
    # third state matters — a filesystem without the feature has no checksums to
    # check, and reporting that as a pass would be claiming a check that never
    # ran.
    try:
        checksums = ctx.fs().checksums(int(params.get("csum_inodes", 200) or 0))
    except Ext4Error as exc:
        checksums = {"status": "error", "detail": str(exc)}
    if checksums.get("status") == "failed":
        res.add(
            "critical",
            "Sumy kontrolne metadanych: NIEZGODNE",
            detail=(
                f"{len(checksums.get('bad', []))} struktur nie zgadza się z sumą: "
                + "; ".join(item["what"] for item in checksums.get("bad", [])[:5])
                + ". Metadane są uszkodzone albo nieaktualne."
            ),
            values=checksums,
        )
    elif checksums.get("status") == "ok":
        res.add(
            "ok",
            f"Sumy kontrolne metadanych: zgodne ({checksums.get('ok_count', 0)})",
            detail=checksums.get("detail", ""),
            values=checksums,
        )
    else:
        res.add(
            "info",
            "Sumy kontrolne metadanych: brak w tym filesystemie",
            detail=checksums.get("detail", ""),
            values=checksums,
        )
    packages = ctx.packages()
    res.add(
        "info",
        "Mapowanie uid → pakiet (/system/packages.xml)",
        values={"packages": len(packages)} if packages else {},
    )
    digest = None
    if params.get("hash", ctx.config.hash_image_by_default):
        start = time.time()

        def progress(done: int, total: int) -> None:
            ctx.log(f"SHA-256 {human_bytes(done)} / {human_bytes(total)}")

        digest = sha256_file(image, progress=progress)
        res.add(
            "ok",
            "SHA-256 obrazu",
            values={"sha256": digest, "seconds": round(time.time() - start, 1)},
        )
    payload = {
        "image": str(image),
        "generated": i18n.t("common.done"),
        "geometry": geometry,
        "flags": flags,
        "state": state,
        "partition": partition,
        "sha256": digest,
        "packages": len(packages),
        "checksums": checksums,
    }
    res.data = payload
    path = to_json(ctx.work("exports") / "image_info.json", payload, ctx.masker)
    res.export(path)
    res.seconds = time.time() - started
    return ctx.record(res)


register(
    ModuleSpec(
        id="image_info",
        category="image",
        title="mod.image_info.title",
        summary="mod.image_info.summary",
        params=[
            Param(key="hash", label="param.hash", default=True, kind=BOOL),
            Param(
                key="csum_inodes",
                label="Ile inodów sprawdzić sumami (0 = tylko superblock i bitmapy)",
                default=200,
                kind="str",
                help=(
                    "obraz referencyjny ma 750 000 inodów, a sprawdzenie wszystkich "
                    "trwa pół minuty; limit jest raportowany w wyniku"
                ),
            ),
        ],
        run=run,
    )
)
