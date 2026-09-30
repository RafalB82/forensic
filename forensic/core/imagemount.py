# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Optional read-only mounting of an image with the loop device.

This is the one place in the tool where the *kernel* parses untrusted data: every
other module reads the image with :mod:`forensic.core.ext4`, the project's own
parser, which is the reason the tool works without root at all.  Mounting hands
that job to the kernel instead, so it needs root (or passwordless sudo) and the
extra options in :data:`DEFAULT_OPTIONS` — the tree ends up ``nodev,nosuid,noexec``
rather than a normal mount of whatever was in the image.

Everything here degrades gracefully: when ``sudo`` is unavailable the tool keeps
working purely through :mod:`forensic.core.ext4`.  Unmounting is attempted on
:func:`atexit` so an interrupted menu run does not leave a mount behind.
"""

from __future__ import annotations

import atexit
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from . import i18n

_MOUNTED: list[tuple[str, str]] = []


@dataclass
class MountInfo:
    image: str
    mountpoint: str
    source: str
    fstype: str
    options: str
    mounted_at: str

    def as_dict(self) -> dict:
        return {
            "image": self.image,
            "mountpoint": self.mountpoint,
            "source": self.source,
            "fstype": self.fstype,
            "options": self.options,
            "mounted_at": self.mounted_at,
        }


SBIN_DIRS = ("/sbin", "/usr/sbin", "/usr/local/sbin")

# The kernel parses the filesystem here, on an image that is by definition
# untrusted input.  ``nodev,nosuid,noexec`` cost a read-only mount nothing and
# close the three ways a mounted evidence image could be used against the
# machine it is examined on: a device node, a setuid binary, an executed binary.
DEFAULT_OPTIONS = "ro,loop,norecovery,nodev,nosuid,noexec"


def have(tool: str) -> bool:
    """True when a tool is on PATH or in one of the sbin directories."""
    if shutil.which(tool):
        return True
    return any(Path(directory, tool).exists() for directory in SBIN_DIRS)


def tool_path(tool: str) -> str | None:
    found = shutil.which(tool)
    if found:
        return found
    for directory in SBIN_DIRS:
        candidate = Path(directory, tool)
        if candidate.exists():
            return str(candidate)
    return None


def sudo_ok() -> bool:
    """True when a passwordless sudo works (needed only for mount/e2fsck)."""
    if os.geteuid() == 0:
        return True
    if not have("sudo"):
        return False
    try:
        proc = subprocess.run(
            ["sudo", "-n", "true"], capture_output=True, timeout=5, check=False
        )
        return proc.returncode == 0
    except Exception:
        return False


def _run(args: list[str], timeout: int = 300) -> subprocess.CompletedProcess:
    needs_root = not have("mount") or os.geteuid() != 0
    if needs_root and have("sudo"):
        return subprocess.run(
            ["sudo", "-n", *args], capture_output=True, text=True, timeout=timeout, check=False
        )
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)


def is_mounted(mountpoint: str) -> bool:
    try:
        with open("/proc/mounts", encoding="utf-8") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) > 1 and parts[1] == mountpoint:
                    return True
    except Exception:
        return False
    return False


def find_mount_for(image: str) -> MountInfo | None:
    """Return mount info when the given image (or its loop device) is mounted."""
    try:
        with open("/proc/mounts", encoding="utf-8") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) < 4:
                    continue
                source, mountpoint, fstype, options = parts[0], parts[1], parts[2], parts[3]
                if source == image or os.path.realpath(source) == os.path.realpath(image):
                    return MountInfo(
                        image=image,
                        mountpoint=mountpoint,
                        source=source,
                        fstype=fstype,
                        options=options,
                        mounted_at="",
                    )
    except Exception:
        return None
    return None


def mount(
    image: str,
    mountpoint: str,
    options: str = DEFAULT_OPTIONS,
    timeout: int = 300,
    keep: bool = False,
) -> tuple[MountInfo | None, str]:
    """Mount ``image`` read-only.  Returns (info, message)."""
    image_path = Path(image)
    if not image_path.exists():
        return None, f"{i18n.t('msg.image_missing')}: {image}"
    existing = find_mount_for(str(image_path))
    if existing is not None:
        return existing, i18n.t("msg.already_mounted")
    target = Path(mountpoint)
    if not target.is_dir():
        try:
            target.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            if not sudo_ok():
                return None, f"brak uprawnień do utworzenia punktu montowania: {target}"
            made = _run(["mkdir", "-p", str(target)], timeout=30)
            if made.returncode != 0 or not target.is_dir():
                return None, (made.stderr or f"nie można utworzyć {target}").strip()
    if is_mounted(str(target)):
        return None, f"{target}: {i18n.t('msg.already_mounted')}"
    mount_bin = tool_path("mount") or "mount"
    args = [mount_bin, "-o", options, str(image_path), str(target)]
    if not have("mount"):
        return None, i18n.t("msg.mount_needs_sudo")
    if os.geteuid() != 0:
        if not sudo_ok():
            return None, i18n.t("msg.mount_needs_sudo")
    proc = _run(args, timeout=timeout)
    if proc.returncode != 0:
        return None, (proc.stderr or proc.stdout or "mount failed").strip()
    info = find_mount_for(str(image_path))
    if info is None:
        info = MountInfo(
            image=str(image_path),
            mountpoint=str(target),
            source=str(image_path),
            fstype="ext4",
            options=options,
            mounted_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        )
    if not keep:
        _MOUNTED.append((str(target), str(image_path)))
    return info, i18n.t("msg.mounted")


def umount(mountpoint: str) -> tuple[bool, str]:
    """Unmount if possible; try a lazy unmount as a fallback."""
    if not is_mounted(mountpoint):
        return True, i18n.t("msg.umounted")
    umount_bin = tool_path("umount") or "umount"
    for args in ([umount_bin, mountpoint], [umount_bin, "-l", mountpoint]):
        proc = _run(args, timeout=120)
        if proc.returncode == 0:
            return True, i18n.t("msg.umounted")
    return False, (proc.stderr or "umount failed").strip()


def health(mountpoint: str, probes: list[str] | None = None) -> dict:
    """Cheap sanity check that a mounted tree looks like an Android /data."""
    probes = probes or [
        "system",
        "data",
        "misc",
        "media",
    ]
    out: dict = {"mountpoint": str(mountpoint), "exists": Path(mountpoint).is_dir(), "probes": {}}
    for probe in probes:
        out["probes"][probe] = (Path(mountpoint) / probe).exists()
    out["ok"] = out["exists"] and any(out["probes"].values())
    return out


@atexit.register
def _cleanup() -> None:
    for mountpoint, _image in list(_MOUNTED):
        try:
            umount(mountpoint)
        except (OSError, ValueError):
            # At interpreter shutdown there is nowhere left to report to, and a
            # failed lazy unmount is retried by the next ``umount -l`` run.
            pass
