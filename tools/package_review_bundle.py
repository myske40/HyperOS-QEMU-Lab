#!/usr/bin/env python3
"""Assemble a small, text-only HyperOS QEMU review bundle."""
from __future__ import annotations

import ast
import hashlib
import json
import shutil
import stat
import struct
import sys
import zipfile
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
OUT = PROJECT / "reports" / "hyperos-qemu-review-v9-final.zip"
STAGE = PROJECT / "reports" / "hyperos-qemu-review-v9-final-staging"
sys.path[:0] = [str(PROJECT / "analysis" / "pydeps-lz4"), str(PROJECT / "tools" / "python")]

from asgard.formats.erofs import EROFS
from asgard.formats.ext4 import Ext4
from asgard.formats.images import _open_super_image_reader, _read_lp_metadata, _select_lp_partitions
from asgard.formats.random_access import ImageView, SparseView

ANALYSIS = PROJECT / "analysis"
IMAGES = ANALYSIS / "source-partitions" / "peridot_id_global_images_OS3.0.304.0.WNPIDXM_16.0" / "images"
FIRMWARE = PROJECT / "firmware" / "peridot_id_global_images_OS3.0.304.0.WNPIDXM_20260721.0000.00_16.0_id_6178d39ec1 (1).tgz"
SYSTEM = ANALYSIS / "system_a-from-super.img"
VENDOR = ANALYSIS / "vendor_a-from-super.img"
SUPER = IMAGES / "super.img"

class WindowView:
    def __init__(self, source, offset: int, size: int):
        self.source = source
        self.offset = offset
        self.size = size

    def read_at(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > self.size:
            raise ValueError("read is outside logical partition")
        return self.source.read_at(self.offset + offset, size)

def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def put_file(src: Path, rel: str) -> None:
    dest = STAGE / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dest)

def put_bytes(data: bytes, rel: str) -> None:
    dest = STAGE / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)

def inode_at(fs, path: str):
    inode = fs._inode(fs.root_nid) if isinstance(fs, EROFS) else fs._inode(2)
    for part in path.strip("/").split("/"):
        if part:
            inode = fs._inode(fs._lookup(inode, part))
    return inode

def read_erofs(fs, path: str) -> bytes:
    inode = inode_at(fs, path)
    if not stat.S_ISREG(inode.mode):
        raise ValueError(f"not a regular EROFS file: {path}")
    return b"".join(fs.iter_file(inode))

def list_dir(fs, path: str):
    parent = inode_at(fs, path)
    if not stat.S_ISDIR(parent.mode):
        return []
    result = []
    for block in fs._data(parent):
        if isinstance(fs, EROFS):
            count = struct.unpack_from("<H", block, 8)[0] // 12
            for i in range(count):
                nid, name_start = struct.unpack_from("<QH", block, i * 12)
                name_end = struct.unpack_from("<H", block, (i + 1) * 12 + 8)[0] if i + 1 < count else len(block)
                name = block[name_start:name_end].split(b"\0", 1)[0].decode("utf-8", "replace")
                if name not in (".", ".."):
                    result.append((name, fs._inode(nid)))
        else:
            offset = 0
            while offset + 8 <= len(block):
                ino, rec_len = struct.unpack_from("<IH", block, offset)
                if rec_len < 8 or offset + rec_len > len(block):
                    break
                name_len = block[offset + 6]
                if ino and name_len and offset + 8 + name_len <= offset + rec_len:
                    name = block[offset + 8:offset + 8 + name_len].decode("utf-8", "replace")
                    if name not in (".", ".."):
                        result.append((name, fs._inode(ino)))
                offset += rec_len
    return result

def walk_files(fs: EROFS, path: str):
    for name, node in list_dir(fs, path):
        child = f"{path.rstrip('/')}/{name}"
        if stat.S_ISDIR(node.mode):
            yield from walk_files(fs, child)
        elif stat.S_ISREG(node.mode):
            yield child, node

def copy_erofs(fs: EROFS, src: str, rel: str) -> bool:
    try:
        put_bytes(read_erofs(fs, src), rel)
        return True
    except Exception as exc:
        put_bytes(f"Could not extract {src}: {type(exc).__name__}: {exc}\n".encode(), rel + ".EXTRACTION-ERROR.txt")
        return False

def cpio_entry(path: Path, wanted: str) -> bytes:
    data = path.read_bytes()
    pos = 0
    while pos + 110 <= len(data):
        while pos < len(data) and data[pos] == 0:
            pos += 1
        if pos + 110 > len(data):
            break
        header = data[pos:pos + 110]
        if header[:6] not in (b"070701", b"070702"):
            raise ValueError(f"invalid newc header at {pos}")
        fields = [
            0 if not (field := header[6 + i * 8:14 + i * 8]).strip(b"\0") else int(field, 16)
            for i in range(13)
        ]
        file_size, name_size = fields[6], fields[11]
        name_start = pos + 110
        name_end = name_start + name_size
        name = data[name_start:name_end - 1].decode("utf-8", "replace")
        body_start = (name_end + 3) & ~3
        body_end = body_start + file_size
        if name == wanted:
            return data[body_start:body_end]
        pos = (body_end + 3) & ~3
    raise FileNotFoundError(f"{wanted} not found in {path.name}")

def extract_source_texts() -> list[str]:
    status = []
    with SYSTEM.open("rb") as f:
        system_fs = EROFS(ImageView(f, 0, SYSTEM.stat().st_size))
        for src, rel in (
            ("system/etc/selinux/plat_file_contexts", "extracted/system/etc/selinux/plat_file_contexts"),
            ("system/etc/init/hw/init.rc", "extracted/system/etc/init/hw/init.rc"),
            ("system/etc/init/keystore2.rc", "extracted/system/etc/init/keystore2.rc"),
        ):
            status.append(f"{src}: {'ok' if copy_erofs(system_fs, src, rel) else 'failed'}")

    with VENDOR.open("rb") as f:
        vendor_fs = EROFS(ImageView(f, 0, VENDOR.stat().st_size))
        for src, rel in (
            ("etc/selinux/vendor_file_contexts", "extracted/vendor/etc/selinux/vendor_file_contexts.original"),
            ("etc/fstab.qcom", "extracted/vendor/etc/fstab.qcom.original"),
            ("etc/init/hw/init.target.rc", "extracted/vendor/etc/init/hw/init.target.rc.original"),
        ):
            status.append(f"{src}: {'ok' if copy_erofs(vendor_fs, src, rel) else 'failed'}")
        matches = []
        for src, node in walk_files(vendor_fs, "etc/init"):
            if src.endswith(".rc"):
                try:
                    content = b"".join(vendor_fs.iter_file(node))
                except Exception:
                    continue
                if any(term in content.lower() for term in (b"vendor_init", b"hypsys", b"tombstone")):
                    matches.append((src, content))
        for src, content in matches:
            put_bytes(content, "extracted/vendor/" + src)
        status.append(f"vendor init rc matching vendor_init/hypsys/tombstone: {len(matches)}")
        for src, node in walk_files(vendor_fs, "etc/vintf"):
            if Path(src).name.startswith("manifest") and src.endswith(".xml"):
                put_bytes(b"".join(vendor_fs.iter_file(node)), "extracted/vendor/" + src)
        for src, node in walk_files(vendor_fs, "etc/init"):
            if Path(src).name == "android.hardware.security.keymint-service-qti.rc":
                put_bytes(b"".join(vendor_fs.iter_file(node)), "extracted/vendor/" + src)
        for src, rel, payload in (
            ("etc/fstab.qcom", "extracted/vendor/etc/fstab.qcom.v8-patched", "qemu-vendor-fstab-data-v8.bin"),
            ("etc/selinux/vendor_file_contexts", "extracted/vendor/etc/selinux/vendor_file_contexts.v8-patched", "qemu-vendor-contexts-data-v8.bin"),
            ("etc/init/hw/init.target.rc", "extracted/vendor/etc/init/hw/init.target.rc.v8-patched", "qemu-vendor-init-target-data-v8.bin"),
        ):
            source = ANALYSIS / payload
            if source.exists():
                put_file(source, rel)
                status.append(f"{src} v8 payload: ok")

    with SUPER.open("rb") as f:
        with _open_super_image_reader(f, member_name=SUPER.name, member_size=SUPER.stat().st_size) as reader:
            metadata = _read_lp_metadata(reader)
        partitions = _select_lp_partitions(metadata, ("odm_a",))
        if len(partitions) == 1:
            part = partitions[0]
            extents = metadata.extents[part.first_extent_index:part.first_extent_index + part.num_extents]
            if len(extents) == 1 and extents[0].target_type == 0:
                extent = extents[0]
                try:
                    super_view = SparseView(ImageView(f, 0, SUPER.stat().st_size))
                    odm_view = WindowView(super_view, extent.target_data * 512, extent.num_sectors * 512)
                    try:
                        odm_fs = EROFS(odm_view)
                    except Exception:
                        odm_fs = Ext4(odm_view)
                    for src, node in walk_files(odm_fs, "etc/vintf"):
                        if src.endswith(".xml"):
                            put_bytes(b"".join(odm_fs.iter_file(node)), "extracted/odm/" + src)
                    for src, node in walk_files(odm_fs, "etc/init"):
                        if Path(src).name == "android.hardware.security.keymint3-service.strongbox.nxp.rc":
                            put_bytes(b"".join(odm_fs.iter_file(node)), "extracted/odm/" + src)
                    status.append("odm_a: EROFS XML/init extraction ok")
                except Exception as exc:
                    status.append(f"odm_a: extraction unavailable ({type(exc).__name__}: {exc})")
            else:
                status.append("odm_a: partition is not one linear extent; XML extraction skipped")
        else:
            status.append("odm_a: partition missing/ambiguous")
    return status

def extract_script_fragments() -> None:
    for script_name, version in (
        ("make_qemu_vendor_modprobe_patch.py", "v6"),
        ("make_qemu_vendor_modprobe_patch_v7.py", "v7"),
        ("make_qemu_vendor_modprobe_patch_v8.py", "v8"),
    ):
        script = PROJECT / "tools" / script_name
        put_file(script, f"scripts/{version}/{script_name}")
        tree = ast.parse(script.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and (target.id.endswith("_APPEND") or target.id == "QEMU_SCRIPT"):
                        try:
                            value = ast.literal_eval(node.value)
                        except Exception:
                            continue
                        if isinstance(value, bytes):
                            suffix = ".rc.append" if target.id.endswith("_APPEND") else ".sh"
                            put_bytes(value, f"scripts/{version}/{target.id.lower()}{suffix}")
    for name in ("make_qemu_vendor_barrier_patch.py", "make_qemu_stage2_fstab.py", "run_qemu_trace.ps1"):
        path = PROJECT / "tools" / name
        if path.exists():
            put_file(path, f"scripts/support/{name}")

def main() -> None:
    if STAGE.exists() or OUT.exists():
        raise SystemExit("Review bundle output already exists; refusing to overwrite.")
    STAGE.mkdir(parents=True)
    extraction_status = extract_source_texts()
    for version, stem in (
        ("v6", "qemu-avb-20261105-165007"),
        ("v7", "qemu-avb-20261105-173422"),
        ("v8", "qemu-avb-20261105-174001"),
    ):
        put_file(ANALYSIS / f"{stem}.serial.log", f"logs/{version}-serial-full-raw.log")
        run_json = ANALYSIS / f"{stem}.json"
        if run_json.exists():
            put_file(run_json, f"configs/{version}-qemu-run.json")
        patch_json = ANALYSIS / f"qemu-vendor-modprobe-test-{version}.json"
        if patch_json.exists():
            put_file(patch_json, f"configs/{version}-patch-manifest.json")
    prior = PROJECT / "reports" / "ai-consultation-2026-11-05-v1"
    for name in ("qemu-v6-patch-manifest.json", "qemu-v6-run-config.json"):
        if (prior / name).exists():
            put_file(prior / name, f"configs/prior-{name}")
    extract_script_fragments()
    put_file(ANALYSIS / "kernel.config", "extracted/kernel.config")
    put_file(ANALYSIS / "etc__init__hw__init.target.rc.extracted", "extracted/vendor/etc/init/hw/init.target.rc.base-extraction")
    put_file(ANALYSIS / "etc__init__hw__init.qti.kernel.rc.extracted", "extracted/vendor/etc/init/hw/init.qti.kernel.rc")
    put_bytes(cpio_entry(ANALYSIS / "qemu-virt-stage2-ramdisk.cpio", "first_stage_ramdisk/fstab.qcom"), "extracted/first_stage_ramdisk/fstab.qcom.stage2-original")
    put_bytes(cpio_entry(ANALYSIS / "qemu-virt-vendor-modprobe-test-ramdisk-v8.cpio", "first_stage_ramdisk/fstab.qcom"), "extracted/first_stage_ramdisk/fstab.qcom.v8-patched")
    proposal = (
        "# PROPOSAL ONLY — not injected into any image.\n"
        "# Intended around stock restorecon /data in a valid system-init hook.\n"
        "exec_background - root root -- /system/bin/sh -c \"for i in 1 2 3 4; do sleep 8; /system/bin/logcat -b all -d -t 500 | /system/bin/toybox grep -E 'keystore|Keystore|KeyMint|panic|Abort' > /dev/kmsg; /system/bin/toybox ls -ldZ /data /data/misc/keystore > /dev/kmsg 2>&1; done\"\n"
        "exec - root root -- /system/bin/sh -c \"/system/bin/restorecon -nv /data > /dev/kmsg 2>&1\"\n"
        "exec - root root -- /system/bin/sh -c \"/system/bin/toybox ls -ldZ /data /data/misc/keystore > /dev/kmsg 2>&1\"\n"
        "restorecon /data\n"
        "exec - root root -- /system/bin/sh -c \"/system/bin/toybox ls -ldZ /data /data/misc/keystore > /dev/kmsg 2>&1\"\n"
    )
    put_bytes(proposal.encode(), "scripts/v9/diagnostic-init-snippet.proposal.rc")
    put_bytes(json.dumps({"version":"v9","status":"not-built-not-run","reason":"No v9 patch builder or QEMU run was created. The reviewed snippet is retained as a proposal only; a safe init-domain hook that preserves AVB/dm-verity has not yet been established."}, indent=2).encode() + b"\n", "configs/v9-status.json")
    notes = """# HyperOS QEMU review bundle

## Integrity and scope

Text-only bundle: full unfiltered v6–v8 serial logs, run metadata, patch manifests, patch-builder sources, RC/shell fragments, and selected extracted configuration. It excludes the 8.7 GB firmware archive, super.img, partition images, raw/QCOW2 disks, CPIO binaries, kernel binaries, and Qualcomm/NXP proprietary binaries.

Firmware archive SHA-256 is recorded in SHA256SUMS.txt but the archive is not included. Firmware source and baseline disk remained read-only; the v8 manifest records an unchanged baseline-disk hash.

## Changes and results

- **v6:** /data F2FS formatting/mount reached post-fs-data. keystore2 received SIGABRT five times (PIDs 329, 392, 432, 457, 492), then init's critical-process reboot. Serial does not contain the panic text; DB-vs-KeyMint cause is unknown.
- **v7:** init rejected the private property trigger init.svc.keystore2 as unexported. The added RC actions were not a valid diagnostic run.
- **v8:** setting init.svc_debug.no_fatal.keystore2 was denied from u:r:vendor_init:s0 to default_prop; SELinux stayed enforcing. keystore2 SIGABRTed five times (PIDs 330, 392, 433, 458, 496); init then reported its critical-process threshold. No Zygote, System Server, or sys.boot_completed evidence.

## v8 timing evidence

- keystore2 PID 330 started at 78.756 s.
- /data F2FS mount succeeded at 99.242 s.
- PID 330 received signal 6 at 99.374 s, 132 ms after mount; it had run about 20.6 s before /data was mounted.
- PID 392 started at 100.055 s; /data/misc/keystore was created at 106.413 s; PID 392 received signal 6 at 106.870 s.

These timestamps make /data handling a hypothesis worth checking, not a proven cause. No captured logcat panic distinguishes “Failed to open database” from “Failed to create service ... IKeystoreService”; H1/H2 remains unknown.

## v9 status

No v9 image, patch builder, or QEMU run was created. The proposed snippet is included for reviewer feedback only. It needs a verified init-domain insertion point that does not require changing the verified system image or AVB/dm-verity. The v8 vendor init property write was explicitly denied. No security policy or AVB/dm-verity setting was changed.

Do not replace QTI KeyMint until logcat/tombstone proves a missing KeyMint /default service. AOSP system/keymint libraries alone are not a ready-to-install service.

See EXTRACTION-STATUS.txt for extraction results. Firmware-derived text is copied read-only.
"""
    put_bytes(notes.encode(), "NOTES.md")
    put_bytes(("\n".join(extraction_status) + "\n").encode(), "EXTRACTION-STATUS.txt")
    # Reuse the SHA-256 verified during this session; the 8.7 GB source is not
    # reread just to package its already-recorded digest.
    firmware_hash = "3e3772c6539ba4387d8c97ea9d2e42c28efa5d1b658db0e80e9ae2a9dbf5efdc"
    lines = [f"{firmware_hash}  SOURCE-ONLY  {FIRMWARE.name}"]
    for path in sorted(p for p in STAGE.rglob("*") if p.is_file() and p.name != "SHA256SUMS.txt"):
        lines.append(f"{sha(path)}  {path.relative_to(STAGE).as_posix()}")
    put_bytes(("\n".join(lines) + "\n").encode(), "SHA256SUMS.txt")
    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in sorted(p for p in STAGE.rglob("*") if p.is_file()):
            rel = path.relative_to(STAGE).as_posix()
            if Path(rel).suffix.lower() in {".tgz", ".img", ".qcow2", ".raw", ".cpio", ".bin", ".pyd", ".dll", ".so"}:
                raise ValueError(f"forbidden file in review bundle: {rel}")
            zf.write(path, rel)
    if OUT.stat().st_size >= 25 * 1024 * 1024:
        raise ValueError(f"ZIP exceeds 25 MiB: {OUT.stat().st_size}")
    print(json.dumps({"zip": str(OUT), "bytes": OUT.stat().st_size, "files": sum(1 for p in STAGE.rglob("*") if p.is_file()), "firmware_sha256": firmware_hash}, indent=2))

if __name__ == "__main__":
    main()
