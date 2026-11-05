#!/usr/bin/env python3
"""Build a QEMU-only v10 shell-domain keystore diagnostic adaptation on a disposable QCOW2 overlay.

The firmware, extracted vendor image, and baseline test disk are read-only
inputs. Firmware-derived changes are written only into a new QCOW2 overlay;
the only ramdisk change is a copied first-stage fstab in a new CPIO archive.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools" / "python"))
sys.path.insert(0, str(PROJECT / "tools"))
sys.path.insert(0, str(PROJECT / "analysis" / "pydeps-lz4"))

from asgard.formats.erofs import EROFS  # noqa: E402
from asgard.formats.random_access import ImageView  # noqa: E402
from make_qemu_stage2_fstab import read_newc, write_newc  # noqa: E402
from make_qemu_vendor_barrier_patch import (  # noqa: E402
    SECTOR_SIZE,
    get_super_partition_start,
    get_vendor_extent,
    patch_fstab,
    sha256,
    sha256_bytes,
)


DEFAULT_VENDOR = PROJECT / "analysis" / "vendor_a-from-super.img"
DEFAULT_SUPER = PROJECT / "analysis" / "source-partitions" / "peridot_id_global_images_OS3.0.304.0.WNPIDXM_16.0" / "images" / "super.img"
DEFAULT_BASE_DISK = PROJECT / "analysis" / "hyperos-virt-test-16g-qemu-placeholders.raw"
DEFAULT_RAMDISK = PROJECT / "analysis" / "qemu-virt-stage2-ramdisk.cpio"
DEFAULT_BLOCK = PROJECT / "analysis" / "qemu-vendor-modprobe-test-block-v10-final.bin"
DEFAULT_FSTAB_INODE_BLOCK = PROJECT / "analysis" / "qemu-vendor-fstab-inode-block-v10-final.bin"
DEFAULT_SUPERBLOCK = PROJECT / "analysis" / "qemu-vendor-erofs-superblock-v10-final.bin"
DEFAULT_FSTAB_DATA = PROJECT / "analysis" / "qemu-vendor-fstab-data-v10-final.bin"
DEFAULT_CONTEXT_INODE_BLOCK = PROJECT / "analysis" / "qemu-vendor-contexts-inode-block-v10-final.bin"
DEFAULT_CONTEXT_DATA = PROJECT / "analysis" / "qemu-vendor-contexts-data-v10-final.bin"
DEFAULT_INIT_TARGET_INODE_BLOCK = PROJECT / "analysis" / "qemu-vendor-init-target-inode-block-v10-final.bin"
DEFAULT_INIT_TARGET_DATA = PROJECT / "analysis" / "qemu-vendor-init-target-data-v10-final.bin"
DEFAULT_RAMDISK_OUTPUT = PROJECT / "analysis" / "qemu-virt-vendor-modprobe-test-ramdisk-v10-final.cpio"
DEFAULT_QCOW2 = PROJECT / "analysis" / "hyperos-virt-test-16g-vendor-modprobe-test-v10-final.qcow2"
DEFAULT_MANIFEST = PROJECT / "analysis" / "qemu-vendor-modprobe-test-v10-final.json"
DEFAULT_V8_RAMDISK = PROJECT / "analysis" / "qemu-virt-vendor-modprobe-test-ramdisk-v8.cpio"

TARGET_FILE = "bin/vendor_modprobe.sh"
FSTAB_FILE = "etc/fstab.qcom"
CONTEXTS_FILE = "etc/selinux/vendor_file_contexts"
INIT_TARGET_RC_FILE = "etc/init/hw/init.target.rc"
FSTAB_PATH = "first_stage_ramdisk/fstab.qcom"
QEMU_CONTEXT_RULES = (
    b"/dev/block/nvme0n1p6 u:object_r:metadata_block_device:s0\n"
    b"/dev/block/nvme0n1p11 u:object_r:misc_block_device:s0\n"
    b"/dev/block/nvme0n1p18 u:object_r:userdata_block_device:s0\n"
)
QEMU_SCRIPT = (
    b"#! /vendor/bin/sh\n"
    b"# QEMU has no POCO F6 kernel modules.\n"
    b"setprop vendor.all.modules.ready 1\n"
    b"exit 0\n"
)
QEMU_DIAGNOSTIC_APPEND = (
    b"\n# QEMU-only one-shot keystore diagnostics through the stock shell SELinux domain.\n"
    b"service qemu-keystore-diagnostic /system/bin/sh -c \"echo ===-QEMU-logcat-begin-===; /system/bin/logcat -b all -d -v monotonic -t 1000; echo ===-data-labels-after-stock-restorecon-===; /system/bin/toybox ls -ldZ /data /data/misc/keystore /data/tombstones; echo ===-restorecon-dry-run-===; /system/bin/restorecon -n -v /data; echo ===-tombstones-begin-===; /system/bin/toybox ls -lZ /data/tombstones; for f in /data/tombstones/tombstone_*; do echo ===-$f-===; /system/bin/cat $f; done; echo ===-QEMU-diagnostics-end-===\"\n"
    b"    class core\n"
    b"    user shell\n"
    b"    group shell log readproc\n"
    b"    console\n"
    b"    disabled\n"
    b"    oneshot\n"
    b"    seclabel u:r:shell:s0\n"
    b"\non post-fs-data\n"
    b"    start qemu-keystore-diagnostic\n"
)


class PatchedReader:
    def __init__(self, source, patches: list[tuple[int, bytes]]):
        self.source = source
        self.patches = patches
        self.size = source.size

    def read_at(self, offset: int, size: int) -> bytes:
        raw = bytearray(self.source.read_at(offset, size))
        for patch_offset, replacement in self.patches:
            start = max(offset, patch_offset)
            end = min(offset + size, patch_offset + len(replacement))
            if start < end:
                raw[start - offset : end - offset] = replacement[
                    start - patch_offset : end - patch_offset
                ]
        return bytes(raw)


def patch_qemu_fstab(data: bytes) -> tuple[bytes, list[str]]:
    lines = data.decode("utf-8").splitlines(keepends=True)
    changes: list[str] = []
    data_rows = 0
    for index, original in enumerate(lines):
        fields = original.split()
        if len(fields) < 5 or fields[1] != "/data":
            continue
        if fields[2] not in ("f2fs", "mifs"):
            raise ValueError(f"Unexpected /data filesystem type: {fields[2]}")
        data_rows += 1
        mount_options = fields[3].split(",")
        fs_mgr_options = fields[4].split(",")
        removed_mount = [option for option in mount_options if option == "inlinecrypt"]
        removed_fs_mgr = [
            option
            for option in fs_mgr_options
            if option.startswith(("fileencryption=", "metadata_encryption=", "keydirectory=", "sysfs_path="))
        ]
        mount_options = [option for option in mount_options if option != "inlinecrypt"]
        fs_mgr_options = [
            option
            for option in fs_mgr_options
            if not option.startswith(("fileencryption=", "metadata_encryption=", "keydirectory=", "sysfs_path="))
        ]
        if not any(option == "formattable" for option in fs_mgr_options):
            raise ValueError("/data lost its formattable flag")
        fields[3] = ",".join(mount_options)
        fields[4] = ",".join(fs_mgr_options)
        newline = "\r\n" if original.endswith("\r\n") else "\n" if original.endswith("\n") else ""
        lines[index] = "\t".join(fields) + newline
        changes.append(f"{fields[2]} /data: removed {','.join(removed_mount + removed_fs_mgr)}")
    if data_rows != 2:
        raise ValueError(f"Expected exactly f2fs and mifs /data rows, found {data_rows}")
    result = "".join(lines).encode("utf-8")
    if len(result) > len(data):
        raise ValueError("QEMU fstab rewrite unexpectedly grew")
    note = b"# QEMU test: /data is unencrypted on the virtual disk\n"
    remaining = len(data) - len(result)
    if remaining < len(note):
        raise ValueError("Insufficient fstab space to record the QEMU change")
    result += note + b" " * (remaining - len(note))
    if len(result) != len(data):
        raise AssertionError("QEMU fstab rewrite changed the EROFS inode size")
    for line in result.decode("utf-8").splitlines():
        fields = line.split()
        if len(fields) >= 5 and fields[1] == "/data":
            if "inlinecrypt" in fields[3].split(","):
                raise ValueError("inlinecrypt remained on a QEMU /data row")
            if any(option.startswith(("fileencryption=", "metadata_encryption=", "keydirectory=", "sysfs_path=")) for option in fields[4].split(",")):
                raise ValueError("hardware encryption or UFS path remained on a QEMU /data row")
    return result, changes


def erofs_crc32c(superblock_block: bytes | bytearray) -> int:
    data = bytearray(superblock_block[1024:4096])
    struct.pack_into("<I", data, 4, 0)
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc


def patch_qemu_contexts(data: bytes) -> tuple[bytes, list[str]]:
    rules = QEMU_CONTEXT_RULES.decode("ascii")
    if any(rule.split()[0].encode("ascii") in data for rule in rules.splitlines()):
        raise ValueError("QEMU NVMe file-context rule already exists; refusing duplicate injection")
    if not data.endswith(b"\n"):
        data += b"\n"
    updated = data + QEMU_CONTEXT_RULES
    for line in QEMU_CONTEXT_RULES.decode("ascii").splitlines():
        path, context = line.split()
        if f"{path} {context}".encode("ascii") not in updated:
            raise ValueError(f"QEMU file-context rule did not round-trip: {line}")
    return updated, [line.strip() for line in QEMU_CONTEXT_RULES.decode("ascii").splitlines()]


def patch_qemu_init_target_rc(data: bytes) -> tuple[bytes, list[str]]:
    if not data.endswith(b"\n"):
        raise ValueError("Vendor init.target.rc does not end with a newline")
    if b"QEMU-only one-shot keystore diagnostics" in data:
        raise ValueError("QEMU diagnostic init action already exists; refusing duplicate injection")
    updated = data + QEMU_DIAGNOSTIC_APPEND
    required = (
        b"service qemu-keystore-diagnostic /system/bin/sh -c \"echo ===-QEMU-logcat-begin-===",
        b"/system/bin/logcat -b all -d -v monotonic -t 1000",
        b"/system/bin/restorecon -n -v /data",
        b"    user shell\n",
        b"    seclabel u:r:shell:s0\n",
        b"    start qemu-keystore-diagnostic\n",
    )
    if any(item not in updated for item in required):
        raise ValueError("QEMU shell-domain diagnostic configuration failed its text validation")
    forbidden = (b"init.svc_debug.no_fatal.keystore2", b"restorecon_recursive /data")
    if any(item in updated for item in forbidden):
        raise ValueError("v10 must not contain no-fatal or an extra mutating /data relabel")
    return updated, [
        "Replace v9 init-domain logcat execution with one-shot logcat and tombstone capture in the stock shell SELinux domain, routed to the existing serial console.",
        "Record post-stock-restorecon /data labels and run restorecon in dry-run mode only; no SELinux, AVB, dm-verity, or policy changes.",
    ]


def parse_qemu_io_hexdump(output: str, expected_start: int, expected_size: int) -> bytes:
    chunks: dict[int, bytes] = {}
    row = re.compile(r"^([0-9a-fA-F]+):  ((?:[0-9a-fA-F]{2} ){0,15}[0-9a-fA-F]{2})  ")
    for line in output.splitlines():
        match = row.match(line)
        if match:
            offset = int(match.group(1), 16)
            chunks[offset] = bytes.fromhex(match.group(2))
    result = bytearray()
    cursor = expected_start
    while cursor < expected_start + expected_size:
        chunk = chunks.get(cursor)
        if chunk is None:
            raise ValueError(f"qemu-io readback omitted offset 0x{cursor:x}")
        result.extend(chunk)
        cursor += len(chunk)
    return bytes(result[:expected_size])


def write_exact_qcow2_block(qemu_io: Path, qcow2: Path, block_file: Path, offset: int, data: bytes) -> None:
    """Write exact bytes despite qemu-io opening pattern files in text mode on Windows.

    Windows text mode treats 0x1a as EOF and may translate CRLF. Split those
    bytes out and write them with -P; write all remaining safe spans from files.
    """
    commands: list[str] = []
    with tempfile.TemporaryDirectory(prefix="qemu-inline-patch-", dir=str(block_file.parent)) as temp_dir:
        temp_path = Path(temp_dir)
        cursor = 0
        part = 0
        while cursor < len(data):
            if data[cursor] in (0x0D, 0x1A):
                commands.append(f"write -q -P 0x{data[cursor]:02x} {offset + cursor} 1")
                cursor += 1
                continue
            end = cursor + 1
            while end < len(data) and data[end] not in (0x0D, 0x1A):
                end += 1
            chunk_file = temp_path / f"chunk-{part:03d}.bin"
            chunk_file.write_bytes(data[cursor:end])
            source_path = str(chunk_file.resolve())
            if any(character.isspace() for character in source_path):
                raise ValueError("qemu-io source-file paths cannot contain spaces in this runner")
            commands.append(f"write -q -s {source_path} {offset + cursor} {end - cursor}")
            cursor = end
            part += 1

        command_args: list[str] = [str(qemu_io), "-f", "qcow2"]
        for command in commands:
            command_args.extend(("-c", command))
        command_args.append(str(qcow2.resolve()))
        subprocess.run(command_args, check=True, capture_output=True, text=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vendor", type=Path, default=DEFAULT_VENDOR)
    parser.add_argument("--super", type=Path, default=DEFAULT_SUPER)
    parser.add_argument("--base-disk", type=Path, default=DEFAULT_BASE_DISK)
    parser.add_argument("--ramdisk", type=Path, default=DEFAULT_RAMDISK)
    parser.add_argument("--reference-v8-ramdisk", type=Path, default=DEFAULT_V8_RAMDISK)
    parser.add_argument("--block-output", type=Path, default=DEFAULT_BLOCK)
    parser.add_argument("--fstab-inode-block-output", type=Path, default=DEFAULT_FSTAB_INODE_BLOCK)
    parser.add_argument("--superblock-output", type=Path, default=DEFAULT_SUPERBLOCK)
    parser.add_argument("--fstab-data-output", type=Path, default=DEFAULT_FSTAB_DATA)
    parser.add_argument("--contexts-inode-block-output", type=Path, default=DEFAULT_CONTEXT_INODE_BLOCK)
    parser.add_argument("--contexts-data-output", type=Path, default=DEFAULT_CONTEXT_DATA)
    parser.add_argument("--init-target-inode-block-output", type=Path, default=DEFAULT_INIT_TARGET_INODE_BLOCK)
    parser.add_argument("--init-target-data-output", type=Path, default=DEFAULT_INIT_TARGET_DATA)
    parser.add_argument("--ramdisk-output", type=Path, default=DEFAULT_RAMDISK_OUTPUT)
    parser.add_argument("--qcow2-output", type=Path, default=DEFAULT_QCOW2)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    args = parser.parse_args()

    inputs = (args.vendor, args.super, args.base_disk, args.ramdisk, args.reference_v8_ramdisk)
    for path in inputs:
        if not path.is_file():
            raise FileNotFoundError(path)
    outputs = (
        args.block_output,
        args.fstab_inode_block_output,
        args.superblock_output,
        args.fstab_data_output,
        args.contexts_inode_block_output,
        args.contexts_data_output,
        args.init_target_inode_block_output,
        args.init_target_data_output,
        args.ramdisk_output,
        args.qcow2_output,
        args.manifest,
    )
    for path in outputs:
        if path.exists():
            raise FileExistsError(f"Refusing to overwrite derived output: {path}")

    with args.vendor.open("rb") as stream:
        source = ImageView(stream, 0, args.vendor.stat().st_size)
        fs = EROFS(source)
        block_size = fs.block_size

        modprobe_inode = fs.find(TARGET_FILE)
        original_script = b"".join(fs.iter_file(modprobe_inode))
        if modprobe_inode.layout != 2:
            raise ValueError(f"Expected inline plain EROFS data (layout=2), got {modprobe_inode.layout}")
        if modprobe_inode.size != len(original_script) or len(QEMU_SCRIPT) > modprobe_inode.size:
            raise ValueError("QEMU replacement does not fit vendor_modprobe.sh")
        if b"setprop vendor.all.modules.ready 1" not in original_script:
            raise ValueError("Target script no longer sets the expected readiness property")
        inline_offset = modprobe_inode.position + modprobe_inode.inode_size + modprobe_inode.xattr_size
        modprobe_block_offset = (modprobe_inode.position // block_size) * block_size
        inline_in_block = inline_offset - modprobe_block_offset
        if inline_in_block < 0 or inline_in_block + modprobe_inode.size > block_size:
            raise ValueError("Target inline file crosses its EROFS metadata block")
        replacement_script = QEMU_SCRIPT + b" " * (modprobe_inode.size - len(QEMU_SCRIPT))
        old_modprobe_block = source.read_at(modprobe_block_offset, block_size)
        modprobe_block = bytearray(old_modprobe_block)
        modprobe_block[inline_in_block : inline_in_block + modprobe_inode.size] = replacement_script
        modprobe_block = bytes(modprobe_block)

        fstab_inode = fs.find(FSTAB_FILE)
        if fstab_inode.layout != 3:
            raise ValueError(f"Expected compressed EROFS fstab layout=3, got {fstab_inode.layout}")
        original_vendor_fstab = b"".join(fs.iter_file(fstab_inode))
        vendor_fstab, fstab_changes = patch_qemu_fstab(original_vendor_fstab)
        if len(vendor_fstab) != fstab_inode.size:
            raise ValueError("QEMU fstab rewrite changed the EROFS inode size")

        contexts_inode = fs.find(CONTEXTS_FILE)
        if contexts_inode.layout != 3 or contexts_inode.inode_size != 32:
            raise ValueError("Expected compact compressed EROFS vendor_file_contexts")
        original_contexts = b"".join(fs.iter_file(contexts_inode))
        contexts_data_raw, qemu_context_rules = patch_qemu_contexts(original_contexts)
        contexts_data_blocks = (len(contexts_data_raw) + block_size - 1) // block_size

        init_target_inode = fs.find(INIT_TARGET_RC_FILE)
        if init_target_inode.layout != 3 or init_target_inode.inode_size != 32:
            raise ValueError("Expected compact compressed EROFS vendor init.target.rc")
        original_init_target_rc = b"".join(fs.iter_file(init_target_inode))
        init_target_rc, qemu_init_actions = patch_qemu_init_target_rc(original_init_target_rc)
        init_target_data_blocks = (len(init_target_rc) + block_size - 1) // block_size

        superblock_block = bytearray(source.read_at(0, block_size))
        old_superblock_block = bytes(superblock_block)
        if struct.unpack_from("<I", superblock_block, 1024)[0] != 0xE0F5E1E2:
            raise ValueError("Vendor EROFS superblock magic is invalid")
        old_blocks = struct.unpack_from("<I", superblock_block, 1024 + 36)[0]
        compat_features = struct.unpack_from("<I", superblock_block, 1024 + 8)[0]
        old_crc = struct.unpack_from("<I", superblock_block, 1024 + 4)[0]
        if not (compat_features & 1):
            raise ValueError("EROFS checksum feature is not enabled; refusing superblock edit")
        if erofs_crc32c(superblock_block) != old_crc:
            raise ValueError("Original EROFS superblock CRC32C does not validate")

        fstab_data_blocks = (len(vendor_fstab) + block_size - 1) // block_size
        required_blocks = fstab_data_blocks + contexts_data_blocks + init_target_data_blocks
        partition_blocks = source.size // block_size
        if source.size % block_size:
            raise ValueError("Extracted vendor partition is not block aligned")
        run_start = None
        run_length = 0
        for block_number in range(old_blocks, partition_blocks):
            candidate = source.read_at(block_number * block_size, block_size)
            if not any(candidate):
                run_start = block_number if run_start is None else run_start
                run_length += 1
                if run_length >= required_blocks:
                    break
            else:
                run_start = None
                run_length = 0
        if run_start is None or run_length < required_blocks:
            raise ValueError(f"No zero-filled run of {required_blocks} blocks exists after EROFS blocks_count")
        fstab_start_block = run_start
        fstab_data = vendor_fstab + bytes(fstab_data_blocks * block_size - len(vendor_fstab))
        contexts_start_block = fstab_start_block + fstab_data_blocks
        contexts_data = contexts_data_raw + bytes(contexts_data_blocks * block_size - len(contexts_data_raw))
        init_target_start_block = contexts_start_block + contexts_data_blocks
        init_target_data = init_target_rc + bytes(init_target_data_blocks * block_size - len(init_target_rc))

        fstab_inode_block_offset = (fstab_inode.position // block_size) * block_size
        fstab_inode_block = bytearray(source.read_at(fstab_inode_block_offset, block_size))
        old_fstab_inode_block = bytes(fstab_inode_block)
        inode_in_block = fstab_inode.position - fstab_inode_block_offset
        old_format = struct.unpack_from("<H", fstab_inode_block, inode_in_block)[0]
        if ((old_format >> 1) & 7) != 3 or fstab_inode.inode_size != 32:
            raise ValueError("Unexpected compressed fstab inode encoding")
        new_format = old_format & ~0x000E  # EROFS layout 0: uncompressed flat data.
        struct.pack_into("<H", fstab_inode_block, inode_in_block, new_format)
        struct.pack_into("<I", fstab_inode_block, inode_in_block + 16, fstab_start_block)
        fstab_inode_block = bytes(fstab_inode_block)

        contexts_inode_block_offset = (contexts_inode.position // block_size) * block_size
        contexts_inode_block = bytearray(source.read_at(contexts_inode_block_offset, block_size))
        old_contexts_inode_block = bytes(contexts_inode_block)
        contexts_inode_in_block = contexts_inode.position - contexts_inode_block_offset
        contexts_format = struct.unpack_from("<H", contexts_inode_block, contexts_inode_in_block)[0]
        if ((contexts_format >> 1) & 7) != 3:
            raise ValueError("vendor_file_contexts is no longer a compressed EROFS inode")
        struct.pack_into("<H", contexts_inode_block, contexts_inode_in_block, contexts_format & ~0x000E)
        struct.pack_into("<I", contexts_inode_block, contexts_inode_in_block + 8, len(contexts_data_raw))
        struct.pack_into("<I", contexts_inode_block, contexts_inode_in_block + 16, contexts_start_block)
        contexts_inode_block = bytes(contexts_inode_block)

        init_target_inode_block_offset = (init_target_inode.position // block_size) * block_size
        init_target_inode_block = bytearray(source.read_at(init_target_inode_block_offset, block_size))
        old_init_target_inode_block = bytes(init_target_inode_block)
        init_target_inode_in_block = init_target_inode.position - init_target_inode_block_offset
        init_target_format = struct.unpack_from("<H", init_target_inode_block, init_target_inode_in_block)[0]
        if ((init_target_format >> 1) & 7) != 3:
            raise ValueError("vendor init.target.rc is no longer a compressed EROFS inode")
        struct.pack_into("<H", init_target_inode_block, init_target_inode_in_block, init_target_format & ~0x000E)
        struct.pack_into("<I", init_target_inode_block, init_target_inode_in_block + 8, len(init_target_rc))
        struct.pack_into("<I", init_target_inode_block, init_target_inode_in_block + 16, init_target_start_block)
        init_target_inode_block = bytes(init_target_inode_block)

        metadata_offsets = {fstab_inode_block_offset, contexts_inode_block_offset, init_target_inode_block_offset}
        if len(metadata_offsets) != 3:
            raise ValueError("QEMU fstab, file_contexts, and init.target.rc share an EROFS metadata block")

        new_blocks = max(old_blocks, init_target_start_block + init_target_data_blocks)
        struct.pack_into("<I", superblock_block, 1024 + 36, new_blocks)
        struct.pack_into("<I", superblock_block, 1024 + 4, 0)
        new_crc = erofs_crc32c(superblock_block)
        struct.pack_into("<I", superblock_block, 1024 + 4, new_crc)
        if erofs_crc32c(superblock_block) != new_crc:
            raise ValueError("Updated EROFS superblock CRC32C does not validate")
        superblock_block = bytes(superblock_block)

        patches = [
            (modprobe_block_offset, modprobe_block),
            (fstab_inode_block_offset, fstab_inode_block),
            (contexts_inode_block_offset, contexts_inode_block),
            (init_target_inode_block_offset, init_target_inode_block),
            (fstab_start_block * block_size, fstab_data),
            (contexts_start_block * block_size, contexts_data),
            (init_target_start_block * block_size, init_target_data),
            (0, superblock_block),
        ]
        patched_fs = EROFS(PatchedReader(source, patches))
        verified_script = b"".join(patched_fs.iter_file(patched_fs.find(TARGET_FILE)))
        verified_fstab_inode = patched_fs.find(FSTAB_FILE)
        verified_vendor_fstab = b"".join(patched_fs.iter_file(verified_fstab_inode))
        verified_contexts_inode = patched_fs.find(CONTEXTS_FILE)
        verified_contexts = b"".join(patched_fs.iter_file(verified_contexts_inode))
        verified_init_target_inode = patched_fs.find(INIT_TARGET_RC_FILE)
        verified_init_target_rc = b"".join(patched_fs.iter_file(verified_init_target_inode))
        if verified_script != replacement_script:
            raise ValueError("Patched vendor_modprobe.sh failed EROFS readback validation")
        if verified_vendor_fstab != vendor_fstab:
            raise ValueError("Patched vendor fstab failed EROFS readback validation")
        if verified_fstab_inode.layout != 0 or verified_fstab_inode.start_block != fstab_start_block:
            raise ValueError("Patched vendor fstab inode does not point to the new flat data")
        if verified_contexts != contexts_data_raw:
            raise ValueError("Patched vendor file_contexts failed EROFS readback validation")
        if verified_contexts_inode.layout != 0 or verified_contexts_inode.start_block != contexts_start_block:
            raise ValueError("Patched vendor_file_contexts inode does not point to its new flat data")
        if verified_init_target_rc != init_target_rc:
            raise ValueError("Patched vendor init.target.rc failed EROFS readback validation")
        if verified_init_target_inode.layout != 0 or verified_init_target_inode.start_block != init_target_start_block:
            raise ValueError("Patched vendor init.target.rc inode does not point to its new flat data")

    entries = read_newc(args.ramdisk.read_bytes())
    matches = [(index, values, payload) for index, (name, values, payload) in enumerate(entries) if name == FSTAB_PATH]
    if len(matches) != 1:
        raise ValueError(f"Expected one {FSTAB_PATH} in ramdisk; found {len(matches)}")
    reference_matches = [
        (values, payload)
        for name, values, payload in read_newc(args.reference_v8_ramdisk.read_bytes())
        if name == FSTAB_PATH
    ]
    if len(reference_matches) != 1:
        raise ValueError(f"Expected one {FSTAB_PATH} in v8 reference ramdisk; found {len(reference_matches)}")
    reference_fstab_mtime = reference_matches[0][0][5]
    fstab_index, values, old_stage1_fstab = matches[0]
    stage1_fstab, old_vendor_row, new_vendor_row, avb_rows_before = patch_fstab(old_stage1_fstab)
    updated = list(entries)
    metadata = list(values)
    # Match v8's generated CPIO metadata so the v9-v8 ramdisk diff is empty;
    # the only intentional v9 delta is the vendor init.target.rc diagnostic.
    metadata[5] = reference_fstab_mtime
    metadata[6] = len(stage1_fstab)
    name, _, _ = updated[fstab_index]
    updated[fstab_index] = (name, tuple(metadata), stage1_fstab)
    ramdisk_data = write_newc(updated)
    reread = {name: payload for name, _values, payload in read_newc(ramdisk_data)}
    if reread.get(FSTAB_PATH) != stage1_fstab:
        raise ValueError("Modified ramdisk fstab failed CPIO round-trip validation")
    if stage1_fstab.count(b"avb=vbmeta") != old_stage1_fstab.count(b"avb=vbmeta") - 1:
        raise ValueError("First-stage fstab change did not remove only vendor AVB")

    super_start, super_gpt = get_super_partition_start(args.base_disk)
    extent = get_vendor_extent(args.super, args.vendor)
    vendor_disk_start = super_start + extent["offset"]
    absolute_offsets = {
        "vendor_modprobe_block": vendor_disk_start + modprobe_block_offset,
        "vendor_fstab_inode_block": vendor_disk_start + fstab_inode_block_offset,
        "vendor_contexts_inode_block": vendor_disk_start + contexts_inode_block_offset,
        "vendor_init_target_inode_block": vendor_disk_start + init_target_inode_block_offset,
        "vendor_erofs_superblock": vendor_disk_start,
        "vendor_fstab_data": vendor_disk_start + fstab_start_block * block_size,
        "vendor_contexts_data": vendor_disk_start + contexts_start_block * block_size,
        "vendor_init_target_data": vendor_disk_start + init_target_start_block * block_size,
    }
    baseline_expected = {
        "vendor_modprobe_block": old_modprobe_block,
        "vendor_fstab_inode_block": old_fstab_inode_block,
        "vendor_contexts_inode_block": old_contexts_inode_block,
        "vendor_init_target_inode_block": old_init_target_inode_block,
        "vendor_erofs_superblock": old_superblock_block,
        "vendor_fstab_data": bytes(len(fstab_data)),
        "vendor_contexts_data": bytes(len(contexts_data)),
        "vendor_init_target_data": bytes(len(init_target_data)),
    }
    with args.base_disk.open("rb") as disk:
        for name, offset in absolute_offsets.items():
            disk.seek(offset)
            actual = disk.read(len(baseline_expected[name]))
            if actual != baseline_expected[name]:
                raise ValueError(f"Baseline test disk {name} does not match the expected original bytes")
    base_disk_sha_before = sha256(args.base_disk)

    args.block_output.parent.mkdir(parents=True, exist_ok=True)
    for path in (
        args.fstab_inode_block_output,
        args.superblock_output,
        args.fstab_data_output,
        args.contexts_inode_block_output,
        args.contexts_data_output,
        args.init_target_inode_block_output,
        args.init_target_data_output,
        args.ramdisk_output,
        args.qcow2_output,
        args.manifest,
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
    args.block_output.write_bytes(modprobe_block)
    args.fstab_inode_block_output.write_bytes(fstab_inode_block)
    args.superblock_output.write_bytes(superblock_block)
    args.fstab_data_output.write_bytes(fstab_data)
    args.contexts_inode_block_output.write_bytes(contexts_inode_block)
    args.contexts_data_output.write_bytes(contexts_data)
    args.init_target_inode_block_output.write_bytes(init_target_inode_block)
    args.init_target_data_output.write_bytes(init_target_data)
    args.ramdisk_output.write_bytes(ramdisk_data)

    qemu_img = PROJECT / "tools" / "qemu" / "qemu-img.exe"
    qemu_io = PROJECT / "tools" / "qemu" / "qemu-io.exe"
    subprocess.run(
        [str(qemu_img), "create", "-q", "-f", "qcow2", "-F", "raw", "-b", str(args.base_disk.resolve()), str(args.qcow2_output.resolve())],
        check=True,
    )
    payloads = [
        ("vendor_modprobe_block", args.block_output, modprobe_block),
        ("vendor_fstab_inode_block", args.fstab_inode_block_output, fstab_inode_block),
        ("vendor_contexts_inode_block", args.contexts_inode_block_output, contexts_inode_block),
        ("vendor_init_target_inode_block", args.init_target_inode_block_output, init_target_inode_block),
        ("vendor_erofs_superblock", args.superblock_output, superblock_block),
        ("vendor_fstab_data", args.fstab_data_output, fstab_data),
        ("vendor_contexts_data", args.contexts_data_output, contexts_data),
        ("vendor_init_target_data", args.init_target_data_output, init_target_data),
    ]
    for name, payload_path, payload in payloads:
        offset = absolute_offsets[name]
        write_exact_qcow2_block(qemu_io, args.qcow2_output, payload_path, offset, payload)
        readback = subprocess.run(
            [str(qemu_io), "-f", "qcow2", "-c", f"read -v {offset} {len(payload)}", str(args.qcow2_output.resolve())],
            check=True,
            capture_output=True,
            text=True,
        )
        if parse_qemu_io_hexdump(readback.stdout, offset, len(payload)) != payload:
            raise ValueError(f"QEMU QCOW2 readback differs for {name}")
    base_disk_sha_after = sha256(args.base_disk)
    if base_disk_sha_after != base_disk_sha_before:
        raise ValueError("Baseline raw disk hash changed while creating the derived QCOW2 overlay")

    manifest = {
        "created_at_epoch": int(time.time()),
        "version": "v10",
        "changes_from_v8": ["Replace the v9 init-domain logcat hook with a one-shot diagnostic service explicitly using the already-defined shell SELinux domain; dump logcat and tombstones to serial, report post-restorecon labels, and run restorecon dry-run only."],
        "purpose": "QEMU-only diagnostic based on the v8 baseline; collect keystore2 panic evidence through stock shell-domain permissions while vendor AVB remains exempted only in this test ramdisk",
        "hardware_for_next_run": "qcom",
        "fstab_suffix_for_next_run": "qcom",
        "source_vendor_image": str(args.vendor.resolve()),
        "source_vendor_sha256": sha256(args.vendor),
        "source_super_image": str(args.super.resolve()),
        "source_super_sha256": sha256(args.super),
        "source_base_disk": str(args.base_disk.resolve()),
        "source_base_disk_sha256": base_disk_sha_before,
        "source_base_disk_sha256_after": base_disk_sha_after,
        "source_ramdisk": str(args.ramdisk.resolve()),
        "source_ramdisk_sha256": sha256(args.ramdisk),
        "reference_v8_ramdisk": str(args.reference_v8_ramdisk.resolve()),
        "reference_v8_ramdisk_sha256": sha256(args.reference_v8_ramdisk),
        "first_stage_fstab_mtime_matches_v8": True,
        "vendor_partition": "vendor_a",
        "vendor_gpt_start": super_start,
        "super_gpt_partition": super_gpt,
        "vendor_super_extent_offset": extent["offset"],
        "vendor_super_extent_size": extent["size"],
        "target_file": "/vendor/bin/vendor_modprobe.sh",
        "target_file_original_sha256": sha256_bytes(original_script),
        "target_file_modified_sha256": sha256_bytes(replacement_script),
        "target_file_layout": "inline plain EROFS inode data; no LZ4 recompression",
        "target_file_original_size": len(original_script),
        "target_file_modified_size": len(replacement_script),
        "target_file_replacement": QEMU_SCRIPT.decode("ascii"),
        "target_file_inode_position": modprobe_inode.position,
        "target_file_inline_data_offset": inline_offset,
        "target_file_metadata_block_offset": modprobe_block_offset,
        "ero_fs_block_size": block_size,
        "vendor_fstab_file": "/vendor/etc/fstab.qcom",
        "vendor_fstab_original_sha256": sha256_bytes(original_vendor_fstab),
        "vendor_fstab_modified_sha256": sha256_bytes(vendor_fstab),
        "vendor_fstab_original_size": len(original_vendor_fstab),
        "vendor_fstab_modified_size": len(vendor_fstab),
        "vendor_fstab_changes": fstab_changes,
        "vendor_fstab_original_layout": fstab_inode.layout,
        "vendor_fstab_modified_layout": 0,
        "vendor_fstab_inode_position": fstab_inode.position,
        "vendor_fstab_inode_metadata_block_offset": fstab_inode_block_offset,
        "vendor_fstab_data_start_block": fstab_start_block,
        "vendor_fstab_data_block_count": fstab_data_blocks,
        "vendor_fstab_data_sha256": sha256_bytes(fstab_data),
        "vendor_contexts_file": "/vendor/etc/selinux/vendor_file_contexts",
        "vendor_contexts_original_sha256": sha256_bytes(original_contexts),
        "vendor_contexts_modified_sha256": sha256_bytes(contexts_data_raw),
        "vendor_contexts_original_size": len(original_contexts),
        "vendor_contexts_modified_size": len(contexts_data_raw),
        "vendor_contexts_original_ends_newline": original_contexts.endswith(b"\n"),
        "vendor_contexts_added_rules": qemu_context_rules,
        "vendor_contexts_inode_position": contexts_inode.position,
        "vendor_contexts_inode_metadata_block_offset": contexts_inode_block_offset,
        "vendor_contexts_data_start_block": contexts_start_block,
        "vendor_contexts_data_block_count": contexts_data_blocks,
        "vendor_contexts_zero_run_was_verified": True,
        "vendor_fstab_zero_run_was_verified": True,
        "vendor_init_target_rc_file": "/vendor/etc/init/hw/init.target.rc",
        "vendor_init_target_rc_original_sha256": sha256_bytes(original_init_target_rc),
        "vendor_init_target_rc_modified_sha256": sha256_bytes(init_target_rc),
        "vendor_init_target_rc_original_size": len(original_init_target_rc),
        "vendor_init_target_rc_modified_size": len(init_target_rc),
        "vendor_init_target_rc_original_layout": init_target_inode.layout,
        "vendor_init_target_rc_modified_layout": 0,
        "vendor_init_target_rc_inode_position": init_target_inode.position,
        "vendor_init_target_rc_inode_metadata_block_offset": init_target_inode_block_offset,
        "vendor_init_target_rc_data_start_block": init_target_start_block,
        "vendor_init_target_rc_data_block_count": init_target_data_blocks,
        "vendor_init_target_rc_qemu_actions": qemu_init_actions,
        "vendor_init_target_rc_zero_run_was_verified": True,
        "erofs_blocks_before": old_blocks,
        "erofs_blocks_after": new_blocks,
        "erofs_superblock_crc32c_before": f"0x{old_crc:08x}",
        "erofs_superblock_crc32c_after": f"0x{new_crc:08x}",
        "disk_patch_offsets": absolute_offsets,
        "patch_payload_sha256": {name: sha256_bytes(payload) for name, _path, payload in payloads},
        "patch_block_file": str(args.block_output.resolve()),
        "first_stage_fstab": FSTAB_PATH,
        "vendor_fstab_row_before": old_vendor_row,
        "vendor_fstab_row_after": new_vendor_row,
        "first_stage_avb_rows_before": avb_rows_before,
        "first_stage_avb_rows_after": avb_rows_before - 1,
        "ramdisk_output": str(args.ramdisk_output.resolve()),
        "ramdisk_output_sha256": sha256(args.ramdisk_output),
        "fstab_inode_block_file": str(args.fstab_inode_block_output.resolve()),
        "contexts_inode_block_file": str(args.contexts_inode_block_output.resolve()),
        "contexts_data_file": str(args.contexts_data_output.resolve()),
        "init_target_inode_block_file": str(args.init_target_inode_block_output.resolve()),
        "init_target_data_file": str(args.init_target_data_output.resolve()),
        "superblock_file": str(args.superblock_output.resolve()),
        "fstab_data_file": str(args.fstab_data_output.resolve()),
        "qcow2_output": str(args.qcow2_output.resolve()),
        "qcow2_output_size": args.qcow2_output.stat().st_size,
        "base_disk_modified": False,
        "source_firmware_modified": False,
        "validation": [
            "Replacement retains the original inline EROFS file size and metadata layout.",
            "EROFS reader round-trip returns the exact QEMU vendor_modprobe.sh and modified vendor fstab.",
            "EROFS reader round-trip returns the exact vendor_file_contexts with three QEMU NVMe partition labels.",
            "EROFS reader round-trip returns the exact QEMU init.target.rc shell-domain diagnostics and dry-run label inspection.",
            "Only a verified zero-filled run in the vendor partition tail is allocated for new fstab, context, and init data.",
            "EROFS superblock block count is updated and its CRC32C validates.",
            "First-stage fstab removes AVB only from /vendor; all other AVB entries remain.",
            "Baseline disk patch locations match source bytes, including a zero-filled new fstab data run.",
            "Each QCOW2 patch payload was read back byte-for-byte with qemu-io.",
            "The source vendor image, source super image, and baseline raw disk were opened read-only.",
        ],
    }
    args.manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
