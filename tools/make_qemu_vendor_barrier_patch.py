#!/usr/bin/env python3
"""Create a narrowly scoped QEMU-only vendor/init patch and ramdisk copy.

The source firmware and source test disk are read-only inputs. The vendor EROFS
change replaces one compressed LZ4 data cluster in a derived qcow2 overlay;
the first-stage fstab in a derived ramdisk bypasses AVB for vendor_a only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
import time
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools" / "python"))
sys.path.insert(0, str(PROJECT / "tools"))

from asgard.formats.erofs import EROFS  # noqa: E402
from asgard.formats.images import _open_super_image_reader, _read_lp_metadata, _select_lp_partitions  # noqa: E402
from asgard.formats.random_access import ImageView  # noqa: E402
from make_qemu_stage2_fstab import read_newc, sha256, write_newc  # noqa: E402

import lz4.block  # noqa: E402


DEFAULT_VENDOR = PROJECT / "analysis" / "vendor_a-from-super.img"
DEFAULT_SUPER = (
    PROJECT
    / "analysis"
    / "source-partitions"
    / "peridot_id_global_images_OS3.0.304.0.WNPIDXM_16.0"
    / "images"
    / "super.img"
)
DEFAULT_BASE_DISK = PROJECT / "analysis" / "hyperos-virt-test-16g-qemu-placeholders.raw"
DEFAULT_RAMDISK = PROJECT / "analysis" / "qemu-virt-stage2-ramdisk.cpio"
DEFAULT_BLOCK = PROJECT / "analysis" / "qemu-vendor-init-patch-block.bin"
DEFAULT_OUT_RAMDISK = PROJECT / "analysis" / "qemu-virt-vendor-barrier-ramdisk.cpio"
DEFAULT_MANIFEST = PROJECT / "analysis" / "qemu-vendor-barrier-patch.json"
TARGET_RC = "etc/init/hw/init.qti.kernel.rc"
TARGET_LINE = b"    wait_for_prop vendor.all.modules.ready 1"
COMMENT = b"    # QEMU skips missing module wait"
FSTAB_PATH = "first_stage_ramdisk/fstab.qcom"
SECTOR_SIZE = 512


class PatchedReader:
    def __init__(self, source, offset: int, replacement: bytes):
        self.source = source
        self.offset = offset
        self.replacement = replacement
        self.size = source.size

    def read_at(self, offset: int, size: int) -> bytes:
        raw = bytearray(self.source.read_at(offset, size))
        start = max(offset, self.offset)
        end = min(offset + size, self.offset + len(self.replacement))
        if start < end:
            raw[start - offset : end - offset] = self.replacement[
                start - self.offset : end - self.offset
            ]
        return bytes(raw)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def get_super_partition_start(disk_path: Path) -> tuple[int, dict[str, int]]:
    with disk_path.open("rb") as disk:
        disk.seek(SECTOR_SIZE)
        header = disk.read(SECTOR_SIZE)
        if header[:8] != b"EFI PART":
            raise ValueError("Base test disk has no valid primary GPT header")
        entries_lba = struct.unpack_from("<Q", header, 72)[0]
        entries_count = struct.unpack_from("<I", header, 80)[0]
        entry_size = struct.unpack_from("<I", header, 84)[0]
        if entry_size < 128 or entries_count > 4096:
            raise ValueError("Base test disk has unexpected GPT geometry")
        disk.seek(entries_lba * SECTOR_SIZE)
        entries = disk.read(entries_count * entry_size)
        matches: list[dict[str, int]] = []
        for index in range(entries_count):
            entry = entries[index * entry_size : (index + 1) * entry_size]
            if not any(entry[:16]):
                continue
            name = entry[56:128].decode("utf-16le").split("\0", 1)[0]
            if name == "super":
                first_lba, last_lba = struct.unpack_from("<QQ", entry, 32)
                matches.append({"start": first_lba * SECTOR_SIZE, "size": (last_lba - first_lba + 1) * SECTOR_SIZE})
    if len(matches) != 1:
        raise ValueError(f"Expected one GPT super partition, found {len(matches)}")
    return matches[0]["start"], matches[0]


def get_vendor_extent(super_path: Path, vendor_path: Path) -> dict[str, int]:
    with super_path.open("rb") as stream:
        with _open_super_image_reader(stream, member_name=super_path.name, member_size=super_path.stat().st_size) as reader:
            metadata = _read_lp_metadata(reader)
            partitions = _select_lp_partitions(metadata, ("vendor_a",))
            if len(partitions) != 1:
                raise ValueError("Could not uniquely identify vendor_a in super metadata")
            partition = partitions[0]
            extents = metadata.extents[partition.first_extent_index : partition.first_extent_index + partition.num_extents]
            if len(extents) != 1:
                raise ValueError(f"vendor_a uses {len(extents)} extents; this patcher requires one linear extent")
            extent = extents[0]
            if extent.target_type != 0 or extent.target_source != 0:
                raise ValueError("vendor_a is not a single linear extent on super device 0")
            size = extent.num_sectors * SECTOR_SIZE
            if vendor_path.stat().st_size != size:
                raise ValueError(f"vendor_a image size mismatch: LP metadata={size}, extracted={vendor_path.stat().st_size}")
            return {"offset": extent.target_data * SECTOR_SIZE, "size": size, "target_data_sectors": extent.target_data}


def patch_fstab(data: bytes) -> tuple[bytes, str, str, int]:
    lines = data.decode("utf-8").splitlines(keepends=True)
    found: list[tuple[int, list[str], str]] = []
    avb_rows_before = 0
    for index, original in enumerate(lines):
        fields = original.split()
        if len(fields) >= 5 and "avb=vbmeta" in fields[4].split(","):
            avb_rows_before += 1
        if len(fields) >= 5 and fields[1] == "/vendor":
            found.append((index, fields, original))
    if len(found) != 1:
        raise ValueError(f"Expected one first-stage /vendor fstab row, found {len(found)}")
    index, fields, original = found[0]
    if "avb=vbmeta" not in fields[4].split(","):
        raise ValueError("First-stage /vendor fstab row has no avb=vbmeta flag")
    fields[4] = ",".join(flag for flag in fields[4].split(",") if flag != "avb=vbmeta")
    newline = "\r\n" if original.endswith("\r\n") else "\n" if original.endswith("\n") else ""
    lines[index] = "\t".join(fields) + newline
    result = "".join(lines).encode("utf-8")
    avb_rows_after = sum(
        1
        for line in result.decode("utf-8").splitlines()
        if len(line.split()) >= 5 and "avb=vbmeta" in line.split()[4].split(",")
    )
    if avb_rows_before - avb_rows_after != 1:
        raise ValueError("Fstab edit changed an unexpected number of AVB rows")
    return result, original.rstrip("\r\n"), lines[index].rstrip("\r\n"), avb_rows_before


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vendor", type=Path, default=DEFAULT_VENDOR)
    parser.add_argument("--super", type=Path, default=DEFAULT_SUPER)
    parser.add_argument("--base-disk", type=Path, default=DEFAULT_BASE_DISK)
    parser.add_argument("--ramdisk", type=Path, default=DEFAULT_RAMDISK)
    parser.add_argument("--block-output", type=Path, default=DEFAULT_BLOCK)
    parser.add_argument("--ramdisk-output", type=Path, default=DEFAULT_OUT_RAMDISK)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    args = parser.parse_args()
    for path in (args.vendor, args.super, args.base_disk, args.ramdisk):
        if not path.is_file():
            raise FileNotFoundError(path)
    for path in (args.block_output, args.ramdisk_output, args.manifest):
        if path.exists():
            raise FileExistsError(f"Refusing to overwrite derived output: {path}")

    with args.vendor.open("rb") as stream:
        source = ImageView(stream, 0, args.vendor.stat().st_size)
        fs = EROFS(source)
        inode = fs.find(TARGET_RC)
        if inode.layout not in (1, 3):
            raise ValueError(f"Target init rc is not LZ4-compressed EROFS data (layout={inode.layout})")
        original_rc = b"".join(fs.iter_file(inode))
        if original_rc.count(TARGET_LINE) != 1:
            raise ValueError("Expected the exact vendor module wait once in init.qti.kernel.rc")
        if len(COMMENT) > len(TARGET_LINE):
            raise ValueError("Replacement comment does not fit the original line")
        replacement_line = COMMENT + b" " * (len(TARGET_LINE) - len(COMMENT))
        modified_rc = original_rc.replace(TARGET_LINE, replacement_line, 1)
        if len(modified_rc) != inode.size:
            raise AssertionError("In-place EROFS edit changed the file size")
        base = (inode.position + inode.inode_size + inode.xattr_size + 7) & ~7
        compression_header = fs.image.read_at(base, 8)
        if not fs.incompat & 0x01:
            raise ValueError("EROFS LZ4 0-padding feature is absent; refusing block replacement")
        cluster_bits = fs.block_size.bit_length() - 1 + (compression_header[7] & 0x0F)
        indices, index_end = fs._compressed_indices(inode, compression_header, cluster_bits)
        heads = [
            (number, value, physical_block, kind)
            for number, (kind, value, physical_block) in enumerate(indices)
            if kind != 2 and (number << cluster_bits) + value < inode.size
        ]
        if len(heads) != 1 or heads[0][3] != 1:
            raise ValueError(f"Expected one LZ4 data extent for the target rc, got {heads}")
        physical_block = heads[0][2]
        physical_offset = physical_block * fs.block_size
        old_block = fs.image.read_at(physical_offset, fs.block_size)
        compressed = lz4.block.compress(
            modified_rc,
            mode="high_compression",
            compression=9,
            store_size=False,
        )
        if len(compressed) > fs.block_size:
            raise ValueError("Modified init rc no longer fits its original EROFS physical block")
        new_block = b"\0" * (fs.block_size - len(compressed)) + compressed
        if lz4.block.decompress(compressed, uncompressed_size=len(modified_rc)) != modified_rc:
            raise ValueError("LZ4 replacement failed its round-trip check")
        patched_fs = EROFS(PatchedReader(source, physical_offset, new_block))
        verified_rc = b"".join(patched_fs.iter_file(patched_fs.find(TARGET_RC)))
        if verified_rc != modified_rc:
            raise ValueError("Patched EROFS readback differs from the expected init rc")

    ramdisk_bytes = args.ramdisk.read_bytes()
    entries = read_newc(ramdisk_bytes)
    targets = [(i, values, payload) for i, (name, values, payload) in enumerate(entries) if name == FSTAB_PATH]
    if len(targets) != 1:
        raise ValueError(f"Expected one {FSTAB_PATH} in the first-stage ramdisk, found {len(targets)}")
    target_index, fstab_values, old_fstab = targets[0]
    new_fstab, old_vendor_row, new_vendor_row, avb_rows_before = patch_fstab(old_fstab)
    updated_entries = list(entries)
    name, values, _ = updated_entries[target_index]
    values = list(values)
    values[6] = len(new_fstab)
    values[5] = int(time.time())
    updated_entries[target_index] = (name, tuple(values), new_fstab)
    cpio = write_newc(updated_entries)
    checked_entries = read_newc(cpio)
    checked_payloads = {name: payload for name, _values, payload in checked_entries}
    if checked_payloads.get(FSTAB_PATH) != new_fstab:
        raise ValueError("Modified first-stage fstab failed CPIO round-trip validation")
    checked_fstab_lines = checked_payloads.get(FSTAB_PATH, b"").decode("utf-8").splitlines()
    checked_avb_rows = sum(
        1
        for line in checked_fstab_lines
        if len(line.split()) >= 5 and "avb=vbmeta" in line.split()[4].split(",")
    )
    if checked_avb_rows != avb_rows_before - 1:
        raise ValueError("Unexpected AVB fstab row count after QEMU-only vendor exemption")

    super_start, super_gpt = get_super_partition_start(args.base_disk)
    extent = get_vendor_extent(args.super, args.vendor)
    absolute_offset = super_start + extent["offset"] + physical_offset
    with args.base_disk.open("rb") as disk:
        disk.seek(absolute_offset)
        base_disk_block = disk.read(fs.block_size)
    if base_disk_block != old_block:
        raise ValueError("Base QEMU test disk vendor block differs from the extracted vendor_a image")

    args.block_output.parent.mkdir(parents=True, exist_ok=True)
    args.ramdisk_output.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.block_output.write_bytes(new_block)
    args.ramdisk_output.write_bytes(cpio)
    manifest = {
        "purpose": "QEMU-only release of the Qualcomm vendor module wait for this device-mismatched virtual machine",
        "source_vendor_image": str(args.vendor.resolve()),
        "source_vendor_sha256": sha256(args.vendor),
        "source_super_image": str(args.super.resolve()),
        "source_super_sha256": sha256(args.super),
        "source_base_disk": str(args.base_disk.resolve()),
        "source_base_disk_sha256": sha256(args.base_disk),
        "source_ramdisk": str(args.ramdisk.resolve()),
        "source_ramdisk_sha256": sha256(args.ramdisk),
        "vendor_partition": "vendor_a",
        "vendor_gpt_start": super_start,
        "super_gpt_partition": super_gpt,
        "vendor_super_extent_offset": extent["offset"],
        "vendor_super_extent_size": extent["size"],
        "target_file": "/vendor/etc/init/hw/init.qti.kernel.rc",
        "target_file_original_sha256": sha256_bytes(original_rc),
        "target_file_modified_sha256": sha256_bytes(modified_rc),
        "target_line_original": TARGET_LINE.decode("ascii"),
        "target_line_modified": replacement_line.decode("ascii"),
        "ero_fs_block_size": fs.block_size,
        "ero_fs_physical_block_index": physical_block,
        "ero_fs_physical_block_offset": physical_offset,
        "super_absolute_patch_offset": absolute_offset,
        "patch_block_size": fs.block_size,
        "patch_block_original_sha256": sha256_bytes(old_block),
        "patch_block_sha256": sha256_bytes(new_block),
        "patch_block_file": str(args.block_output.resolve()),
        "first_stage_fstab": FSTAB_PATH,
        "vendor_fstab_row_before": old_vendor_row,
        "vendor_fstab_row_after": new_vendor_row,
        "first_stage_avb_rows_before": avb_rows_before,
        "first_stage_avb_rows_after": avb_rows_before - 1,
        "ramdisk_output": str(args.ramdisk_output.resolve()),
        "ramdisk_output_sha256": sha256(args.ramdisk_output),
        "change_scope": "Removes AVB verification only from the modified vendor_a first-stage fstab row. All other first-stage AVB rows remain intact; source vbmeta, source super, and source images are unchanged.",
        "reason": "QEMU lacks the POCO F6 vendor modules. init.qti.kernel.rc blocks at post-fs on vendor.all.modules.ready=1 after vendor_modprobe exits unsuccessfully. The QEMU-only copy comments out that single wait; it does not create driver modules or claim they loaded.",
        "validation": [
            "Original and modified vendor init rc have identical byte lengths.",
            "The modified LZ4 cluster decompresses to the expected rc contents through the EROFS reader.",
            "The first-stage fstab CPIO edit round-trips and removes avb=vbmeta from /vendor only.",
            "The patch block in the base test disk matches the extracted vendor_a source block before writing.",
        ],
    }
    args.manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
