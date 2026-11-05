#!/usr/bin/env python3
"""Create a QEMU-only second-stage fstab and derived initramfs copy.

The stock vendor/system images remain untouched. Android init selects the
added first_stage_ramdisk/fstab.qemu when booted with fstab_suffix=qemu.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import struct
import time
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
DEFAULT_FSTAB = PROJECT / "analysis" / "fstab.qcom.extracted"
DEFAULT_RAMDISK = PROJECT / "analysis" / "qemu-virt-stage2-ramdisk.cpio"
DEFAULT_OUTPUT_FSTAB = PROJECT / "analysis" / "fstab.qemu.generated"
DEFAULT_OUTPUT_BOOTCONFIG = PROJECT / "analysis" / "bootconfig.qemu"
DEFAULT_OUTPUT_RAMDISK = PROJECT / "analysis" / "qemu-virt-fstab-ramdisk.cpio"
DEFAULT_MANIFEST = PROJECT / "analysis" / "qemu-fstab-modification.json"
CPIO_PATHS = (
    "first_stage_ramdisk/fstab.qemu",
    "first_stage_ramdisk/system/etc/fstab.qemu",
    "fstab.qemu",
)
BOOTCONFIG_DATA = b'androidboot.fstab_suffix = "qemu"\n'
BOOTCONFIG_MAGIC = b"#BOOTCONFIG\n"
GPT_PARTITIONS = {
    "boot_a", "init_boot_a", "vendor_boot_a", "dtbo_a", "recovery_a",
    "metadata", "vbmeta_a", "vbmeta_system_a", "super", "userdata",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def align4(value: int) -> int:
    return (value + 3) & ~3


def read_newc(data: bytes) -> list[tuple[str, tuple[int, ...], bytes]]:
    entries: list[tuple[str, tuple[int, ...], bytes]] = []
    cursor = 0
    while cursor < len(data):
        while cursor < len(data) and data[cursor] == 0:
            cursor += 1
        if cursor >= len(data):
            break
        if data[cursor : cursor + 6] not in (b"070701", b"070702"):
            raise ValueError(f"Unexpected bytes at initramfs offset 0x{cursor:x}")
        if cursor + 110 > len(data):
            raise ValueError("Truncated newc header")
        raw_fields = [data[cursor + 6 + 8 * i : cursor + 14 + 8 * i] for i in range(13)]
        # The existing PowerShell ramdisk builder writes NUL-filled fields in
        # its TRAILER!!! record; Linux's initramfs unpacker accepts them as 0.
        values = tuple(0 if not field.strip(b"\0") else int(field, 16) for field in raw_fields)
        file_size, name_size = values[6], values[11]
        name_begin = cursor + 110
        name_end = name_begin + name_size
        if name_size < 1 or name_end > len(data):
            raise ValueError("Invalid newc pathname size")
        name = data[name_begin : name_end - 1].decode("utf-8")
        payload_begin = align4(name_end)
        payload_end = payload_begin + file_size
        if payload_end > len(data):
            raise ValueError(f"Truncated newc payload for {name}")
        if name != "TRAILER!!!":
            entries.append((name, values, data[payload_begin:payload_end]))
        cursor = align4(payload_end)
    if not entries:
        raise ValueError("No newc CPIO entries found")
    return entries


def write_entry(out: bytearray, name: str, values: tuple[int, ...], payload: bytes) -> None:
    name_bytes = name.encode("utf-8") + b"\0"
    fields = list(values)
    fields[6] = len(payload)
    fields[11] = len(name_bytes)
    header = b"070701" + b"".join(f"{value:08x}".encode("ascii") for value in fields)
    if len(header) != 110:
        raise AssertionError("Invalid newc header length")
    out.extend(header)
    out.extend(name_bytes)
    out.extend(b"\0" * (align4(len(out)) - len(out)))
    out.extend(payload)
    out.extend(b"\0" * (align4(len(out)) - len(out)))


def write_newc(entries: list[tuple[str, tuple[int, ...], bytes]]) -> bytes:
    out = bytearray()
    for name, values, payload in entries:
        write_entry(out, name, values, payload)
    trailer_values = (0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 11, 0)
    write_entry(out, "TRAILER!!!", trailer_values, b"")
    return bytes(out)


def filter_fstab(source: Path) -> tuple[bytes, list[str], int]:
    kept: list[str] = []
    removed: list[str] = []
    for line in source.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if not fields or fields[0].startswith("#"):
            kept.append(line)
            continue
        device = fields[0]
        reason = None
        if device.startswith("/dev/block/bootdevice/by-name/"):
            partition = device.rsplit("/", 1)[-1]
            if partition != "userdata":
                mapped = f"{partition}_a"
                if mapped not in GPT_PARTITIONS and partition not in GPT_PARTITIONS:
                    reason = "source partition is absent from the QEMU GPT"
        elif device.startswith("/devices/platform/soc/"):
            reason = "removable or SoC-specific storage device is absent on QEMU virt"
        if reason:
            removed.append(f"{line}\t# omitted: {reason}")
        else:
            if device == "/dev/block/by-name/metadata" and len(fields) >= 5:
                fields[4] = ",".join(flag for flag in fields[4].split(",") if flag != "first_stage_mount")
                line = "\t".join(fields)
            kept.append(line)
    generated = (
        f"# QEMU-only fstab generated from {source.name}; absent POCO F6 physical devices omitted.\n"
        + "\n".join(kept)
        + "\n"
    ).encode("utf-8")
    return generated, removed, len(kept)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fstab", type=Path, default=DEFAULT_FSTAB)
    parser.add_argument("--ramdisk", type=Path, default=DEFAULT_RAMDISK)
    parser.add_argument("--output-fstab", type=Path, default=DEFAULT_OUTPUT_FSTAB)
    parser.add_argument("--output-bootconfig", type=Path, default=DEFAULT_OUTPUT_BOOTCONFIG)
    parser.add_argument("--output-ramdisk", type=Path, default=DEFAULT_OUTPUT_RAMDISK)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    args = parser.parse_args()
    for path in (args.fstab, args.ramdisk):
        if not path.is_file():
            raise FileNotFoundError(path)

    fstab_bytes, removed, kept_count = filter_fstab(args.fstab)
    if not removed:
        raise ValueError("No absent QEMU-only partition entries found; refusing a no-op overlay")
    if b"first_stage_mount" not in fstab_bytes or b"logical" not in fstab_bytes:
        raise ValueError("Generated fstab lost required logical/first-stage entries")

    original_entries = read_newc(args.ramdisk.read_bytes())
    for cpio_path in CPIO_PATHS:
        if any(name == cpio_path for name, _values, _payload in original_entries):
            raise ValueError(f"Input already contains {cpio_path}; refusing to overwrite it")
    output_entries = list(original_entries)
    existing_names = {name for name, _values, _payload in original_entries}
    for ino, directory in enumerate(("first_stage_ramdisk/system", "first_stage_ramdisk/system/etc"), start=1000):
        if directory not in existing_names:
            directory_values = (ino, stat.S_IFDIR | 0o755, 0, 0, 2, int(time.time()), 0, 0, 0, 0, 0, len(directory) + 1, 0)
            output_entries.append((directory, directory_values, b""))
            existing_names.add(directory)
    for ino, cpio_path in enumerate(CPIO_PATHS, start=1):
        values = (ino, stat.S_IFREG | 0o644, 0, 0, 1, int(time.time()), len(fstab_bytes), 0, 0, 0, 0, len(cpio_path) + 1, 0)
        output_entries.append((cpio_path, values, fstab_bytes))
    cpio_bytes = write_newc(output_entries)
    padded_bootconfig = BOOTCONFIG_DATA + b"\0" * ((-len(BOOTCONFIG_DATA)) % 4)
    bootconfig_checksum = sum(padded_bootconfig) & 0xFFFFFFFF
    bootconfig_tail = (
        padded_bootconfig
        + struct.pack("<II", len(padded_bootconfig), bootconfig_checksum)
        + BOOTCONFIG_MAGIC
    )
    output_bytes = cpio_bytes + bootconfig_tail

    args.output_fstab.parent.mkdir(parents=True, exist_ok=True)
    args.output_bootconfig.parent.mkdir(parents=True, exist_ok=True)
    args.output_ramdisk.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.output_fstab.write_bytes(fstab_bytes)
    args.output_bootconfig.write_bytes(BOOTCONFIG_DATA)
    args.output_ramdisk.write_bytes(output_bytes)

    validated = read_newc(cpio_bytes)
    matches = {name: payload for name, _values, payload in validated if name in CPIO_PATHS}
    if matches != {name: fstab_bytes for name in CPIO_PATHS}:
        raise ValueError("Generated initramfs did not round-trip the QEMU fstab")
    if not output_bytes.endswith(BOOTCONFIG_MAGIC):
        raise ValueError("Generated initramfs is missing the bootconfig trailer")
    stored_size, stored_checksum = struct.unpack("<II", output_bytes[-20:-12])
    if stored_size != len(padded_bootconfig) or stored_checksum != bootconfig_checksum:
        raise ValueError("Generated bootconfig trailer failed its size/checksum validation")
    if sum(output_bytes[-20-stored_size:-20]) & 0xFFFFFFFF != stored_checksum:
        raise ValueError("Generated bootconfig checksum did not round-trip")
    manifest = {
        "created_at_epoch": int(time.time()),
        "purpose": "QEMU-only second-stage fstab; stock vendor/system AVB images remain unchanged",
        "fstab_suffix": "qemu",
        "fstab_cpio_paths": list(CPIO_PATHS),
        "bootconfig_data": BOOTCONFIG_DATA.decode("ascii").rstrip("\n"),
        "bootconfig_padded_size": len(padded_bootconfig),
        "bootconfig_checksum": bootconfig_checksum,
        "gpt_partitions": sorted(GPT_PARTITIONS),
        "input_fstab": str(args.fstab.resolve()),
        "input_fstab_sha256": sha256(args.fstab),
        "input_ramdisk": str(args.ramdisk.resolve()),
        "input_ramdisk_sha256": sha256(args.ramdisk),
        "output_fstab": str(args.output_fstab.resolve()),
        "output_fstab_sha256": sha256(args.output_fstab),
        "output_bootconfig": str(args.output_bootconfig.resolve()),
        "output_bootconfig_sha256": sha256(args.output_bootconfig),
        "output_ramdisk": str(args.output_ramdisk.resolve()),
        "output_ramdisk_sha256": sha256(args.output_ramdisk),
        "kept_fstab_line_count_including_comments": kept_count,
        "removed_lines": removed,
        "changes": [
            "Added fstab.qemu at root and both Android first-stage ramdisk lookup paths.",
            "Appended Android bootconfig override androidboot.fstab_suffix=qemu to the derived initramfs.",
            "Omitted rows for absent POCO F6 partitions and SoC-specific removable storage.",
            "Moved metadata out of first_stage_mount so it remains mounted during second-stage mount_all.",
            "Kept dynamic-partition, AVB, SELinux, and userdata options unchanged.",
        ],
    }
    args.manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "output_ramdisk": str(args.output_ramdisk.resolve()),
        "output_ramdisk_sha256": manifest["output_ramdisk_sha256"],
        "output_fstab": str(args.output_fstab.resolve()),
        "output_fstab_sha256": manifest["output_fstab_sha256"],
        "removed_rows": len(removed),
        "kept_rows": kept_count,
        "manifest": str(args.manifest.resolve()),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
