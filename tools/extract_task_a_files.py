#!/usr/bin/env python3
"""Read-only extraction of the small firmware text files requested by Task A."""
from __future__ import annotations

import json
import stat
import struct
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(PROJECT / "analysis" / "pydeps-lz4"), str(PROJECT / "tools" / "python")]

from asgard.formats.erofs import EROFS
from asgard.formats.ext4 import Ext4
from asgard.formats.images import _open_super_image_reader, _read_lp_metadata, _select_lp_partitions
from asgard.formats.random_access import ImageView, SparseView

ANALYSIS = PROJECT / "analysis"
IMAGES = ANALYSIS / "source-partitions" / "peridot_id_global_images_OS3.0.304.0.WNPIDXM_16.0" / "images"
SYSTEM = ANALYSIS / "system_a-from-super.img"
VENDOR = ANALYSIS / "vendor_a-from-super.img"
SUPER = IMAGES / "super.img"
OUT = ANALYSIS / "task-a-extracted-v2"


class WindowView:
    def __init__(self, source, offset: int, size: int):
        self.source, self.offset, self.size = source, offset, size

    def read_at(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > self.size:
            raise ValueError("read outside logical partition")
        return self.source.read_at(self.offset + offset, size)


def list_dir(fs, path: str):
    inode = fs._inode(fs.root_nid) if isinstance(fs, EROFS) else fs._inode(2)
    for component in path.strip("/").split("/"):
        if component:
            inode = fs._inode(fs._lookup(inode, component))
    if not stat.S_ISDIR(inode.mode):
        return []
    found = []
    for block in fs._data(inode):
        if isinstance(fs, EROFS):
            count = struct.unpack_from("<H", block, 8)[0] // 12
            for i in range(count):
                nid, name_start = struct.unpack_from("<QH", block, i * 12)
                end = struct.unpack_from("<H", block, (i + 1) * 12 + 8)[0] if i + 1 < count else len(block)
                name = block[name_start:end].split(b"\0", 1)[0].decode("utf-8", "replace")
                if name not in (".", ".."):
                    found.append((name, fs._inode(nid)))
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
                        found.append((name, fs._inode(ino)))
                offset += rec_len
    return found


def walk_files(fs, path: str):
    for name, node in list_dir(fs, path):
        child = f"{path.rstrip('/')}/{name}"
        if stat.S_ISDIR(node.mode):
            yield from walk_files(fs, child)
        elif stat.S_ISREG(node.mode):
            yield child, node


def extract(fs, image_name: str, source_path: str, node, status: list[dict]) -> None:
    data = b"".join(fs.iter_file(node))
    # The requested payloads are text configuration. Keep unexpected binary
    # entries out of the review bundle and report them by path and size.
    if b"\0" in data:
        status.append({"source": f"/{image_name}/{source_path}", "result": "skipped-nul-byte", "size": len(data)})
        return
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        status.append({"source": f"/{image_name}/{source_path}", "result": "skipped-non-utf8", "size": len(data)})
        return
    dest = OUT / image_name / source_path
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    status.append({"source": f"/{image_name}/{source_path}", "result": "extracted", "size": len(data)})


def get_node(fs, path: str):
    node = fs._inode(fs.root_nid) if isinstance(fs, EROFS) else fs._inode(2)
    for component in path.strip("/").split("/"):
        if component:
            node = fs._inode(fs._lookup(node, component))
    return node


def extract_exact(fs, image_name: str, path: str, status: list[dict]) -> None:
    try:
        node = get_node(fs, path)
        if not stat.S_ISREG(node.mode):
            status.append({"source": f"/{image_name}/{path}", "result": "not-regular-file"})
            return
        extract(fs, image_name, path, node, status)
    except Exception as exc:
        status.append({"source": f"/{image_name}/{path}", "result": f"not-found-or-error: {type(exc).__name__}: {exc}"})


def fs_type(fs) -> str:
    return "EROFS" if isinstance(fs, EROFS) else "ext4"


def main() -> int:
    if OUT.exists():
        raise SystemExit(f"Refusing to overwrite extraction directory: {OUT}")
    OUT.mkdir(parents=True)
    status: list[dict] = []
    formats: dict[str, str] = {}

    with SYSTEM.open("rb") as stream:
        system_fs = EROFS(ImageView(stream, 0, SYSTEM.stat().st_size))
        formats["system_a"] = fs_type(system_fs)
        for path in ("system/etc/selinux/plat_file_contexts", "system/etc/init/hw/init.rc", "system/etc/init/keystore2.rc"):
            extract_exact(system_fs, "system_a", path, status)

    with VENDOR.open("rb") as stream:
        vendor_fs = EROFS(ImageView(stream, 0, VENDOR.stat().st_size))
        formats["vendor_a"] = fs_type(vendor_fs)
        exact = (
            "etc/vintf/manifest.xml",
            "bin/init.qti.qcv.sh",
            "etc/init/qseecomd.rc",
            "etc/init/init.qti.qcv.rc",
            "etc/init/android.hardware.security.keymint-service-qti.rc",
            "etc/selinux/vendor_file_contexts",
            "etc/fstab.qcom",
            "etc/init/hw/init.target.rc",
        )
        for path in exact:
            extract_exact(vendor_fs, "vendor_a", path, status)
        for base, predicate in (
            ("etc/vintf", lambda p: p.lower().endswith(".xml") and ("/manifest/" in f"/{p}" or Path(p).name.startswith("manifest"))),
            ("etc/init", lambda p: p.lower().endswith(".rc") and any(term in p.lower() for term in ("keymint", "qseecomd", "init.qti.qcv"))),
        ):
            for path, node in walk_files(vendor_fs, base):
                if predicate(path):
                    extract(vendor_fs, "vendor_a", path, node, status)
        for path, node in walk_files(vendor_fs, "etc/init"):
            if path.endswith(".rc"):
                try:
                    data = b"".join(vendor_fs.iter_file(node))
                except Exception:
                    continue
                lowered = data.lower()
                if any(term in lowered for term in (b"vendor_init", b"hypsys", b"tombstone")):
                    extract(vendor_fs, "vendor_a", path, node, status)

    with SUPER.open("rb") as stream:
        with _open_super_image_reader(stream, member_name=SUPER.name, member_size=SUPER.stat().st_size) as reader:
            metadata = _read_lp_metadata(reader)
        selected = _select_lp_partitions(metadata, ("odm_a",))
        if len(selected) != 1:
            raise RuntimeError(f"odm_a missing/ambiguous: {len(selected)} entries")
        part = selected[0]
        extents = metadata.extents[part.first_extent_index:part.first_extent_index + part.num_extents]
        if len(extents) != 1 or extents[0].target_type != 0:
            raise RuntimeError(f"odm_a extent layout unsupported: {len(extents)} extent(s)")
        extent = extents[0]
        sparse = SparseView(ImageView(stream, 0, SUPER.stat().st_size))
        odm_view = WindowView(sparse, extent.target_data * 512, extent.num_sectors * 512)
        try:
            odm_fs = EROFS(odm_view)
        except Exception:
            odm_fs = Ext4(odm_view)
        formats["odm_a"] = fs_type(odm_fs)
        for path, node in walk_files(odm_fs, "etc/vintf"):
            if path.lower().endswith((".xml", ".rc", ".conf")):
                extract(odm_fs, "odm_a", path, node, status)
        for path, node in walk_files(odm_fs, "etc/init"):
            if Path(path).name == "android.hardware.security.keymint3-service.strongbox.nxp.rc":
                extract(odm_fs, "odm_a", path, node, status)
        layout = {
            "name": part.name,
            "num_extents": len(extents),
            "first_extent_sector": extent.target_data,
            "extent_sectors": extent.num_sectors,
            "logical_bytes": extent.num_sectors * 512,
            "filesystem": formats["odm_a"],
        }

    manifest = {
        "read_only": True,
        "source_images": {
            "system_a": str(SYSTEM),
            "vendor_a": str(VENDOR),
            "super_sparse": str(SUPER),
        },
        "filesystem_types": formats,
        "odm_a_layout": layout,
        "files": status,
    }
    (OUT / "extraction-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"out": str(OUT), "filesystem_types": formats, "odm_a_layout": layout,
                      "extracted": sum(item["result"] == "extracted" for item in status),
                      "not_extracted": [item for item in status if item["result"] != "extracted"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
