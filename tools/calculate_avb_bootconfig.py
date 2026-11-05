#!/usr/bin/env python3
"""Calculate Android's bootloader-supplied vbmeta.size/hash_alg/digest values.

Reads original firmware images only. Chain order is taken from the top-level
vbmeta descriptors, matching libavb's root-first, descriptor-order traversal.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path


def find_source_images(project: Path) -> Path:
    candidates = list((project / "analysis" / "source-partitions").rglob("vbmeta.img"))
    if len(candidates) != 1:
        raise SystemExit(f"Expected exactly one source vbmeta.img, found {len(candidates)}")
    return candidates[0].parent


def chained_partition_names(avbtool: Path, vbmeta_image: Path) -> list[str]:
    proc = subprocess.run(
        [sys.executable, str(avbtool), "info_image", "--image", str(vbmeta_image)],
        check=True,
        capture_output=True,
        text=True,
    )
    names = re.findall(
        r"Chain Partition descriptor:\s*\n\s*Partition Name:\s*([A-Za-z0-9_]+)",
        proc.stdout,
    )
    if not names:
        raise SystemExit("Top-level vbmeta has no readable chain partition descriptors")
    return names


def vbmeta_blob(path: Path) -> tuple[bytes, int]:
    with path.open("rb") as f:
        f.seek(0, 2)
        file_size = f.tell()
        if file_size < 256:
            raise SystemExit(f"{path.name}: file is too small for AVB metadata")
        f.seek(0)
        magic = f.read(4)
        footer_vbmeta_size = None
        if magic == b"AVB0":
            offset = 0
        else:
            if file_size < 64:
                raise SystemExit(f"{path.name}: missing AVB header/footer")
            f.seek(-64, 2)
            footer = f.read(64)
            if footer[:4] != b"AVBf":
                raise SystemExit(f"{path.name}: no AVB0 header or AVBf footer")
            offset = int.from_bytes(footer[20:28], "big")
            footer_vbmeta_size = int.from_bytes(footer[28:36], "big")
        f.seek(offset)
        header = f.read(256)
        if len(header) != 256 or header[:4] != b"AVB0":
            raise SystemExit(f"{path.name}: footer does not point to a valid AVB0 header")
        auth_size = int.from_bytes(header[12:20], "big")
        aux_size = int.from_bytes(header[20:28], "big")
        size = 256 + auth_size + aux_size
        if footer_vbmeta_size is not None and footer_vbmeta_size != size:
            raise SystemExit(
                f"{path.name}: footer says vbmeta size {footer_vbmeta_size}, header says {size}"
            )
        if offset + size > file_size:
            raise SystemExit(f"{path.name}: vbmeta data exceeds image bounds")
        f.seek(offset)
        blob = f.read(size)
        if len(blob) != size:
            raise SystemExit(f"{path.name}: truncated vbmeta metadata")
        return blob, offset


def main() -> None:
    project = Path(__file__).resolve().parent.parent
    tools = project / "tools"
    images = find_source_images(project)
    avbtool = tools / "avbtool.py"
    root = images / "vbmeta.img"
    chain = chained_partition_names(avbtool, root)
    ordered_paths = [root]
    ordered_paths.extend(images / f"{name}.img" for name in chain)
    if any(not path.is_file() for path in ordered_paths):
        missing = [path.name for path in ordered_paths if not path.is_file()]
        raise SystemExit(f"Missing chained AVB image(s): {', '.join(missing)}")

    digest = hashlib.sha256()
    total_size = 0
    details = []
    for path in ordered_paths:
        blob, offset = vbmeta_blob(path)
        digest.update(blob)
        total_size += len(blob)
        details.append(
            {
                "partition_image": path.name,
                "vbmeta_offset": offset,
                "vbmeta_size": len(blob),
                "sha256": hashlib.sha256(blob).hexdigest(),
            }
        )

    result = {
        "source_images": str(images),
        "chain_order": [path.name for path in ordered_paths],
        "size": total_size,
        "hash_alg": "sha256",
        "digest": digest.hexdigest(),
        "components": details,
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

