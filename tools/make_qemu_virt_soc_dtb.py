#!/usr/bin/env python3
"""Create a derived QEMU virt DTB with its PCIe host below a simple-bus /soc."""

from __future__ import annotations

import argparse
import struct
from dataclasses import dataclass, field
from pathlib import Path


FDT_MAGIC = 0xD00DFEED
FDT_BEGIN_NODE = 1
FDT_END_NODE = 2
FDT_PROP = 3
FDT_NOP = 4
FDT_END = 9


@dataclass
class Node:
    name: str
    props: list[tuple[str, bytes]] = field(default_factory=list)
    children: list["Node"] = field(default_factory=list)


def align4(value: int) -> int:
    return (value + 3) & ~3


def parse_dtb(data: bytes) -> tuple[Node, bytes, tuple[int, ...]]:
    if len(data) < 40:
        raise ValueError("DTB is shorter than its 40-byte header")
    header = struct.unpack_from(">10I", data)
    magic, total, struct_off, strings_off, reserve_off, *_ = header
    size_strings, size_struct = header[8], header[9]
    if magic != FDT_MAGIC:
        raise ValueError(f"Unexpected DTB magic 0x{magic:08x}")
    if total > len(data) or struct_off + size_struct > total or strings_off + size_strings > total:
        raise ValueError("DTB header points outside the available data")

    strings = data[strings_off : strings_off + size_strings]
    struct_end = struct_off + size_struct
    pos = struct_off
    stack: list[Node] = []
    root: Node | None = None
    while pos + 4 <= struct_end:
        token = struct.unpack_from(">I", data, pos)[0]
        pos += 4
        if token == FDT_BEGIN_NODE:
            end = data.find(b"\0", pos, struct_end)
            if end < 0:
                raise ValueError("Unterminated FDT node name")
            name = data[pos:end].decode("utf-8")
            pos = align4(end + 1)
            node = Node(name)
            if stack:
                stack[-1].children.append(node)
            elif root is None:
                root = node
            else:
                raise ValueError("DTB contains more than one root node")
            stack.append(node)
        elif token == FDT_END_NODE:
            if not stack:
                raise ValueError("Unexpected FDT_END_NODE")
            stack.pop()
        elif token == FDT_PROP:
            if not stack or pos + 8 > struct_end:
                raise ValueError("Malformed FDT_PROP")
            length, nameoff = struct.unpack_from(">II", data, pos)
            pos += 8
            if nameoff >= len(strings):
                raise ValueError("FDT property name offset is out of range")
            name_end = strings.find(b"\0", nameoff)
            if name_end < 0:
                raise ValueError("Unterminated FDT property name")
            name = strings[nameoff:name_end].decode("utf-8")
            value = data[pos : pos + length]
            if len(value) != length:
                raise ValueError("FDT property value is truncated")
            stack[-1].props.append((name, value))
            pos = align4(pos + length)
        elif token == FDT_NOP:
            continue
        elif token == FDT_END:
            break
        else:
            raise ValueError(f"Unknown FDT token 0x{token:08x} at 0x{pos - 4:x}")
    if root is None or stack:
        raise ValueError("DTB tree is incomplete")

    # Copy complete 16-byte memory reservation records, including the zero terminator.
    reserve_pos = reserve_off
    while reserve_pos + 16 <= total:
        address, size = struct.unpack_from(">QQ", data, reserve_pos)
        reserve_pos += 16
        if address == 0 and size == 0:
            break
    else:
        raise ValueError("DTB memory reservation map has no terminator")
    reserve_map = data[reserve_off:reserve_pos]
    return root, reserve_map, header


def encode_dtb(root: Node, reserve_map: bytes, old_header: tuple[int, ...]) -> bytes:
    prop_names: list[str] = []

    def collect(node: Node) -> None:
        for name, _ in node.props:
            if name not in prop_names:
                prop_names.append(name)
        for child in node.children:
            collect(child)

    collect(root)
    strings = bytearray()
    name_offsets: dict[str, int] = {}
    for name in prop_names:
        name_offsets[name] = len(strings)
        strings.extend(name.encode("utf-8") + b"\0")

    structure = bytearray()

    def emit_node(node: Node) -> None:
        structure.extend(struct.pack(">I", FDT_BEGIN_NODE))
        structure.extend(node.name.encode("utf-8") + b"\0")
        structure.extend(b"\0" * (align4(len(structure)) - len(structure)))
        for name, value in node.props:
            structure.extend(struct.pack(">III", FDT_PROP, len(value), name_offsets[name]))
            structure.extend(value)
            structure.extend(b"\0" * (align4(len(structure)) - len(structure)))
        for child in node.children:
            emit_node(child)
        structure.extend(struct.pack(">I", FDT_END_NODE))

    emit_node(root)
    structure.extend(struct.pack(">I", FDT_END))

    header_size = 40
    reserve_off = header_size
    struct_off = align4(reserve_off + len(reserve_map))
    strings_off = align4(struct_off + len(structure))
    total = strings_off + len(strings)
    version, last_comp, boot_cpu = old_header[5], old_header[6], old_header[7]
    header = struct.pack(
        ">10I",
        FDT_MAGIC,
        total,
        struct_off,
        strings_off,
        reserve_off,
        version,
        last_comp,
        boot_cpu,
        len(strings),
        len(structure),
    )
    output = bytearray(header)
    output.extend(reserve_map)
    output.extend(b"\0" * (struct_off - len(output)))
    output.extend(structure)
    output.extend(b"\0" * (strings_off - len(output)))
    output.extend(strings)
    return bytes(output)


def add_soc_parent(root: Node, pcie_name: str) -> None:
    existing_soc = [child for child in root.children if child.name == "soc"]
    if existing_soc:
        raise ValueError("The input DTB already has a top-level /soc node")
    matches = [child for child in root.children if child.name == pcie_name]
    if len(matches) != 1:
        names = ", ".join(child.name for child in root.children)
        raise ValueError(f"Expected one /{pcie_name}; root children are: {names}")

    pcie = matches[0]
    root.children.remove(pcie)
    soc = Node(
        "soc",
        props=[
            ("compatible", b"simple-bus\0"),
            ("#address-cells", struct.pack(">I", 2)),
            ("#size-cells", struct.pack(">I", 2)),
            ("ranges", b""),
        ],
        children=[pcie],
    )
    root.children.append(soc)


def print_tree(node: Node, indent: int = 0) -> None:
    print("  " * indent + ("/" if indent == 0 else node.name))
    for name, value in node.props:
        if name == "compatible":
            rendered = ",".join(part.decode("utf-8", "replace") for part in value.rstrip(b"\0").split(b"\0"))
        else:
            rendered = f"{len(value)} bytes"
        print("  " * (indent + 1) + f"{name} = {rendered}")
    for child in node.children:
        print_tree(child, indent + 1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", nargs="?", type=Path)
    parser.add_argument("--pcie", default="pcie@10000000", help="top-level PCIe node name")
    parser.add_argument("--list", action="store_true", help="print tree without making a DTB")
    args = parser.parse_args()

    data = args.input.read_bytes()
    root, reserve_map, header = parse_dtb(data)
    if args.list:
        print_tree(root)
        return
    if args.output is None:
        parser.error("output is required unless --list is used")
    add_soc_parent(root, args.pcie)
    result = encode_dtb(root, reserve_map, header)
    # Re-parse our own output before writing it.
    parsed, _, _ = parse_dtb(result)
    soc = next((child for child in parsed.children if child.name == "soc"), None)
    if soc is None or not any(child.name == args.pcie for child in soc.children):
        raise ValueError("DTB validation failed: PCIe host is not under /soc")
    args.output.write_bytes(result)
    print(f"Created {args.output} ({len(result)} bytes); moved /{args.pcie} below /soc")


if __name__ == "__main__":
    main()
