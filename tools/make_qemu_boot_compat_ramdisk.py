#!/usr/bin/env python3
"""Add a QEMU-only init hook that releases Qualcomm's module-ready wait."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from make_qemu_stage2_fstab import read_newc, sha256, write_newc


PROJECT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = PROJECT / "analysis" / "qemu-virt-stage2-ramdisk.cpio"
DEFAULT_OUTPUT = PROJECT / "analysis" / "qemu-virt-modules-barrier-ramdisk.cpio"
DEFAULT_MANIFEST = PROJECT / "analysis" / "qemu-modules-barrier-ramdisk.json"
RC_PATH = "first_stage_ramdisk/init.qcom.rc"
RC_APPEND = b"""

# QEMU-only: the stock kernel has built-in PL011 and NVMe support, while the
# POCO F6 Qualcomm module set does not match QEMU virt. Release the vendor init
# barrier after the stock module loader has exited; no driver is fabricated.
service qemu_vendor_modules_ready /system/bin/setprop vendor.all.modules.ready 1
    class core
    user root
    group root system
    seclabel u:r:vendor_modprobe:s0
    oneshot
    disabled

on property:init.svc.vendor.modprobe=stopped
    exec_start qemu_vendor_modules_ready
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    args = parser.parse_args()
    if not args.input.is_file():
        raise FileNotFoundError(args.input)
    if args.output.exists():
        raise FileExistsError(f"Refusing to overwrite derived output: {args.output}")

    entries = read_newc(args.input.read_bytes())
    if any(name == RC_PATH for name, _values, _payload in entries):
        raise ValueError(f"Input already contains {RC_PATH}; refusing to overwrite it")
    if not any(name == "init" for name, _values, _payload in entries):
        raise ValueError("Input initramfs has no /init binary")
    template = next(values for name, values, _payload in entries if name == "init")
    now = int(__import__("time").time())
    values = list(template)
    values[0] += 1
    values[1] = (values[1] & 0o170000) | 0o644
    values[2] = values[3] = 0
    values[4] = 1
    values[5] = now
    values[6] = len(RC_APPEND)
    values[7] = values[8] = values[9] = values[10] = 0
    values[11] = len(RC_PATH) + 1
    values[12] = 0
    output_bytes = write_newc([*entries, (RC_PATH, tuple(values), RC_APPEND)])

    verified = {name: payload for name, _values, payload in read_newc(output_bytes)}
    if verified.get(RC_PATH) != RC_APPEND:
        raise ValueError("Derived initramfs failed CPIO round-trip validation")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(output_bytes)
    manifest = {
        "purpose": "QEMU-only init hook to release vendor.all.modules.ready after the vendor module loader stops",
        "input": str(args.input.resolve()),
        "input_sha256": sha256(args.input),
        "output": str(args.output.resolve()),
        "output_sha256": hashlib.sha256(output_bytes).hexdigest(),
        "hook_path_after_switch_root": "/init.qcom.rc",
        "hook_sha256": hashlib.sha256(RC_APPEND).hexdigest(),
        "change": "Adds first_stage_ramdisk/init.qcom.rc, which becomes /init.qcom.rc after Android switches root. It releases the vendor init barrier only after vendor.modprobe stops; no module is added and AVB/SELinux policy is unchanged.",
        "reason": "Observed init.qti.kernel.rc post-fs waits indefinitely for vendor.all.modules.ready=1; vendor_modprobe exits 1 in QEMU when the POCO module set cannot load. The earlier root-level import was discarded at switch_root.",
    }
    args.manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
