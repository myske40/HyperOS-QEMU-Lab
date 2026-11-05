#!/usr/bin/env python3
"""Create and verify the text-only v6-v9 HyperOS QEMU reviewer ZIP."""
from __future__ import annotations

import ast
import hashlib
import json
import shutil
import sys
import zipfile
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
ANALYSIS = PROJECT / "analysis"
TOOLS = PROJECT / "tools"
REPORTS = PROJECT / "reports"
OUT = REPORTS / "hyperos-qemu-review-v9-taskA-reviewer-ready.zip"
STAGE = REPORTS / "hyperos-qemu-review-v9-taskA-reviewer-ready-staging"
TASK_A = ANALYSIS / "task-a-extracted-v2"
V9_MANIFEST_PATH = ANALYSIS / "qemu-vendor-modprobe-test-v9-final.json"
V8_MANIFEST_PATH = ANALYSIS / "qemu-vendor-modprobe-test-v8.json"
V9_RUN_PATH = ANALYSIS / "qemu-avb-20261105-185241.json"
V9_SERIAL_PATH = ANALYSIS / "qemu-avb-20261105-185241.serial.log"
FIRMWARE = PROJECT / "firmware" / "peridot_id_global_images_OS3.0.304.0.WNPIDXM_20260721.0000.00_16.0_id_6178d39ec1 (1).tgz"
FIRMWARE_SHA256 = "3e3772c6539ba4387d8c97ea9d2e42c28efa5d1b658db0e80e9ae2a9dbf5efdc"

sys.path.insert(0, str(TOOLS))
import package_review_bundle as common  # noqa: E402

common.STAGE = STAGE


def put_tree(source: Path, destination: str) -> None:
    for path in sorted(source.rglob("*")):
        if path.is_file():
            common.put_file(path, f"{destination}/{path.relative_to(source).as_posix()}")


def extract_script_and_fragments(version: str, filename: str) -> None:
    source = TOOLS / filename
    common.put_file(source, f"scripts/{version}/{filename}")
    tree = ast.parse(source.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        for target in targets:
            if not isinstance(target, ast.Name):
                continue
            if not (target.id.endswith("_APPEND") or target.id == "QEMU_SCRIPT"):
                continue
            try:
                value = ast.literal_eval(node.value)
            except Exception:
                continue
            if not isinstance(value, bytes):
                continue
            suffix = ".rc.append" if target.id.endswith("_APPEND") else ".sh"
            common.put_bytes(value, f"scripts/{version}/{target.id.lower()}{suffix}")


def text_payload(filename: str, byte_count: int, destination: str) -> None:
    payload = (ANALYSIS / filename).read_bytes()[:byte_count]
    if b"\0" in payload:
        raise ValueError(f"unexpected NUL in extracted text payload {filename}")
    payload.decode("utf-8")
    common.put_bytes(payload, destination)


def build_notes(v8: dict, v9: dict, run: dict, task_a: dict, diff: dict) -> str:
    audit_text = (
        "- The v6 and v8 raw logs show `exec 7 (/system/bin/vdc keymaster earlyBootEnded)` as started/waiting, "
        "then `vdc()++ keymaster earlyBootEnded` and `Waited 0ms for vold`. Neither run has an exec-7 exit line "
        "before the critical-process reboot. Servicemanager repeatedly reports that `android.security.maintenance` "
        "could not be found. This strongly supports an init queue stall at that exec, but the log does not explicitly "
        "prove causation or replace checking Android 16 init source. The init `took ... succeeded` line records spawn, not completion.\n"
    )
    changed = ", ".join(diff["changed_patch_payloads"])
    avc = (
        "`audit: avc: denied { getattr } ... comm=\"init\" path=\"/system/bin/logcat\" "
        "scontext=u:r:init:s0 tcontext=u:object_r:logcat_exec:s0 tclass=file permissive=0`; init then logs "
        "`Command 'start qemu-logcat' ... failed: Could not start service: Cannot find '/system/bin/logcat': Permission denied`. "
        "This is recorded as a policy denial; no policy change was made.\n"
    )
    return f"""# HyperOS QEMU reviewer bundle — v6 through v9

## Scope and integrity

This ZIP contains full unfiltered serial logs for runs v6–v9, settings and patch manifests, patch builder sources and their RC/shell additions, small text-only firmware extracts, the reviewer handoff and addenda, and SHA-256 checksums. It excludes the firmware archive, `super.img`, partition images, raw or QCOW2 disks, CPIO archives, kernels, and Qualcomm/NXP proprietary binaries.

Firmware source SHA-256: `{FIRMWARE_SHA256}` (source-only; not included). The v9 manifest records baseline raw disk hash `{v9['source_base_disk_sha256']}` both before and after patch preparation. No source firmware or baseline disk was modified. No SELinux or dm-verity policy was relaxed. The v8-derived test ramdisk keeps the documented targeted vendor AVB fstab exception; v9 does not change that ramdisk.

## Firmware and Task A findings

- The supplied magic-byte detector identifies `system_a` and `vendor_a` as EROFS and `super.img` as Android sparse. Reading `odm_a` through the sparse logical-partition view identifies it as one linear EROFS extent: sector `{task_a['odm_a_layout']['first_extent_sector']}`, `{task_a['odm_a_layout']['extent_sectors']}` sectors, `{task_a['odm_a_layout']['logical_bytes']}` bytes.
- 153 requested small configuration files were extracted read-only. `/vendor/etc/vintf/manifest.xml` is absent; VINTF declarations are in fragments under `/vendor/etc/vintf/manifest/`.
- Those fragments declare `IKeyMintDevice/default`, `IBootControl/default`, and `IQSEECom`. ODM separately declares `IKeyMintDevice/strongbox` and includes its NXP service rc. The existence of declarations does not prove those services start or function under QEMU.
- The addendum's earlier statement that those declarations were absent is superseded by the extraction evidence in this bundle.

## Run history and evidence

- **v6:** five keystore2 SIGABRT exits (PIDs 329, 392, 432, 457, 492); init then performed the critical-process reboot. The serial log does not contain the keystore2 panic message.
- **v7:** init rejected the private `init.svc.keystore2` property trigger as unexported. This invalidates that diagnostic attempt.
- **v8:** five keystore2 SIGABRT exits (PIDs 330, 392, 433, 458, 496). The attempted `init.svc_debug.no_fatal.keystore2` property write from `u:r:vendor_init:s0` to `default_prop` was denied by SELinux. The post-fs-data logcat hook has no start record. The stock log does not contain a successful `restorecon /data` line; timing alone is not proof that it ran.
- **v9:** diagnostic-only change: start the logcat service from vendor `on init`, before keystore2. That action ran, but SELinux denied init's `{{getattr}}` access to `/system/bin/logcat` (exact raw AVC is in the full log). No policy was loosened. Five keystore2 SIGABRT exits were observed (PIDs 332, 392, 432, 463, 502); init rebooted at about 190.4 s guest time and QEMU exited with code 0 before the 1800 s timeout.

## v9 result and remaining unknowns

{audit_text}

The v9 log also records stock `restorecon /data/misc /data/misc/keystore ... succeeded` at 157.702 s, but it does not provide the keystore2 panic text. The single v9 logcat start attempt failed with this denial: {avc}

The failure is still not distinguished between a keystore database/label problem and a missing or nonfunctional KeyMint service. Do not replace KeyMint or alter labels/policy until a diagnostic captures the panic or another direct proof identifies the cause. No Zygote, System Server, or `sys.boot_completed` evidence appears in v6–v9.

Run configuration: QEMU AArch64 `virt`, CPU `{run['cpu_model']}`, `{run['vcpus']}` vCPUs, `{run['ram_gib']}` GiB guest RAM, 16 GiB test disk, NVMe, POCO QEMU DTB, timeout `{run['timeout_seconds']}` seconds. The host had about 0.81 GiB free physical memory at launch, so this attempt used 3 GiB instead of the 4 GiB target to reduce memory pressure.

## v9 versus v8 image diff

- Effective patch payloads that differ: {changed}. Both are pieces of the same `/vendor/etc/init/hw/init.target.rc` replacement (inode metadata block and RC data block); the EROFS superblock CRC and eight-block allocation are unchanged.
- The v9 and v8 first-stage ramdisk files are byte-identical; v9 reuses the v8 fstab metadata timestamp.
- The v9 overlay's other vendor payload hashes and source base-disk hash match v8. See `configs/v9-v8-effective-diff.json` and both manifests.

## Source documents

`reviewer-supplied/HANDOFF-ADDENDUM-v9-latest.md` is the latest reviewer addendum; it supersedes the earlier addendum where they conflict. `previous-handoff/AI-REQUEST.md` is the handoff included for the prior reviewer. The two v9 builder scripts are retained separately: the reviewer-supplied file as received and the local builder used for the validated v9 image.

`SHA256SUMS.txt` contains hashes for every other file in this ZIP plus source-only firmware/super/disk hashes. It does not hash itself because a file cannot contain its own stable checksum.
"""


def main() -> None:
    if OUT.exists() or STAGE.exists():
        raise SystemExit(f"Refusing to overwrite existing output: {OUT} or {STAGE}")
    if not V9_SERIAL_PATH.is_file() or V9_SERIAL_PATH.stat().st_size == 0:
        raise FileNotFoundError("The complete raw v9 serial log is missing or empty")
    if not TASK_A.is_dir():
        raise FileNotFoundError(TASK_A)
    STAGE.mkdir(parents=True)

    v8 = json.loads(V8_MANIFEST_PATH.read_text(encoding="utf-8"))
    v9 = json.loads(V9_MANIFEST_PATH.read_text(encoding="utf-8"))
    run = json.loads(V9_RUN_PATH.read_text(encoding="utf-8-sig"))
    task_a = json.loads((TASK_A / "extraction-manifest.json").read_text(encoding="utf-8"))

    changed_payloads = [
        name for name, digest in v9["patch_payload_sha256"].items()
        if v8["patch_payload_sha256"].get(name) != digest
    ]
    expected_payloads = ["vendor_init_target_inode_block", "vendor_init_target_data"]
    if changed_payloads != expected_payloads:
        raise ValueError(f"Unexpected v8-v9 payload diff: {changed_payloads}")
    if v8["ramdisk_output_sha256"] != v9["ramdisk_output_sha256"]:
        raise ValueError("v8 and v9 first-stage ramdisks are not byte-identical")
    if v8["source_base_disk_sha256"] != v9["source_base_disk_sha256"]:
        raise ValueError("v8 and v9 do not use the same baseline disk hash")
    if v8["erofs_superblock_crc32c_after"] != v9["erofs_superblock_crc32c_after"]:
        raise ValueError("EROFS superblock CRC differs between v8 and v9")

    diff = {
        "versions": ["v8", "v9"],
        "changed_patch_payloads": changed_payloads,
        "both_payloads_belong_to": "/vendor/etc/init/hw/init.target.rc",
        "v8_init_target_rc_sha256": v8["vendor_init_target_rc_modified_sha256"],
        "v9_init_target_rc_sha256": v9["vendor_init_target_rc_modified_sha256"],
        "v8_init_target_rc_bytes": v8["vendor_init_target_rc_modified_size"],
        "v9_init_target_rc_bytes": v9["vendor_init_target_rc_modified_size"],
        "v8_init_target_rc_blocks": v8["vendor_init_target_rc_data_block_count"],
        "v9_init_target_rc_blocks": v9["vendor_init_target_rc_data_block_count"],
        "erofs_superblock_crc32c_v8": v8["erofs_superblock_crc32c_after"],
        "erofs_superblock_crc32c_v9": v9["erofs_superblock_crc32c_after"],
        "ramdisk_sha256_v8": v8["ramdisk_output_sha256"],
        "ramdisk_sha256_v9": v9["ramdisk_output_sha256"],
        "baseline_raw_disk_sha256_v8": v8["source_base_disk_sha256"],
        "baseline_raw_disk_sha256_v9": v9["source_base_disk_sha256"],
        "all_other_patch_payloads_identical": True,
    }

    # Full raw serial logs and run/patch manifests for v6-v9.
    run_specs = (
        ("v6", "qemu-avb-20261105-165007", "qemu-vendor-modprobe-test-v6.json"),
        ("v7", "qemu-avb-20261105-173422", "qemu-vendor-modprobe-test-v7.json"),
        ("v8", "qemu-avb-20261105-174001", "qemu-vendor-modprobe-test-v8.json"),
        ("v9", "qemu-avb-20261105-185241", "qemu-vendor-modprobe-test-v9-final.json"),
    )
    for version, stem, manifest_name in run_specs:
        common.put_file(ANALYSIS / f"{stem}.serial.log", f"logs/{version}-serial-full-raw.log")
        common.put_file(ANALYSIS / f"{stem}.json", f"configs/{version}-qemu-run.json")
        common.put_file(ANALYSIS / manifest_name, f"configs/{version}-patch-manifest.json")
    common.put_bytes(json.dumps(diff, indent=2).encode("utf-8") + b"\n", "configs/v9-v8-effective-diff.json")

    # Full patch builders and the exact RC/shell payload constants used by each version.
    for version, filename in (
        ("v6", "make_qemu_vendor_modprobe_patch.py"),
        ("v7", "make_qemu_vendor_modprobe_patch_v7.py"),
        ("v8", "make_qemu_vendor_modprobe_patch_v8.py"),
        ("v9", "make_qemu_vendor_modprobe_patch_v9.py"),
    ):
        extract_script_and_fragments(version, filename)
    for filename in (
        "make_qemu_vendor_barrier_patch.py",
        "make_qemu_stage2_fstab.py",
        "run_qemu_trace.ps1",
        "extract_task_a_files.py",
        "package_review_bundle_v9_taskA.py",
    ):
        common.put_file(TOOLS / filename, f"scripts/support/{filename}")
    common.put_file(Path(r"C:\Users\msi\Downloads\make_qemu_vendor_modprobe_patch_v9.py"), "reviewer-supplied/make_qemu_vendor_modprobe_patch_v9.py")
    common.put_file(Path(r"C:\Users\msi\Downloads\extract_task_a.py"), "reviewer-supplied/extract_task_a.py")
    common.put_file(Path(r"C:\Users\msi\Downloads\HANDOFF-ADDENDUM-v9 (2).md"), "reviewer-supplied/HANDOFF-ADDENDUM-v9-latest.md")
    earlier_addendum = Path(r"C:\Users\msi\Downloads\HANDOFF-ADDENDUM-v9.md")
    if earlier_addendum.is_file():
        common.put_file(earlier_addendum, "reviewer-supplied/HANDOFF-ADDENDUM-v9-before-revision.md")
    common.put_file(REPORTS / "ai-consultation-2026-11-05-v1" / "AI-REQUEST.md", "previous-handoff/AI-REQUEST.md")

    # Small text-only firmware extracts from system_a, vendor_a, and logical odm_a.
    put_tree(TASK_A, "extracted/task-a")
    common.put_file(ANALYSIS / "kernel.config", "extracted/kernel.config")
    common.put_file(ANALYSIS / "etc__init__hw__init.qti.kernel.rc.extracted", "extracted/vendor/etc/init/hw/init.qti.kernel.rc")
    common.put_file(ANALYSIS / "etc__init__hw__init.target.rc.extracted", "extracted/vendor/etc/init/hw/init.target.rc.analysis-source")

    # Latest v9-effective small text payloads, trimmed to the EROFS inode sizes.
    text_payload("qemu-vendor-contexts-data-v9-final.bin", v9["vendor_contexts_modified_size"], "extracted/vendor/etc/selinux/vendor_file_contexts.v9-patched")
    text_payload("qemu-vendor-fstab-data-v9-final.bin", v9["vendor_fstab_modified_size"], "extracted/vendor/etc/fstab.qcom.v9-patched")
    text_payload("qemu-vendor-init-target-data-v9-final.bin", v9["vendor_init_target_rc_modified_size"], "extracted/vendor/etc/init/hw/init.target.rc.v9-patched")
    common.put_bytes(common.cpio_entry(ANALYSIS / "qemu-virt-stage2-ramdisk.cpio", "first_stage_ramdisk/fstab.qcom"), "extracted/first_stage_ramdisk/fstab.qcom.original")
    common.put_bytes(common.cpio_entry(ANALYSIS / "qemu-virt-vendor-modprobe-test-ramdisk-v8.cpio", "first_stage_ramdisk/fstab.qcom"), "extracted/first_stage_ramdisk/fstab.qcom.v8-patched")
    common.put_bytes(common.cpio_entry(ANALYSIS / "qemu-virt-vendor-modprobe-test-ramdisk-v9-final.cpio", "first_stage_ramdisk/fstab.qcom"), "extracted/first_stage_ramdisk/fstab.qcom.v9-patched")

    extraction_status = (
        "system_a, vendor_a: EROFS dari raw logical partition image.\n"
        "super.img sumber: Android sparse (magic 3aff26ed).\n"
        f"odm_a: {task_a['odm_a_layout']['filesystem']}, satu extent linear, "
        f"{task_a['odm_a_layout']['logical_bytes']} byte; dibaca lewat logical sparse view tanpa materialisasi image.\n"
        f"File kecil yang diekstrak: {sum(item['result'] == 'extracted' for item in task_a['files'])}.\n"
        "/vendor/etc/vintf/manifest.xml tidak ada; deklarasi vendor berada di fragment manifest.\n"
        "Teks hasil ekstraksi bersifat read-only; NUL/non-UTF-8 tidak disertakan.\n"
    )
    common.put_bytes(extraction_status.encode("utf-8"), "EXTRACTION-STATUS.txt")
    notes = build_notes(v8, v9, run, task_a, diff)
    common.put_bytes(notes.encode("utf-8"), "NOTES.md")
    (REPORTS / "NOTES.md").write_text(notes, encoding="utf-8", newline="\n")

    source_hashes = [
        f"{FIRMWARE_SHA256}  SOURCE-ONLY  {FIRMWARE.name}",
        f"{v9['source_super_sha256']}  SOURCE-ONLY  super.img",
        f"{v9['source_vendor_sha256']}  SOURCE-ONLY  vendor_a-from-super.img",
        f"{v9['source_base_disk_sha256']}  SOURCE-ONLY  hyperos-virt-test-16g-qemu-placeholders.raw",
    ]
    sums = list(source_hashes)
    for path in sorted(item for item in STAGE.rglob("*") if item.is_file()):
        if path.name == "SHA256SUMS.txt":
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        sums.append(f"{digest}  {path.relative_to(STAGE).as_posix()}")
    common.put_bytes(("\n".join(sums) + "\n").encode("utf-8"), "SHA256SUMS.txt")

    forbidden = {".tgz", ".img", ".qcow2", ".raw", ".cpio", ".bin", ".pyd", ".dll", ".so"}
    with zipfile.ZipFile(OUT, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(item for item in STAGE.rglob("*") if item.is_file()):
            relative = path.relative_to(STAGE).as_posix()
            if Path(relative).suffix.lower() in forbidden:
                raise ValueError(f"Forbidden binary/image file in bundle: {relative}")
            archive.write(path, relative)
    if OUT.stat().st_size >= 25 * 1024 * 1024:
        raise ValueError(f"ZIP exceeds 25 MiB: {OUT.stat().st_size}")

    # Verify every listed archive entry and reject unlisted or binary payloads.
    with zipfile.ZipFile(OUT, "r") as archive:
        names = set(archive.namelist())
        sums_text = archive.read("SHA256SUMS.txt").decode("utf-8")
        listed: set[str] = set()
        for line in sums_text.splitlines():
            digest, label = line.split("  ", 1)
            if label.startswith("SOURCE-ONLY  "):
                continue
            payload = archive.read(label)
            if hashlib.sha256(payload).hexdigest() != digest:
                raise ValueError(f"Checksum mismatch: {label}")
            listed.add(label)
            if Path(label).suffix.lower() in forbidden:
                raise ValueError(f"Forbidden file in archive: {label}")
        if listed != names - {"SHA256SUMS.txt"}:
            raise ValueError("SHA256SUMS file list does not exactly cover the archive payloads")
    print(json.dumps({"zip": str(OUT), "bytes": OUT.stat().st_size, "files": len(names), "sha256": hashlib.sha256(OUT.read_bytes()).hexdigest()}, indent=2))


if __name__ == "__main__":
    main()
