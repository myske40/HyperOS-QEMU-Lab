param(
    [int]$MemoryGiB = 2,
    [int]$CpuCount = 2
)
$ErrorActionPreference = 'Stop'
$project = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$qemu = Join-Path $project 'tools\qemu\qemu-system-aarch64.exe'
$qemuImg = Join-Path $project 'tools\qemu\qemu-img.exe'
$kernel = Join-Path $project 'analysis\stock-kernel-extracted.bin'
$ramdisk = Join-Path $project 'analysis\qemu-virt-stage2-ramdisk.cpio'
$baseDisk = Join-Path $project 'analysis\hyperos-virt-test-16g.raw'
$analysis = Join-Path $project 'analysis'
foreach ($file in @($qemu, $qemuImg, $kernel, $ramdisk, $baseDisk)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing required file: $file" }
}
if ($MemoryGiB -lt 1 -or $MemoryGiB -gt 4) { throw 'Use 1–4 GiB RAM; the Windows host has limited spare memory.' }
if ($CpuCount -lt 1 -or $CpuCount -gt 4) { throw 'Use 1–4 vCPUs for this TCG diagnostic run.' }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$overlay = Join-Path $analysis "qemu-stage2-$stamp.qcow2"
$stdout = Join-Path $analysis "qemu-stage2-$stamp.stdout.log"
& $qemuImg create -q -f qcow2 -F raw -b $baseDisk $overlay
if ($LASTEXITCODE -ne 0) { throw "Could not create a disposable overlay (exit $LASTEXITCODE)." }
$append = 'console=ttyAMA0,115200 earlycon=pl011,mmio32,0x9000000 ignore_loglevel loglevel=8 rdinit=/init androidboot.fstab_suffix=qcom androidboot.hardware=qcom androidboot.slot_suffix=_a androidboot.boot_devices=4010000000.pcie'
$args = @(
    '-machine', 'virt', '-cpu', 'max', '-m', "${MemoryGiB}G", '-smp', "$CpuCount",
    '-kernel', $kernel, '-initrd', $ramdisk, '-append', $append,
    '-drive', "if=none,id=romdisk,file=$overlay,format=qcow2",
    '-device', 'nvme,drive=romdisk,serial=HYPEROS-QEMU-TEST',
    '-display', 'none', '-monitor', 'none', '-serial', "file:$stdout",
    '-no-reboot', '-no-shutdown'
)
"Overlay disk: $overlay"
"Serial log:   $stdout"
"Starting QEMU with $MemoryGiB GiB RAM and $CpuCount vCPU(s)."
& $qemu @args
"QEMU exit code: $LASTEXITCODE"
