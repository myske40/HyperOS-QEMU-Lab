param(
    [int]$MemoryGiB = 1,
    [int]$CpuCount = 2,
    [ValidatePattern('^[A-Za-z0-9_.+-]+(?:,[A-Za-z0-9_.+-]+=[A-Za-z0-9_.+-]+)*$')]
    [string]$CpuModel = 'max',
    [int]$TimeoutSeconds = 20,
    [switch]$LiveSerial,
    [string]$RamdiskPath = (Join-Path $PSScriptRoot '..\analysis\qemu-virt-stage2-ramdisk.cpio'),
    [string]$DtbPath = '',
    [ValidateSet('raw','qcow2')]
    [string]$BaseDiskFormat = 'raw',
    [string]$BaseDiskPath = (Join-Path $PSScriptRoot '..\analysis\hyperos-virt-test-16g.raw'),
    [ValidatePattern('^[A-Za-z0-9._:/-]+$')]
    [string]$BootDevice = '4010000000.pcie',
    [ValidatePattern('^[A-Za-z0-9._:/-]+$')]
    [string]$BootDevices = '4010000000.pcie',
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$Hardware = 'qcom',
    [ValidatePattern('^[A-Za-z0-9_-]+$')]
    [string]$FstabSuffix = 'qcom'
)
$ErrorActionPreference = 'Stop'
$project = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$qemu = Join-Path $project 'tools\qemu\qemu-system-aarch64.exe'
$qemuImg = Join-Path $project 'tools\qemu\qemu-img.exe'
$avbCalculator = Join-Path $project 'tools\calculate_avb_bootconfig.py'
$qemuPython = 'py'
$kernel = Join-Path $project 'analysis\stock-kernel-extracted.bin'
$ramdisk = [IO.Path]::GetFullPath($RamdiskPath)
$dtb = if ([string]::IsNullOrWhiteSpace($DtbPath)) { '' } else { [IO.Path]::GetFullPath($DtbPath) }
$baseDisk = [IO.Path]::GetFullPath($BaseDiskPath)
$analysis = Join-Path $project 'analysis'
foreach ($file in @($qemu, $qemuImg, $avbCalculator, $kernel, $ramdisk, $baseDisk)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing required file: $file" }
}
if ($dtb -and -not (Test-Path -LiteralPath $dtb -PathType Leaf)) { throw "Missing DTB file: $dtb" }
if ($MemoryGiB -lt 1 -or $MemoryGiB -gt 4) { throw 'Use 1–4 GiB RAM.' }
if ($CpuCount -lt 1 -or $CpuCount -gt 4) { throw 'Use 1–4 vCPUs.' }
if ($TimeoutSeconds -lt 5 -or $TimeoutSeconds -gt 1800) { throw 'Timeout must be 5–1800 seconds.' }
$avbJson = & $qemuPython -3 $avbCalculator
if ($LASTEXITCODE -ne 0) { throw "AVB bootconfig calculation failed (exit $LASTEXITCODE)." }
$avb = ($avbJson -join [Environment]::NewLine) | ConvertFrom-Json
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$overlay = Join-Path $analysis "qemu-avb-$stamp.qcow2"
$serialLog = Join-Path $analysis "qemu-avb-$stamp.serial.log"
$stdoutLog = Join-Path $analysis "qemu-avb-$stamp.stdout.log"
$stderrLog = Join-Path $analysis "qemu-avb-$stamp.stderr.log"
$metaPath = Join-Path $analysis "qemu-avb-$stamp.json"
& $qemuImg create -q -f qcow2 -F $BaseDiskFormat -b $baseDisk $overlay
if ($LASTEXITCODE -ne 0) { throw "Could not create disposable overlay (exit $LASTEXITCODE)." }
$append = 'console=ttyAMA0,115200 earlycon=pl011,mmio32,0x9000000 ignore_loglevel loglevel=8 rdinit=/init androidboot.fstab_suffix=' + $FstabSuffix + ' androidboot.hardware=' + $Hardware + ' androidboot.slot_suffix=_a androidboot.bootdevice=' + $BootDevice + ' androidboot.boot_devices=' + $BootDevices + ' androidboot.vbmeta.size=' + $avb.size + ' androidboot.vbmeta.hash_alg=' + $avb.hash_alg + ' androidboot.vbmeta.digest=' + $avb.digest + ' printk.time=1 printk.devkmsg=on log_buf_len=8M trace_buf_size=1M trace_event=sched:sched_process_exec,sched:sched_process_exit tp_printk'
$qArgs = @(
    '-machine', 'virt', '-cpu', $CpuModel, '-m', ($MemoryGiB.ToString() + 'G'), '-smp', "$CpuCount",
    '-kernel', $kernel, '-initrd', $ramdisk
)
if ($dtb) { $qArgs += @('-dtb', $dtb) }
$qArgs += @(
    '-append', $append,
    '-drive', "if=none,id=romdisk,file=$overlay,format=qcow2",
    '-device', 'nvme,drive=romdisk,serial=HYPEROS-QEMU-AVB',
    '-display', 'none', '-monitor', 'none', '-serial', $(if ($LiveSerial) { 'stdio' } else { "file:$serialLog" }),
    '-no-reboot'
)
$psi = [System.Diagnostics.ProcessStartInfo]::new()
$psi.FileName = $qemu
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.RedirectStandardInput = [bool]$LiveSerial
function ConvertTo-WindowsArgument([string]$Value) {
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') { return $Value }
    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append('"')
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq [char]92) { $slashes++; continue }
        if ($character -eq [char]34) {
            [void]$builder.Append(('\' * (2 * $slashes + 1)))
            [void]$builder.Append('"')
            $slashes = 0
            continue
        }
        if ($slashes -gt 0) { [void]$builder.Append(('\' * $slashes)); $slashes = 0 }
        [void]$builder.Append($character)
    }
    if ($slashes -gt 0) { [void]$builder.Append(('\' * (2 * $slashes))) }
    [void]$builder.Append('"')
    return $builder.ToString()
}
$psi.Arguments = (($qArgs | ForEach-Object { ConvertTo-WindowsArgument ([string]$_) }) -join ' ')
$p = [System.Diagnostics.Process]::new()
$p.StartInfo = $psi
if (-not $p.Start()) { throw 'QEMU process failed to start.' }
$errTask = $p.StandardError.ReadToEndAsync()
$timeoutExceeded = $false
$ended = $false
if ($LiveSerial) {
    $serialWriter = [IO.StreamWriter]::new($serialLog, $false, [Text.UTF8Encoding]::new($false))
    $serialWriter.AutoFlush = $true
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $lineTask = $p.StandardOutput.ReadLineAsync()
    while ($true) {
        if ($lineTask.Wait(100)) {
            $line = $lineTask.GetAwaiter().GetResult()
            if ($null -eq $line) { break }
            $serialWriter.WriteLine($line)
            if ($line -match '(?i)(Linux version|Kernel command line|Run /init|init:.*(Parsing file|processing action|restorecon|keystore2|starting service|exited|error|failed|fatal)|make_f2fs|format successful|mount.*(/data|userdata)|F2FS-fs|avc:.*unlabeled|Abort message|Fatal signal|Zygote|SystemServer|sys.boot_completed)') {
                Write-Host $line
            }
            $lineTask = $p.StandardOutput.ReadLineAsync()
        }
        if (-not $p.HasExited -and $watch.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
            $timeoutExceeded = $true
            try { $p.Kill() } catch {}
        }
    }
    $p.WaitForExit()
    $serialWriter.Dispose()
    $ended = (-not $timeoutExceeded -and $p.HasExited)
    $stdout = ''
} else {
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $ended = $p.WaitForExit($TimeoutSeconds * 1000)
    if (-not $ended) {
        $timeoutExceeded = $true
        try { $p.Kill() } catch {}
        $p.WaitForExit()
    }
    $stdout = $outTask.GetAwaiter().GetResult()
}
[IO.File]::WriteAllText($stdoutLog, $stdout)
[IO.File]::WriteAllText($stderrLog, $errTask.GetAwaiter().GetResult())
$meta = [ordered]@{
    timestamp = $stamp
    qemu = $qemu
    ram_gib = $MemoryGiB
    vcpus = $CpuCount
    cpu_model = $CpuModel
    timeout_seconds = $TimeoutSeconds
    fstab_suffix = $FstabSuffix
    hardware = $Hardware
    boot_device = $BootDevice
    boot_devices = $BootDevices
    dtb = if ($dtb) { $dtb } else { $null }
    process_exited_before_timeout = $ended
    exit_code = if ($ended) { $p.ExitCode } else { $null }
    stopped_by_timeout = $timeoutExceeded
    append = $append
    avb_bootconfig = $avb
    arguments = $qArgs
    kernel = $kernel
    ramdisk = $ramdisk
    base_disk = $baseDisk
    base_disk_format = $BaseDiskFormat
    overlay = $overlay
    serial_log = $serialLog
}
$meta | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $metaPath -Encoding utf8
"AVB digest: $($avb.digest) (size $($avb.size) bytes, $($avb.chain_order -join ' -> '))"
"Serial log: $serialLog"
"QEMU stderr: $stderrLog"
"Run metadata: $metaPath"
"Stopped by timeout: $timeoutExceeded"
if (-not $timeoutExceeded -and $p.HasExited) { "QEMU exit code: $($p.ExitCode)" }

