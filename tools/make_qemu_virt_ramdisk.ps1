param(
    [string]$InitCpio = (Join-Path $PSScriptRoot '..\analysis\init_boot-ramdisk-decoded.cpio'),
    [string]$VendorCpio = (Join-Path $PSScriptRoot '..\analysis\vendor_boot-ramdisk-decoded.cpio'),
    [string]$OutputCpio = (Join-Path $PSScriptRoot '..\analysis\qemu-virt-no-gunyah-ramdisk.cpio'),
    [switch]$SkipAllVendorModules
)
$ErrorActionPreference = 'Stop'
function Align4([int64]$n) { return $n + ((4 - ($n % 4)) % 4) }
function Copy-CpioArchive([string]$InputPath, [IO.Stream]$Destination, [bool]$FilterGunyah, [bool]$SkipModules) {
    $bytes = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $InputPath))
    $pos = [int64]0
    $changed = $false
    while ($pos + 110 -le $bytes.Length) {
        $magic = [Text.Encoding]::ASCII.GetString($bytes, [int]$pos, 6)
        if ($magic -notin @('070701','070702')) { throw "Invalid newc CPIO magic at offset $pos in $InputPath" }
        $oldSize = [Convert]::ToInt64([Text.Encoding]::ASCII.GetString($bytes, [int]($pos+54), 8), 16)
        $nameSize = [Convert]::ToInt32([Text.Encoding]::ASCII.GetString($bytes, [int]($pos+94), 8), 16)
        $name = [Text.Encoding]::UTF8.GetString($bytes, [int]($pos+110), $nameSize-1)
        $nameStart = [int]($pos+110)
        $dataStart = [int](Align4 ($pos+110+$nameSize))
        if ($dataStart + $oldSize -gt $bytes.Length) { throw "Truncated CPIO payload for $name" }
        if ($name -eq 'TRAILER!!!') { break }
        $payload = [byte[]]::new([int]$oldSize)
        if ($oldSize -gt 0) { [Array]::Copy($bytes, $dataStart, $payload, 0, [int]$oldSize) }
        $replacement = $null
        if ($FilterGunyah -and $name -eq 'lib/modules/modules.load') {
            $lines = [regex]::Split([Text.Encoding]::UTF8.GetString($payload), '[\r\n]+')
            if ($SkipModules) { $filtered = @() }
            else { $filtered = @($lines | Where-Object { $_ -and $_ -notmatch '^(gh_.*|gunyah.*|qrtr-gunyah\.ko)$' }) }
            $replacement = [Text.Encoding]::UTF8.GetBytes(($filtered -join [string][char]10) + [char]10)
        } elseif ($FilterGunyah -and $name -eq 'first_stage_ramdisk/fstab.qcom') {
            $lines = [regex]::Split([Text.Encoding]::UTF8.GetString($payload), '[\r\n]+')
            $filtered = @($lines | Where-Object { $_ -notmatch '^/dev/block/by-name/metadata\s' })
            if ($filtered.Count -eq $lines.Count) { throw 'Expected metadata first-stage fstab entry was not found.' }
            $replacement = [Text.Encoding]::UTF8.GetBytes(($filtered -join [string][char]10) + [char]10)
        }
        if ($null -ne $replacement) {
            $payload = $replacement
            $header = [byte[]]::new(110)
            [Array]::Copy($bytes, [int]$pos, $header, 0, 110)
            [Array]::Copy([Text.Encoding]::ASCII.GetBytes($payload.Length.ToString('x8')), 0, $header, 54, 8)
            $Destination.Write($header, 0, $header.Length)
            $changed = $true
        } else {
            $Destination.Write($bytes, [int]$pos, 110)
        }
        $Destination.Write($bytes, $nameStart, $nameSize)
        while ($Destination.Position % 4 -ne 0) { $Destination.WriteByte(0) }
        if ($payload.Length -gt 0) { $Destination.Write($payload, 0, $payload.Length) }
        while ($Destination.Position % 4 -ne 0) { $Destination.WriteByte(0) }
        $pos = [int64](Align4 ($dataStart + $oldSize))
    }
    $header = [byte[]]::new(110)
    [Array]::Copy([Text.Encoding]::ASCII.GetBytes('070701'),0,$header,0,6)
    [Array]::Copy([Text.Encoding]::ASCII.GetBytes('00000001'),0,$header,38,8)
    [Array]::Copy([Text.Encoding]::ASCII.GetBytes('0000000b'),0,$header,94,8)
    $Destination.Write($header,0,$header.Length)
    $name = [Text.Encoding]::ASCII.GetBytes("TRAILER!!!$([char]0)")
    $Destination.Write($name,0,$name.Length)
    while ($Destination.Position % 4 -ne 0) { $Destination.WriteByte(0) }
    return $changed
}
$outPath = [IO.Path]::GetFullPath($OutputCpio)
$stream = [IO.File]::Open($outPath,[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::None)
try {
    Copy-CpioArchive $InitCpio $stream $false $false | Out-Null
    $modified = Copy-CpioArchive $VendorCpio $stream $true ([bool]$SkipAllVendorModules)
} finally { $stream.Dispose() }
if (-not $modified) { throw 'Expected lib/modules/modules.load was not found; output is not valid for this experiment.' }
Get-FileHash -LiteralPath $OutputCpio -Algorithm SHA256 | Select-Object Path,Hash
Get-Item -LiteralPath $OutputCpio | Select-Object FullName,Length

