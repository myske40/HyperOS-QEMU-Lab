param(
    [string]$SourceRoot = (Join-Path $PSScriptRoot '..\analysis\source-partitions'),
    [string]$OutputDisk = (Join-Path $PSScriptRoot '..\analysis\hyperos-virt-test-16g.raw'),
    [switch]$AddQemuPlaceholderPartitions
)
$ErrorActionPreference = 'Stop'
function Align-Lba([long]$lba) { return [long]([Math]::Ceiling($lba / 2048.0) * 2048) }
function Crc32([byte[]]$data) {
    [long]$crc = 4294967295
    foreach ($value in $data) {
        $crc = $crc -bxor [long]$value
        for ($i=0; $i -lt 8; $i++) {
            if (($crc -band 1) -ne 0) { $crc = ($crc -shr 1) -bxor 3988292384L }
            else { $crc = $crc -shr 1 }
        }
    }
    return [uint32]($crc -bxor 4294967295L)
}
function Put-Bytes([byte[]]$buffer,[int]$offset,[byte[]]$value) { [Array]::Copy($value,0,$buffer,$offset,$value.Length) }
function Put-UInt32([byte[]]$buffer,[int]$offset,[uint32]$value) { Put-Bytes $buffer $offset ([BitConverter]::GetBytes($value)) }
function Put-UInt64([byte[]]$buffer,[int]$offset,[uint64]$value) { Put-Bytes $buffer $offset ([BitConverter]::GetBytes($value)) }
function Copy-FileInto([IO.FileStream]$disk,[string]$source,[long]$offset) {
    $inputStream=[IO.File]::OpenRead($source)
    try {
        $disk.Position=$offset
        $buffer=[byte[]]::new(1048576)
        while (($read=$inputStream.Read($buffer,0,$buffer.Length)) -gt 0) {
            $allZero=$true
            for($i=0;$i -lt $read;$i++){if($buffer[$i] -ne 0){$allZero=$false;break}}
            if($allZero){$disk.Seek($read,[IO.SeekOrigin]::Current)|Out-Null}
            else{$disk.Write($buffer,0,$read)}
        }
    } finally {$inputStream.Dispose()}
}
function Expand-AndroidSparseInto([IO.FileStream]$disk,[string]$source,[long]$offset,[long]$expectedSize) {
    $inputStream=[IO.File]::OpenRead($source)
    $reader=[IO.BinaryReader]::new($inputStream)
    try {
        $magic=$reader.ReadUInt32()
        if(('{0:x8}' -f $magic) -ne 'ed26ff3a'){throw "super.img is not Android sparse (magic 0x$($magic.ToString('x8')))"}
        $major=$reader.ReadUInt16();$minor=$reader.ReadUInt16()
        $fileHeaderSize=$reader.ReadUInt16();$chunkHeaderSize=$reader.ReadUInt16()
        $blockSize=$reader.ReadUInt32();$totalBlocks=$reader.ReadUInt32();$totalChunks=$reader.ReadUInt32();$imageCrc=$reader.ReadUInt32()
        $expanded=[long]$blockSize*$totalBlocks
        if($expanded -ne $expectedSize){throw "Sparse expanded size $expanded differs from expected $expectedSize"}
        if($fileHeaderSize -gt 28){$inputStream.Seek($fileHeaderSize-28,[IO.SeekOrigin]::Current)|Out-Null}
        $disk.Position=$offset
        $rawBuffer=[byte[]]::new(1048576)
        for($chunk=0;$chunk -lt $totalChunks;$chunk++){
            $type=$reader.ReadUInt16();$null=$reader.ReadUInt16();$chunkBlocks=$reader.ReadUInt32();$totalSize=$reader.ReadUInt32()
            $chunkBytes=[long]$chunkBlocks*$blockSize
            switch($type){
                0xcac1 {
                    $remaining=$chunkBytes
                    while($remaining -gt 0){
                        $take=[int][Math]::Min($rawBuffer.Length,$remaining)
                        $read=$inputStream.Read($rawBuffer,0,$take)
                        if($read -ne $take){throw 'Truncated RAW sparse chunk'}
                        $allZero=$true
                        for($i=0;$i -lt $read;$i++){if($rawBuffer[$i] -ne 0){$allZero=$false;break}}
                        if($allZero){$disk.Seek($read,[IO.SeekOrigin]::Current)|Out-Null}
                        else{$disk.Write($rawBuffer,0,$read)}
                        $remaining-=$read
                    }
                }
                0xcac2 {
                    $pattern=$reader.ReadBytes(4)
                    $remaining=$chunkBytes
                    while($remaining -gt 0){
                        $take=[int][Math]::Min($rawBuffer.Length,$remaining)
                        for($i=0;$i -lt $take;$i++){$rawBuffer[$i]=$pattern[$i%4]}
                        $disk.Write($rawBuffer,0,$take)
                        $remaining-=$take
                    }
                }
                0xcac3 {$disk.Seek($chunkBytes,[IO.SeekOrigin]::Current)|Out-Null}
                0xcac4 {$null=$reader.ReadUInt32()}
                default {throw "Unknown Android sparse chunk type 0x$($type.ToString('x4'))"}
            }
            $expectedChunkPayload=[long]$totalSize-$chunkHeaderSize
            if($type -eq 0xcac1){$actual=$chunkBytes}
            elseif($type -eq 0xcac2){$actual=4}
            elseif($type -eq 0xcac3){$actual=0}
            else{$actual=4}
            if($expectedChunkPayload -gt $actual){$inputStream.Seek($expectedChunkPayload-$actual,[IO.SeekOrigin]::Current)|Out-Null}
        }
        $end=$disk.Position
        if($end -ne $offset+$expanded){throw "Expanded sparse stream ended at $($end-$offset), expected $expanded"}
        return [pscustomobject]@{Major=$major;Minor=$minor;BlockSize=$blockSize;Blocks=$totalBlocks;Chunks=$totalChunks;ExpandedBytes=$expanded;ImageCrc=('0x{0:x8}' -f $imageCrc)}
    } finally {$reader.Dispose();$inputStream.Dispose()}
}
$images=Get-ChildItem -LiteralPath $SourceRoot -Recurse -File
function Find-Image([string]$name) { $x=@($images|Where-Object Name -eq $name);if($x.Count -ne 1){throw "Expected one $name under $SourceRoot, found $($x.Count)"};return $x[0].FullName }
$specs=@(
    [pscustomobject]@{Name='boot_a';Size=100663296;File=(Find-Image 'boot.img');Start=0;End=0;Sectors=0;AllocatedSize=0},
    [pscustomobject]@{Name='init_boot_a';Size=8388608;File=(Find-Image 'init_boot.img');Start=0;End=0;Sectors=0;AllocatedSize=0},
    [pscustomobject]@{Name='vendor_boot_a';Size=100663296;File=(Find-Image 'vendor_boot.img');Start=0;End=0;Sectors=0;AllocatedSize=0},
    [pscustomobject]@{Name='dtbo_a';Size=20971520;File=(Find-Image 'dtbo.img');Start=0;End=0;Sectors=0;AllocatedSize=0},
    [pscustomobject]@{Name='recovery_a';Size=104857600;File=(Find-Image 'recovery.img');Start=0;End=0;Sectors=0;AllocatedSize=0},
    [pscustomobject]@{Name='metadata';Size=67108864;File=(Find-Image 'metadata.img');Start=0;End=0;Sectors=0;AllocatedSize=0},
    [pscustomobject]@{Name='vbmeta_a';Size=1048576;File=(Find-Image 'vbmeta.img');Start=0;End=0;Sectors=0;AllocatedSize=0},
    [pscustomobject]@{Name='vbmeta_system_a';Size=1048576;File=(Find-Image 'vbmeta_system.img');Start=0;End=0;Sectors=0;AllocatedSize=0},
    [pscustomobject]@{Name='super';Size=9126805504;File=(Find-Image 'super.img');Start=0;End=0;Sectors=0;AllocatedSize=0}
)
if($AddQemuPlaceholderPartitions){
    # Empty block devices let stock fstab resolve its physical partition names
    # under QEMU. Their contents remain zero; no modem, DSP, Bluetooth, or
    # vendor firmware is synthesized.
    $specs+=@(
        [pscustomobject]@{Name='persist';Size=67108864;File=$null;Start=0;End=0;Sectors=0;AllocatedSize=0},
        [pscustomobject]@{Name='misc';Size=4194304;File=$null;Start=0;End=0;Sectors=0;AllocatedSize=0},
        [pscustomobject]@{Name='modem_a';Size=67108864;File=$null;Start=0;End=0;Sectors=0;AllocatedSize=0},
        [pscustomobject]@{Name='modemfirmware_a';Size=67108864;File=$null;Start=0;End=0;Sectors=0;AllocatedSize=0},
        [pscustomobject]@{Name='dsp_a';Size=67108864;File=$null;Start=0;End=0;Sectors=0;AllocatedSize=0},
        [pscustomobject]@{Name='bluetooth_a';Size=67108864;File=$null;Start=0;End=0;Sectors=0;AllocatedSize=0},
        [pscustomobject]@{Name='qmcs';Size=67108864;File=$null;Start=0;End=0;Sectors=0;AllocatedSize=0},
        [pscustomobject]@{Name='spunvm';Size=67108864;File=$null;Start=0;End=0;Sectors=0;AllocatedSize=0}
    )
}
$diskBytes=16L*1024*1024*1024
$totalLbas=[long]($diskBytes/512)
$lastLba=$totalLbas-1
$lastUsable=$totalLbas-34
$cursor=[long]2048
foreach($part in $specs){
    $part.Start=Align-Lba $cursor
    $part.AllocatedSize=[long]([Math]::Ceiling($part.Size/1048576.0)*1048576)
    $part.Sectors=[long]($part.AllocatedSize/512)
    $part.End=$part.Start+$part.Sectors-1
    $cursor=$part.End+1
}
$userdataStart=Align-Lba $cursor
$specs+= [pscustomobject]@{Name='userdata';Size=($lastUsable-$userdataStart+1)*512;AllocatedSize=($lastUsable-$userdataStart+1)*512;Start=$userdataStart;Sectors=$lastUsable-$userdataStart+1;End=$lastUsable;File=$null}
if($specs[-1].Size -le 0){throw 'No room remains for userdata'}
$diskPath=[IO.Path]::GetFullPath($OutputDisk)
if(Test-Path -LiteralPath $diskPath){throw "Output already exists; refusing to overwrite: $diskPath"}
[IO.File]::WriteAllBytes($diskPath,[byte[]]::new(0))
& fsutil.exe sparse setflag $diskPath | Out-Null
if($LASTEXITCODE -ne 0){throw 'Could not mark test disk sparse'}
$disk=[IO.File]::Open($diskPath,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
try {
    $disk.SetLength($diskBytes)
    $entries=[byte[]]::new(128*128)
    $typeGuid=[Guid]::Parse('0fc63daf-8483-4772-8e79-3d69d8477de4').ToByteArray()
    $diskGuid=[Guid]::NewGuid().ToByteArray()
    for($i=0;$i -lt $specs.Count;$i++){
        $part=$specs[$i];$entryOffset=$i*128
        Put-Bytes $entries $entryOffset $typeGuid
        Put-Bytes $entries ($entryOffset+16) ([Guid]::NewGuid().ToByteArray())
        Put-UInt64 $entries ($entryOffset+32) ([uint64]$part.Start)
        Put-UInt64 $entries ($entryOffset+40) ([uint64]$part.End)
        Put-UInt64 $entries ($entryOffset+48) ([uint64]0)
        Put-Bytes $entries ($entryOffset+56) ([Text.Encoding]::Unicode.GetBytes($part.Name))
        if($part.File){
            $imageStream=[IO.File]::OpenRead($part.File)
            $imageHeader=[byte[]]::new(28)
            $headerBytes=$imageStream.Read($imageHeader,0,$imageHeader.Length)
            $imageStream.Dispose()
            $isSparse=($headerBytes -ge 4 -and ('{0:x8}' -f [BitConverter]::ToUInt32($imageHeader,0)) -eq 'ed26ff3a')
            if($part.Name -eq 'super'){$sparseInfo=Expand-AndroidSparseInto $disk $part.File ([long]$part.Start*512) $part.Size}
            elseif($isSparse){
                $expandedBytes=[long][BitConverter]::ToUInt32($imageHeader,12)*[BitConverter]::ToUInt32($imageHeader,16)
                if($expandedBytes -gt $part.Size){throw "Sparse image $($part.Name) expands to $expandedBytes bytes, exceeding partition size $($part.Size)"}
                $null=Expand-AndroidSparseInto $disk $part.File ([long]$part.Start*512) $expandedBytes
            }
            else{Copy-FileInto $disk $part.File ([long]$part.Start*512)}
        }
    }
    $entryCrc=Crc32 $entries
    $mbr=[byte[]]::new(512);$mbr[446]=0;$mbr[447]=0;$mbr[448]=2;$mbr[449]=0;$mbr[450]=0xee;$mbr[451]=0xff;$mbr[452]=0xff;$mbr[453]=0xff
    Put-UInt32 $mbr 454 ([uint32]1);Put-UInt32 $mbr 458 ([uint32][Math]::Min($totalLbas-1,[uint64]4294967295));$mbr[510]=0x55;$mbr[511]=0xaa
    $disk.Position=0;$disk.Write($mbr,0,$mbr.Length)
    $primary=[byte[]]::new(512);Put-Bytes $primary 0 ([Text.Encoding]::ASCII.GetBytes('EFI PART'))
    Put-UInt32 $primary 8 ([uint32]0x00010000);Put-UInt32 $primary 12 ([uint32]92)
    Put-UInt64 $primary 24 ([uint64]1);Put-UInt64 $primary 32 ([uint64]$lastLba)
    Put-UInt64 $primary 40 ([uint64]34);Put-UInt64 $primary 48 ([uint64]$lastUsable)
    Put-Bytes $primary 56 $diskGuid;Put-UInt64 $primary 72 ([uint64]2)
    Put-UInt32 $primary 80 ([uint32]128);Put-UInt32 $primary 84 ([uint32]128);Put-UInt32 $primary 88 $entryCrc
    $headerCopy=[byte[]]::new(92);[Array]::Copy($primary,0,$headerCopy,0,92);Put-UInt32 $headerCopy 16 0
    Put-UInt32 $primary 16 (Crc32 $headerCopy)
    $disk.Position=512;$disk.Write($primary,0,$primary.Length)
    $disk.Position=1024;$disk.Write($entries,0,$entries.Length)
    $backupEntriesLba=$lastLba-32
    $disk.Position=$backupEntriesLba*512;$disk.Write($entries,0,$entries.Length)
    $backup=[byte[]]::new(512);Put-Bytes $backup 0 ([Text.Encoding]::ASCII.GetBytes('EFI PART'))
    Put-UInt32 $backup 8 ([uint32]0x00010000);Put-UInt32 $backup 12 ([uint32]92)
    Put-UInt64 $backup 24 ([uint64]$lastLba);Put-UInt64 $backup 32 ([uint64]1)
    Put-UInt64 $backup 40 ([uint64]34);Put-UInt64 $backup 48 ([uint64]$lastUsable)
    Put-Bytes $backup 56 $diskGuid;Put-UInt64 $backup 72 ([uint64]$backupEntriesLba)
    Put-UInt32 $backup 80 ([uint32]128);Put-UInt32 $backup 84 ([uint32]128);Put-UInt32 $backup 88 $entryCrc
    $backupCopy=[byte[]]::new(92);[Array]::Copy($backup,0,$backupCopy,0,92);Put-UInt32 $backupCopy 16 0
    Put-UInt32 $backup 16 (Crc32 $backupCopy)
    $disk.Position=$lastLba*512;$disk.Write($backup,0,$backup.Length)
    $disk.Flush($true)
} finally {$disk.Dispose()}
$partRows=$specs|Select-Object Name,Start,End,Size,AllocatedSize,File
$partRows | Format-Table -AutoSize
"SPARSE_SUPER=$($sparseInfo|ConvertTo-Json -Compress)"
"OUTPUT=$diskPath"
"SIZE_BYTES=$((Get-Item -LiteralPath $diskPath).Length)"
& fsutil.exe sparse queryflag $diskPath

