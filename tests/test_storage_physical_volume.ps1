#Requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$GuardExe)
$ErrorActionPreference='Stop'
# An opt-in integration fixture: only this new 64 MiB VHD is formatted/filled.
# Never run the allocation on the system volume or on an existing image.
$root=Join-Path $env:TEMP ('edr-physical-volume-'+[guid]::NewGuid().ToString('N'))
$mount=Join-Path $root 'mount'
$vhd=Join-Path $root 'synthetic.vhd'
$null=New-Item -ItemType Directory -Path $mount
$attached=$false
$passed=$false
try {
 if(Test-Path -LiteralPath $vhd){throw 'fixture image already exists'}
 $script=Join-Path $root 'create.txt'
 [IO.File]::WriteAllText($script,"create vdisk file=`"$vhd`" maximum=64 type=expandable`r`nselect vdisk file=`"$vhd`"`r`nattach vdisk`r`nexit`r`n",[Text.Encoding]::ASCII)
 $p=Start-Process diskpart.exe -ArgumentList @('/s',('"'+$script+'"')) -PassThru -WindowStyle Hidden
 try{if(-not $p.WaitForExit(30000)){$p.Kill();throw 'fixture VHD creation timeout'};$p.Refresh();if($p.ExitCode){throw 'fixture VHD creation failed'}}finally{$p.Dispose()}
 $image=Get-DiskImage -ImagePath $vhd -ErrorAction Stop
 if(-not $image.Attached){throw 'new fixture image did not attach'}
 $attached=$true
 $disk=$image | Get-Disk
 if(@($disk).Count-ne 1 -or $disk.Size-gt 64MB -or $disk.PartitionStyle-ne 'RAW'){throw 'unexpected new fixture disk identity'}
 $null=$disk | Initialize-Disk -PartitionStyle GPT -PassThru
 $partition=New-Partition -DiskNumber $disk.Number -UseMaximumSize
 $volume=$partition | Format-Volume -FileSystem NTFS -NewFileSystemLabel 'EDR_SYNTHETIC_SPACE' -Confirm:$false
 $partition | Add-PartitionAccessPath -AccessPath ($mount+'\')
 if((Get-Volume -FilePath ($mount+'\')).FileSystemLabel-ne 'EDR_SYNTHETIC_SPACE'){throw 'fixture mount identity mismatch'}
 Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public static class EdrFixtureVolume{[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]public static extern bool GetDiskFreeSpaceExW(string path,out ulong available,out ulong total,out ulong free);}'
 function Available {
  [UInt64]$a=0;[UInt64]$t=0;[UInt64]$f=0
  if(-not [EdrFixtureVolume]::GetDiskFreeSpaceExW(($mount+'\'),[ref]$a,[ref]$t,[ref]$f)-or $t-gt 64MB){throw 'fixture volume measurement failed'}
  return $a
 }
 $file=Join-Path $mount 'bounded-fill.bin'
 $fill=[IO.File]::Open($file,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try {
  $bytes=New-Object byte[] 65536
  while((Available)-gt 2MB){$fill.Write($bytes,0,$bytes.Length);if($fill.Length-gt 64MB){throw 'fixture fill exceeded image size'}}
  $fill.Flush($true)
 }finally{$fill.Dispose()}
 & $GuardExe --test-volume (Join-Path $mount 'guard.db') full
 if($LASTEXITCODE-ne 0){throw 'native low-space admission contract failed'}
 $diskFull=$false
 $fill=[IO.File]::Open($file,[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try {
  for($i=0;$i-lt 96;$i++){$fill.Write($bytes,0,$bytes.Length);$fill.Flush($true)}
 }catch [IO.IOException]{
  $native=$_.Exception.HResult-band 0xffff
  if($native-ne 112 -and $native-ne 39){throw}
  $diskFull=$true
 }finally{$fill.Dispose()}
 if(-not $diskFull){throw 'isolated volume did not report real disk full'}
 Remove-Item -LiteralPath $file -Force
 & $GuardExe --test-volume (Join-Path $mount 'guard.db') recovered
 if($LASTEXITCODE-ne 0){throw 'native admission did not recover'}
 [ordered]@{test='isolated_ntfs_volume';maximum_image_bytes=64MB;real_disk_full=$diskFull;system_volume_filled=$false;real_agent_cache_touched=$false}|ConvertTo-Json -Compress
 $passed=$true
}finally{
 if($attached){Dismount-DiskImage -ImagePath $vhd -ErrorAction Stop | Out-Null}
 if($passed){Remove-Item -LiteralPath $root -Recurse -Force}else{Write-Warning "Synthetic fixture retained at $root"}
}
