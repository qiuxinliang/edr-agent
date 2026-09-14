#Requires -Version 5.1
# Shared file-only transport contract. No credentials, packaging or network I/O.
function Get-ExchangeHash([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Write-ExchangeJson([string]$Path, $Value) {
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 16), [Text.UTF8Encoding]::new($false))
}
function Get-ExchangeFile([string]$Root, [string]$Name) {
    if ($Name -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*$') { throw 'Signing exchange requires flat, safe filenames' }
    Join-Path $Root $Name
}
function New-SigningRequest([string]$Directory, [string]$Phase, [string]$Commit, [string]$Version, [string]$Arch, [string[]]$Files) {
    if (Test-Path -LiteralPath $Directory) { throw 'Signing request destination already exists' }
    New-Item -ItemType Directory -Path $Directory | Out-Null
    $items = @(); $seen = @{}
    foreach ($file in $Files) {
        $name = [IO.Path]::GetFileName($file)
        $target = Get-ExchangeFile $Directory $name
        if ($seen.ContainsKey($name)) { throw 'Duplicate signing request file' }
        $seen[$name] = $true
        Copy-Item -LiteralPath $file -Destination $target
        $items += [ordered]@{name=$name; sha256=(Get-ExchangeHash $target); size=(Get-Item -LiteralPath $target).Length}
    }
    Write-ExchangeJson (Join-Path $Directory 'request.json') ([ordered]@{
        schema='edr.windows.file-signing.v1'; phase=$Phase; source_commit=$Commit; version=$Version; architecture=$Arch; files=$items
    })
}
function Read-SigningRequest([string]$Directory, [string]$Phase, [string]$Commit, [string]$Version, [string]$Arch) {
    $r = Get-Content -LiteralPath (Join-Path $Directory 'request.json') -Raw | ConvertFrom-Json
    if ($r.schema -cne 'edr.windows.file-signing.v1' -or $r.phase -cne $Phase -or $r.source_commit -cne $Commit -or
        $r.version -cne $Version -or $r.architecture -cne $Arch) { throw 'Signing request identity mismatch' }
    $allowed = switch ($Phase) {
        native { @('FDSensor.exe','FDSecurityInstallerWorker.exe','uninstall.exe','forensic_collector.exe','forensic_collector_builtin.exe','FDSecuritySetupUI.exe') }
        installer { @('FDSecuritySetup.exe','setup-ui-manifest.json') }
        manifest { @('artifact-manifest.json') }
        default { throw 'Unknown signing phase' }
    }
    $seen = @{}
    foreach ($f in $r.files) {
        $path = Get-ExchangeFile $Directory $f.name
        if ($f.name -cnotin $allowed -or $seen.ContainsKey($f.name)) { throw 'Unexpected or duplicate signing payload' }
        $seen[$f.name] = $true
        $item = Get-Item -LiteralPath $path
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $item.Length -ne $f.size -or (Get-ExchangeHash $path) -cne $f.sha256) { throw 'Signing request payload integrity mismatch' }
        if ($f.name.EndsWith('.json') -and $item.Length -gt 1MB) { throw 'Signing metadata exceeds 1 MiB' }
    }
    if ($seen.Count -ne $allowed.Count -or @(Get-ChildItem -LiteralPath $Directory -Force).Count -ne $allowed.Count+1) {
        throw 'Incomplete signing request or extra files; archives and sources are prohibited'
    }
    return $r
}
function Assert-SignedExecutable([string]$Original, [string]$Signed, [string]$Thumbprint) {
    $sig = Get-AuthenticodeSignature -LiteralPath $Signed
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Thumbprint -ne $Thumbprint -or -not $sig.TimeStamperCertificate) {
        throw 'Returned EXE does not have the pinned publisher and valid timestamp'
    }
    # Signing may change only checksum, certificate directory and appended WIN_CERTIFICATE.
    # A different, otherwise valid publisher-signed executable is not an acceptable response.
    [byte[]]$a = [IO.File]::ReadAllBytes($Original); [byte[]]$b = [IO.File]::ReadAllBytes($Signed)
    if ($a.Length -lt 256 -or $b.Length -lt $a.Length) { throw 'Invalid returned PE length' }
    $pe = [BitConverter]::ToInt32($a,60); $optional = $pe+24
    if ($pe -lt 64 -or $optional+152 -gt $a.Length -or [BitConverter]::ToUInt32($a,$pe) -ne 0x4550) { throw 'Invalid input PE header' }
    $magic = [BitConverter]::ToUInt16($a,$optional)
    $security = $optional + $(if($magic -eq 0x20b){144}elseif($magic -eq 0x10b){128}else{throw 'Unknown PE format'})
    if ([BitConverter]::ToUInt64($a,$security) -ne 0) { throw 'Signing input must be an unsigned build output' }
    $offset = [BitConverter]::ToUInt32($b,$security); $size = [BitConverter]::ToUInt32($b,$security+4)
    if ($offset -lt $a.Length -or $offset-$a.Length -gt 7 -or $size -lt 8 -or [long]$offset+$size -ne $b.Length) { throw 'Invalid appended PE certificate range' }
    for ($i=$a.Length; $i -lt $offset; $i++) { if ($b[$i] -ne 0) { throw 'Unexpected data appended before PE certificate' } }
    foreach ($range in @(@(($optional+64),4),@($security,8))) {
        [Array]::Clear($a,$range[0],$range[1]); [Array]::Clear($b,$range[0],$range[1])
    }
    $hash = [Security.Cryptography.SHA256]::Create()
    try {
        if ([Convert]::ToBase64String($hash.ComputeHash($a)) -cne [Convert]::ToBase64String($hash.ComputeHash($b,0,$a.Length))) {
            throw 'Signing response changed executable payload'
        }
    } finally { $hash.Dispose() }
}
function Assert-ExchangeCms([string]$Content, [string]$Signature, [string]$Thumbprint) {
    Add-Type -AssemblyName System.Security
    $cms = [Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new([IO.File]::ReadAllBytes($Content)), $true)
    $cms.Decode([IO.File]::ReadAllBytes($Signature)); $cms.CheckSignature($true)
    if ($cms.SignerInfos.Count -ne 1 -or $cms.SignerInfos[0].Certificate.Thumbprint -ne $Thumbprint -or
        $cms.SignerInfos[0].DigestAlgorithm.Value -ne '2.16.840.1.101.3.4.2.1') { throw 'Returned CMS publisher/digest mismatch' }
}
function Assert-SigningResponse([string]$Request, [string]$Response, [string]$Thumbprint) {
    $r = Get-Content -LiteralPath (Join-Path $Request 'request.json') -Raw | ConvertFrom-Json
    $receipt = Get-Content -LiteralPath (Join-Path $Response 'receipt.json') -Raw | ConvertFrom-Json
    if ($receipt.request_sha256 -cne (Get-ExchangeHash (Join-Path $Request 'request.json')) -or $receipt.publisher -ne $Thumbprint) { throw 'Signing response is bound to another request/publisher' }
    $expected = @($r.files | ForEach-Object name)
    if ($r.phase -eq 'installer') { $expected += 'setup-ui-manifest.json.p7s' }
    if ($r.phase -eq 'manifest') { $expected += 'artifact-manifest.json.p7s' }
    if (@(Get-ChildItem -LiteralPath $Response -Force).Count -ne $expected.Count+1) { throw 'Incomplete signing response or extra files' }
    foreach ($name in $expected) {
        $path = Get-ExchangeFile $Response $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Invalid signing response file' }
        if ($name.EndsWith('.exe')) { Assert-SignedExecutable (Join-Path $Request $name) $path $Thumbprint }
    }
    if ($r.phase -eq 'installer') {
        $original = Get-Content (Join-Path $Request 'setup-ui-manifest.json') -Raw | ConvertFrom-Json
        $returned = Get-Content (Join-Path $Response 'setup-ui-manifest.json') -Raw | ConvertFrom-Json
        $original.setup_exe_sha256 = Get-ExchangeHash (Join-Path $Response 'FDSecuritySetup.exe')
        if (($original | ConvertTo-Json -Depth 16 -Compress) -cne ($returned | ConvertTo-Json -Depth 16 -Compress)) { throw 'Installer response changed unrelated metadata' }
        Assert-ExchangeCms (Join-Path $Response 'setup-ui-manifest.json') (Join-Path $Response 'setup-ui-manifest.json.p7s') $Thumbprint
    }
    if ($r.phase -eq 'manifest') {
        if ((Get-ExchangeHash (Join-Path $Request 'artifact-manifest.json')) -cne (Get-ExchangeHash (Join-Path $Response 'artifact-manifest.json'))) { throw 'Release manifest changed during signing' }
        Assert-ExchangeCms (Join-Path $Response 'artifact-manifest.json') (Join-Path $Response 'artifact-manifest.json.p7s') $Thumbprint
    }
}
