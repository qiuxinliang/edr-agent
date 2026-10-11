#Requires -Version 5.1
param(
    [Parameter(Mandatory=$true)][string]$Root,
    [Parameter(Mandatory=$true)][ValidateSet('amd64','arm64')][string]$Architecture,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9A-F]{40}$')][string]$Thumbprint,
    [Parameter(Mandatory=$true)][string]$Subject,
    [ValidateSet('Verify','RunSetup','Installed')][string]$Mode = 'Verify',
    [string]$SourceDirectory,
    [string]$EvidenceDirectory = 'setup-exe-evidence',
    [string]$InstallDirectory,
    [string]$Stage,
    [string]$ExpectedVersion
)
$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path -LiteralPath $Root).Path
$admission = Get-Content -LiteralPath (Join-Path $Root 'admission.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if ($admission.schema -cne 'edr.headless-lifecycle-input.v1' -or
    $admission.architecture -cne $Architecture -or
    $admission.publisher_thumbprint -cne $Thumbprint -or $admission.publisher_subject -cne $Subject) {
    throw 'Independent package admission/publisher identity mismatch'
}
function Assert-PublisherSignature([string]$Path) {
    $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
    if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or
        $signature.SignerCertificate.Thumbprint -cne $Thumbprint -or
        -not $signature.TimeStamperCertificate) {
        throw "Headless executable lacks valid pinned Authenticode and timestamp: $([IO.Path]::GetFileName($Path))"
    }
}
function Assert-ManifestCms([string]$Content, [string]$Signature) {
    Add-Type -AssemblyName System.Security
    $cms = [Security.Cryptography.Pkcs.SignedCms]::new(
        [Security.Cryptography.Pkcs.ContentInfo]::new([IO.File]::ReadAllBytes($Content)), $true)
    $cms.Decode([IO.File]::ReadAllBytes($Signature))
    # Pinned publisher and detached content authenticity; certificate chain trust
    # and timestamp are independently enforced on every executable above.
    $cms.CheckSignature($true)
    if ($cms.SignerInfos.Count -ne 1 -or -not $cms.SignerInfos[0].Certificate -or
        $cms.SignerInfos[0].Certificate.Thumbprint -cne $Thumbprint -or
        $cms.SignerInfos[0].DigestAlgorithm.Value -cne '2.16.840.1.101.3.4.2.1') {
        throw 'Headless manifest CMS publisher/digest mismatch'
    }
}
# Subject in admission/manifests is the owning Go/RFC4514 representation, not
# Windows X500 display text. The exact certificate thumbprint binds native and
# CMS identity; do not compare differently formatted subject strings or add a
# second publisher setting. Python independently matches canonical metadata.
function Add-HeadlessInstalledCheck([string]$OriginalText, [string]$Hook) {
    $parseErrors = $null; $tokens = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($OriginalText, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count) { throw 'Original lifecycle harness has parse errors' }
    $matches = @($ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ieq 'Assert-InstalledRuntime'
    }, $true))
    if ($matches.Count -ne 1) { throw 'Expected exactly one Assert-InstalledRuntime function in original harness' }
    $offset = $matches[0].Body.Extent.EndOffset - 1
    if ($OriginalText[$offset] -cne '}') { throw 'Unknown lifecycle assertion closing boundary' }
    $result = $OriginalText.Insert($offset, "`n$Hook`n")
    $parseErrors = $null; $tokens = $null
    [void][Management.Automation.Language.Parser]::ParseInput($result, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count) { throw 'Augmented lifecycle harness has parse errors' }
    return $result
}

# Dot-sourcing exposes the pure AST adapter for regression tests only.
if ($MyInvocation.InvocationName -eq '.') { return }

if ($Mode -ceq 'Installed') {
    & python (Join-Path $PSScriptRoot 'headless_repack_lifecycle.py') installed --root $Root --arch $Architecture `
        --stage $Stage --expected-version $ExpectedVersion --install-dir $InstallDirectory --evidence-dir $EvidenceDirectory
    if ($LASTEXITCODE -ne 0) { throw "Installed Headless runtime hash verification failed: $Stage" }
    $receiptPath = Join-Path $EvidenceDirectory ($Stage + '.installed-native.json')
    $receipt = Get-Content -LiteralPath $receiptPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($receipt.package -ceq 'target') {
        try {
            foreach ($file in @($receipt.files)) {
                Assert-PublisherSignature (Join-Path $InstallDirectory $file.name)
                $file | Add-Member -NotePropertyName authenticode -NotePropertyValue 'Valid' -Force
                $file | Add-Member -NotePropertyName publisher_thumbprint -NotePropertyValue $Thumbprint -Force
                $file | Add-Member -NotePropertyName timestamp_verified -NotePropertyValue $true -Force
            }
        } catch {
            $receipt.status = 'failed'; $receipt.error = $_.Exception.Message
            throw
        } finally {
            $receipt | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath $receiptPath -Encoding UTF8
        }
    }
    return
}

if ($Mode -ceq 'RunSetup') {
    $source = (Resolve-Path -LiteralPath $SourceDirectory).Path
    $original = Join-Path $source 'scripts/windows_setup_exe_lifecycle_smoke.ps1'
    $evidence = [IO.Path]::GetFullPath($EvidenceDirectory)
    New-Item -ItemType Directory -Path $evidence -Force | Out-Null
    $consumer = $PSCommandPath
    function Literal([string]$Value) { "'" + $Value.Replace("'", "''") + "'" }
    $hook = '& ' + (Literal $consumer) + ' -Mode Installed -Root ' + (Literal $Root) +
        ' -Architecture ' + (Literal $Architecture) + ' -Thumbprint ' + (Literal $Thumbprint) +
        ' -Subject ' + (Literal $Subject) + ' -Stage $Stage -ExpectedVersion $ExpectedVersion -InstallDirectory $InstallDir -EvidenceDirectory $EvidenceDir'
    $originalText = [IO.File]::ReadAllText($original)
    $originalHash = (Get-FileHash -LiteralPath $original -Algorithm SHA256).Hash.ToLowerInvariant()
    $augmented = Add-HeadlessInstalledCheck -OriginalText $originalText -Hook $hook
    $temporary = Join-Path (Split-Path -Parent $original) ('windows_setup_exe_lifecycle.headless-' + [Guid]::NewGuid().ToString('N') + '.ps1')
    if (Test-Path -LiteralPath $temporary) { throw 'Temporary lifecycle adapter already exists' }
    try {
        [IO.File]::WriteAllText($temporary, $augmented, [Text.UTF8Encoding]::new($false))
        [ordered]@{
            schema='edr.headless-lifecycle-adapter.v1'
            original_source=$original;original_sha256=$originalHash
            augmented_sha256=(Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash.ToLowerInvariant()
            hook='Append installed native SHA-256 assertion after original Assert-InstalledRuntime checks'
            original_source_unchanged=$true
        } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidence 'harness-adapter.json') -Encoding UTF8
        $targetTag = $admission.source.owner.tag
        $baselineTag = $admission.baseline.owner.tag
        & $temporary -TargetSetupExe (Join-Path $Root "target/edr-agent-$targetTag-windows-$Architecture-setup.exe") `
            -BaselineSetupExe (Join-Path $Root "baseline/edr-agent-$baselineTag-windows-$Architecture-setup.exe") `
            -TargetVersion $targetTag.Substring(4) -BaselineVersion $baselineTag.Substring(4) `
            -Architecture $Architecture -EvidenceDir $evidence
        # The unchanged original harness must have visited every checkpoint;
        # missing evidence cannot be substituted with a summary-only pass.
        foreach ($stage in @('install-target-fresh','install-baseline','repair-baseline','upgrade-target','rollback-baseline')) {
            $receipt = Get-Content -LiteralPath (Join-Path $evidence ($stage + '.installed-native.json')) -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($receipt.status -cne 'succeeded' -or $receipt.stage -cne $stage -or $receipt.architecture -cne $Architecture) {
                throw "Missing successful installed hash checkpoint: $stage"
            }
        }
    } finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force -ErrorAction Stop }
        if ((Get-FileHash -LiteralPath $original -Algorithm SHA256).Hash.ToLowerInvariant() -cne $originalHash) {
            throw 'Original lifecycle source changed during augmented execution'
        }
    }
    return
}
$runtime = Join-Path $Root 'target/runtime'
$native = @('FDSensor.exe','FDSecurityInstallerWorker.exe','uninstall.exe','collector/forensic_collector_builtin.exe')
if (Test-Path -LiteralPath (Join-Path $runtime 'collector/forensic_collector.exe')) {
    $native += 'collector/forensic_collector.exe'
}
foreach ($name in $native + @('edr_agent_setup.exe')) { Assert-PublisherSignature (Join-Path $runtime $name) }
$prefix = "edr-agent-$($admission.source.owner.tag)-windows-$Architecture-"
Assert-PublisherSignature (Join-Path $Root ('target/' + $prefix + 'setup.exe'))
Assert-ManifestCms (Join-Path $runtime 'full-installer-manifest.json') (Join-Path $runtime 'full-installer-manifest.p7s')
$artifact = Join-Path $Root ('target/' + $prefix + 'artifact-manifest.json')
Assert-ManifestCms $artifact ($artifact + '.p7s')
[ordered]@{
    schema='edr.headless-lifecycle-signatures.v1';status='succeeded';architecture=$Architecture
    publisher_thumbprint=$Thumbprint;publisher_subject=$Subject
    native_executables=$native;headless_installer=$true;cms_manifests=2
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $Root 'signature-verification.json') -Encoding UTF8
Write-Host 'Independent pinned Headless Authenticode, timestamps and both detached CMS manifests verified'
