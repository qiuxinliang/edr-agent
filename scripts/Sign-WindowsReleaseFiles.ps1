#Requires -Version 5.1
param(
    [Parameter(Mandatory=$true)][string]$InputDirectory,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [Parameter(Mandatory=$true)][ValidateSet('native','installer','manifest')][string]$Phase,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{40}$')][string]$ExpectedCommit,
    [Parameter(Mandatory=$true)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version,
    [Parameter(Mandatory=$true)][ValidateSet('amd64','arm64')][string]$Architecture,
    [Parameter(Mandatory=$true)][string]$Thumbprint,
    [Parameter(Mandatory=$true)][string]$SignTool
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'WindowsStoreSigning.ps1')
. (Join-Path $PSScriptRoot 'WindowsUsbSigningExchange.ps1')
$r = Read-SigningRequest $InputDirectory $Phase $ExpectedCommit $Version $Architecture
$certificate = Get-EdRStoreSigningCertificate $Thumbprint
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Signing response destination already exists' }
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
foreach ($f in $r.files) {
    $path = Get-ExchangeFile $OutputDirectory $f.name
    Copy-Item -LiteralPath (Join-Path $InputDirectory $f.name) -Destination $path
    if ($f.name.EndsWith('.exe')) {
        Invoke-EdRStoreAuthenticodeSign -Path $path -Thumbprint $Thumbprint -SignTool $SignTool
    }
}
if ($Phase -eq 'installer') {
    $path = Join-Path $OutputDirectory 'setup-ui-manifest.json'
    $m = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    $m.setup_exe_sha256 = Get-ExchangeHash (Join-Path $OutputDirectory 'FDSecuritySetup.exe')
    Write-ExchangeJson $path $m
}
foreach ($f in $r.files | Where-Object { $_.name.EndsWith('.json') }) {
    $path = Join-Path $OutputDirectory $f.name
    Write-EdRStoreDetachedCms -ContentPath $path -SignaturePath ($path+'.p7s') -Thumbprint $Thumbprint -SignTool $SignTool
}
Write-ExchangeJson (Join-Path $OutputDirectory 'receipt.json') ([ordered]@{
    request_sha256=(Get-ExchangeHash (Join-Path $InputDirectory 'request.json')); publisher=$certificate.Thumbprint
})
Assert-SigningResponse $InputDirectory $OutputDirectory $Thumbprint
Write-Host "Signed file-only response ready: $Phase / $Architecture"
