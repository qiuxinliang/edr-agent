#Requires -Version 5.1
param([string]$RepoRoot, [switch]$HostContractOnly)
$ErrorActionPreference = 'Stop'
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('edr-policy-auth-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
$config = Join-Path $fixtureRoot 'agent.toml'
$oldBearer = [Environment]::GetEnvironmentVariable('EDR_PLATFORM_BEARER', 'Process')
$rootMaterial = $null; $serverMaterial = $null; $badMaterial = $null; $otherRootMaterial = $null
$privateTlsConfigured = $false
$oldCallback = [Net.ServicePointManager]::ServerCertificateValidationCallback
$oldProtocol = [Net.ServicePointManager]::SecurityProtocol
$oldProxy = [Net.WebRequest]::DefaultWebProxy
function Assert-Policy([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Write-PolicyPhase([string]$Phase, $Listener = $null) {
  $detail = if ($null -eq $Listener) { '' } else { ' accepted=' + $Listener.AcceptedConnections + ' tls=' + $Listener.HandshakeCompleted + ' http=' + $Listener.ReceivedRequest }
  Write-Host ('policy_auth_phase=' + $Phase + $detail)
}
function Write-PolicyConfig([string]$Bearer) {
  [IO.File]::WriteAllText($config, "[unrelated]`nrest_bearer_token = `"must-not-select`"`n[platform]`nrest_bearer_token = `"$Bearer`"`n")
}
function Check-Policy {
  param([string]$Url = 'https://policy.invalid/agent/runtime-policy.toml', [string]$Base = 'https://policy.invalid')
  Invoke-AgentPolicyVerification -Path $config -Url $Url -RestBaseUrl $Base -RelayUrl '' -EndpointId 'fixture-endpoint' -TenantId 'fixture-tenant' -TimeoutSec 3 -ProxyOptions @{}
}
try {
  $tokens = $null; $parseErrors = $null
  $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $RepoRoot 'scripts/edr_agent_postinstall_verify.ps1'), [ref]$tokens, [ref]$parseErrors)
  Assert-Policy (@($parseErrors).Count -eq 0) 'Production policy verifier must parse'
  foreach ($name in @('Read-TomlString', 'Read-AgentPolicyBearer', 'Read-PolicyVersionFromText', 'Invoke-AgentPolicyVerification')) {
    $node = @($ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -eq $name })
    Assert-Policy ($node.Count -eq 1) ('Missing production function: ' + $name)
    . ([scriptblock]::Create($node[0].Extent.Text))
  }
  [Environment]::SetEnvironmentVariable('EDR_PLATFORM_BEARER', $null, 'Process')
  $authFixture = @{ count=0; expectedBearer='fixture.valid.token' }
  function Invoke-WebRequest {
    param($Uri, $Headers, [switch]$UseBasicParsing, $TimeoutSec, $MaximumRedirection)
    $authFixture.count++
    Assert-Policy ($UseBasicParsing -and $MaximumRedirection -eq 0 -and $TimeoutSec -eq 3) 'Finite request must forbid redirects'
    Assert-Policy ($Headers['X-Endpoint-ID'] -ceq 'fixture-endpoint' -and $Headers['X-Tenant-ID'] -ceq 'fixture-tenant') 'Endpoint identity headers must be retained'
    if ($Headers['Authorization'] -cne ('Bearer ' + $authFixture.expectedBearer)) { throw ('rejected sensitive ' + $Headers['Authorization']) }
    [pscustomobject]@{StatusCode=200; Content='version = "fixture-policy"'}
  }
  [IO.File]::WriteAllText($config, "[unrelated]`nrest_base_url = `"https://wrong.invalid`"`n[platform]`nrest_base_url = `"https://policy.invalid`"`n")
  Assert-Policy ((Read-TomlString -Path $config -Key 'rest_base_url' -Section 'platform') -ceq 'https://policy.invalid') 'Origin must come from the platform section'
  Write-PolicyConfig 'fixture.valid.token'
  $r = Check-Policy
  Assert-Policy ($r.status -eq 'ok' -and $r.version -eq 'fixture-policy') 'Scoped configured credential must authenticate'
  $lock = [IO.File]::Open($config, 'Open', 'ReadWrite', 'None'); $lock.Dispose()
  [Environment]::SetEnvironmentVariable('EDR_PLATFORM_BEARER', 'fixture.env.token', 'Process')
  $authFixture.expectedBearer = 'fixture.env.token'
  Assert-Policy ((Check-Policy).status -eq 'ok') 'Nonempty process environment must have Agent precedence'
  [Environment]::SetEnvironmentVariable('EDR_PLATFORM_BEARER', '', 'Process')
  $authFixture.expectedBearer = 'fixture.valid.token'
  Assert-Policy ((Check-Policy).status -eq 'ok') 'Empty environment must use configuration'
  foreach ($bad in @('', 'has space', "line`r`nbreak", ('a' * 512))) {
    [Environment]::SetEnvironmentVariable('EDR_PLATFORM_BEARER', $bad, 'Process')
    Write-PolicyConfig ''
    $before = $authFixture.count; $r = Check-Policy
    Assert-Policy ($r.status -eq 'warning' -and $authFixture.count -eq $before) 'Absent or malformed bearer must not send a request'
    Assert-Policy ($r.message -in @('policy_bearer_missing','policy_bearer_source_invalid')) 'Credential failure must be explicit and secret-free'
  }
  [Environment]::SetEnvironmentVariable('EDR_PLATFORM_BEARER', $null, 'Process')
  $authFixture.expectedBearer = 'a' * 511
  Write-PolicyConfig $authFixture.expectedBearer
  Assert-Policy ((Check-Policy).status -eq 'ok') 'Maximum Agent bearer length must remain usable without truncation'
  $authFixture.expectedBearer = 'fixture.valid.token'
  [IO.File]::WriteAllText($config, "[platform]`nrest_bearer_token = `"fixture.valid.token`"`nrest_bearer_token = `"duplicate`"`n")
  Assert-Policy ((Check-Policy).message -eq 'policy_bearer_source_invalid') 'Duplicate credentials must not be guessed'
  [IO.File]::WriteAllText($config, "[unrelated]`nrest_bearer_token = `"fixture.valid.token`"`n")
  Assert-Policy ((Check-Policy).message -eq 'policy_bearer_missing') 'Another section cannot authorize policy access'
  Write-PolicyConfig 'fixture.valid.token'
  foreach ($url in @('http://policy.invalid/policy', 'https://other.invalid/policy', 'https://user:secret@policy.invalid/policy', 'https://policy.invalid/policy#fragment')) {
    $before = $authFixture.count; $r = Check-Policy -Url $url
    Assert-Policy ($r.status -eq 'warning' -and $authFixture.count -eq $before) 'Invalid or cross-origin URL cannot receive the credential'
  }
  Write-PolicyConfig 'fixture.wrong.token'
  $r = Check-Policy
  Assert-Policy ($r.status -eq 'warning' -and $r.message -eq 'policy_request_failed') 'Request failure must not be treated as authenticated'
  Assert-Policy (($r | ConvertTo-Json -Compress) -notmatch 'fixture.wrong.token|sensitive|Authorization') 'Failure result must not copy secret exception text'
  # Run the complete report owner with only network/OS boundaries substituted.
  # This checks that a successful/failed fetch is wired into the actual installer
  # report and exit status without persisting the synthetic bearer in diagnostics.
  $fakeBinary = Join-Path $fixtureRoot 'FDSensor.exe'
  [IO.File]::WriteAllText($fakeBinary, 'test-only nonexecutable')
  [IO.File]::WriteAllText((Join-Path $fixtureRoot 'VERSION'), 'test-version')
  function Get-CimInstance { [CmdletBinding()]param($ClassName, $Filter) [pscustomobject]@{ExecutablePath=$fakeBinary} }
  function Get-Service { [CmdletBinding()]param() }
  function Get-ScheduledTask { [CmdletBinding()]param() }
  foreach ($case in @(@('fixture.valid.token','ok',0), @('fixture.wrong.token','warning',2), @('','warning',2))) {
    [IO.File]::WriteAllText($config, "[agent]`nendpoint_id = `"fixture-endpoint`"`ntenant_id = `"fixture-tenant`"`n[platform]`nrest_base_url = `"https://policy.invalid`"`nrest_bearer_token = `"$($case[0])`"`n[remote]`nruntime_policy_url = `"https://policy.invalid/agent/runtime-policy.toml`"`n")
    $reportPath = Join-Path $fixtureRoot 'report.json'; $logPath = Join-Path $fixtureRoot 'verify.log'
    & (Join-Path $RepoRoot 'scripts/edr_agent_postinstall_verify.ps1') -InstallDir $fixtureRoot -ConfigPath $config -ReportPath $reportPath -LogPath $logPath -PolicyTimeoutSec 3 -RuntimeMode manual
    $actualExit = $LASTEXITCODE
    $reportText = [IO.File]::ReadAllText($reportPath); $report = $reportText | ConvertFrom-Json
    $pull = @($report.checks | Where-Object name -eq 'runtime_policy_pull')
    Assert-Policy ($actualExit -eq $case[2]) ('Full verifier exit must retain policy warning; exit=' + $actualExit + '; status=' + $report.status + '; cause=' + $pull[0].message + '; runtime=' + (@($report.checks | Where-Object name -eq 'runtime_presence')[0].message))
    Assert-Policy ($report.status -eq $case[1] -and $pull.Count -eq 1 -and $pull[0].status -eq $case[1]) 'Full report must reflect current authenticated fetch outcome'
    Assert-Policy ($report.capability_health -eq 'unknown') 'Authenticated fetch must not claim applied policy or capability health'
    Assert-Policy (($reportText + [IO.File]::ReadAllText($logPath)) -notmatch 'fixture\.(valid|wrong)\.token|Authorization|sensitive') 'Report and log must contain no bearer or secret exception text'
  }
  Remove-Item Function:Get-CimInstance, Function:Get-Service, Function:Get-ScheduledTask
  Remove-Item Function:Invoke-WebRequest
  if ($HostContractOnly) {
    Write-Host 'PASS: production policy verifier scope, precedence, minimization and failure contracts; native TLS NOT EXECUTED'
    return
  }

  # Reuse the installer's strict CLR CA validator in this isolated test process.
  # CurrentUser Root imports can display interactive security UI on Windows;
  # this fixture must not write an OS trust store or wait for that UI. The real
  # verifier/request path remains unchanged, including hostname and EKU checks.
  Assert-Policy ($PSVersionTable.PSEdition -eq 'Desktop') 'Native TLS contract requires Windows PowerShell Desktop; use HostContractOnly on other hosts'
  Write-PolicyPhase 'native_fixture_load'
  Assert-Policy ($null -eq $oldCallback) 'TLS fixture requires an isolated validation callback context'
  $installerAst = [Management.Automation.Language.Parser]::ParseFile((Join-Path $RepoRoot 'scripts/edr_agent_install.ps1'), [ref]$tokens, [ref]$parseErrors)
  Assert-Policy (@($parseErrors).Count -eq 0) 'Production installer TLS validator must parse'
  $validator = @($installerAst.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -eq 'Ensure-BootstrapTlsValidatorType' })
  Assert-Policy ($validator.Count -eq 1) 'Production strict TLS validator must be present'
  . ([scriptblock]::Create($validator[0].Extent.Text))
  Ensure-BootstrapTlsValidatorType
  if (-not ('InstallTlsFixture' -as [type])) { Add-Type -Path (Join-Path $RepoRoot 'tests/windows_install_tls_fixture.cs') }
  Write-PolicyPhase 'native_certificate_create'
  $rootMaterial = [InstallCertificateFixtureFactory]::CreateRoot('FDS Policy Auth ' + [Guid]::NewGuid().ToString('N'))
  $serverMaterial = [InstallCertificateFixtureFactory]::CreateIssued($rootMaterial, 'policy-loopback', $false, '1.3.6.1.5.5.7.3.1', '', '127.0.0.1', -1, 2)
  $badMaterial = [InstallCertificateFixtureFactory]::CreateIssued($rootMaterial, 'wrong-host', $false, '1.3.6.1.5.5.7.3.1', 'wrong.invalid', '', -1, 2)
  $otherRootMaterial = [InstallCertificateFixtureFactory]::CreateRoot('FDS Unrelated Policy CA ' + [Guid]::NewGuid().ToString('N'))
  [FdsBootstrapTlsValidator]::Configure([Security.Cryptography.X509Certificates.X509Certificate2[]]@($rootMaterial.Certificate), [string[]]@($rootMaterial.Certificate.Thumbprint), [string[]]@())
  $privateTlsConfigured = $true
  [Net.ServicePointManager]::ServerCertificateValidationCallback = [FdsBootstrapTlsValidator]::Callback
  Write-PolicyPhase 'native_private_ca_ready'
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  [Net.WebRequest]::DefaultWebProxy = New-Object Net.WebProxy
  # The previous implementation's actual unauthenticated request is rejected.
  Write-PolicyPhase 'unauthenticated_begin'
  $listener = New-Object InstallTlsFixture($serverMaterial.Certificate, 'fixture.valid.token', 200)
  try {
    $code = 0
    try { Invoke-WebRequest -Uri ('https://127.0.0.1:' + $listener.Port + '/agent/runtime-policy.toml') -Headers @{'X-Endpoint-ID'='fixture-endpoint'} -UseBasicParsing -TimeoutSec 3 | Out-Null }
    catch { if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode } }
    Assert-Policy ($code -eq 401 -and $listener.ReceivedRequest -and -not $listener.Authenticated) 'Previous no-bearer request must reproduce actual HTTP 401'
  } finally { $listener.Dispose(); Write-PolicyPhase 'unauthenticated_end' $listener }
  $caseIndex = 0
  foreach ($case in @(@('fixture.valid.token',200,'ok'), @('fixture.wrong.token',200,'warning'), @('fixture.valid.token',401,'warning'), @('fixture.valid.token',403,'warning'), @('fixture.valid.token',302,'warning'))) {
    $caseIndex++
    Write-PolicyPhase ('authenticated_case_' + $caseIndex + '_begin')
    Write-PolicyConfig $case[0]
    $listener = New-Object InstallTlsFixture($serverMaterial.Certificate, 'fixture.valid.token', [int]$case[1])
    try {
      $base = 'https://127.0.0.1:' + $listener.Port
      $r = Check-Policy -Url ($base + '/agent/runtime-policy.toml') -Base $base
      Assert-Policy ($r.status -eq $case[2] -and $listener.ReceivedRequest) 'Actual TLS authentication/status outcome must match (401 includes server expiry rejection)'
      Assert-Policy (($r | ConvertTo-Json -Compress) -notmatch 'fixture\.(valid|wrong|expired)\.token|Authorization') 'Actual HTTP results must contain no bearer'
      if ($case[1] -eq 200 -and $case[0] -ceq 'fixture.valid.token') { Assert-Policy ($listener.Authenticated -and $r.version -eq 'fixture-policy') 'Correct owner must reach and authenticate at the receiver' }
    } finally { $listener.Dispose(); Write-PolicyPhase ('authenticated_case_' + $caseIndex + '_end') $listener }
  }
  Write-PolicyConfig ''
  Assert-Policy ((Check-Policy).message -eq 'policy_bearer_missing') 'Missing owner cannot report policy success'
  Write-PolicyConfig 'fixture.valid.token'
  Write-PolicyPhase 'wrong_hostname_begin'
  $listener = New-Object InstallTlsFixture($badMaterial.Certificate, 'fixture.valid.token', 200)
  try {
    $base = 'https://127.0.0.1:' + $listener.Port
    $r = Check-Policy -Url ($base + '/agent/runtime-policy.toml') -Base $base
    Assert-Policy ($r.status -eq 'warning' -and -not $listener.ReceivedRequest) 'Hostname mismatch must fail TLS before sending HTTP credentials'
  } finally { $listener.Dispose(); Write-PolicyPhase 'wrong_hostname_end' $listener }
  Assert-Policy ([FdsBootstrapTlsValidator]::LastFailure -eq 'certificate_name_mismatch') 'Hostname rejection must come from TLS validation'
  # Keep the original valid hostname/server certificate and change only the
  # trusted CA. This independently proves that no trust-all callback is used.
  [FdsBootstrapTlsValidator]::Configure([Security.Cryptography.X509Certificates.X509Certificate2[]]@($otherRootMaterial.Certificate), [string[]]@($otherRootMaterial.Certificate.Thumbprint), [string[]]@())
  Write-PolicyPhase 'wrong_ca_begin'
  $listener = New-Object InstallTlsFixture($serverMaterial.Certificate, 'fixture.valid.token', 200)
  try {
    $base = 'https://127.0.0.1:' + $listener.Port
    $r = Check-Policy -Url ($base + '/agent/runtime-policy.toml') -Base $base
    Assert-Policy ($r.status -eq 'warning' -and -not $listener.ReceivedRequest) 'Wrong CA must fail TLS before sending HTTP credentials'
  } finally { $listener.Dispose(); Write-PolicyPhase 'wrong_ca_end' $listener }
  Assert-Policy ([FdsBootstrapTlsValidator]::LastFailure -match '^bootstrap_(chain_build_failed|trust_anchor_or_pin_mismatch)') 'Wrong CA rejection must come from chain/anchor validation'
  Write-Host 'PASS: real TLS policy authentication, old 401, rejection/expiry-status/missing bearer, redirect, hostname and CA validation'
} finally {
  [Environment]::SetEnvironmentVariable('EDR_PLATFORM_BEARER', $oldBearer, 'Process')
  [Net.ServicePointManager]::SecurityProtocol = $oldProtocol
  [Net.WebRequest]::DefaultWebProxy = $oldProxy
  [Net.ServicePointManager]::ServerCertificateValidationCallback = $oldCallback
  try { if ($privateTlsConfigured) { [FdsBootstrapTlsValidator]::Configure([Security.Cryptography.X509Certificates.X509Certificate2[]]@(), [string[]]@(), [string[]]@()) } }
  finally {
    try { if ($otherRootMaterial) { $otherRootMaterial.Dispose() } }
    finally {
      try { if ($badMaterial) { $badMaterial.Dispose() } }
      finally {
        try { if ($serverMaterial) { $serverMaterial.Dispose() } }
        finally { try { if ($rootMaterial) { $rootMaterial.Dispose() } } finally { Remove-Item -LiteralPath $fixtureRoot -Recurse -Force } }
      }
    }
  }
}
