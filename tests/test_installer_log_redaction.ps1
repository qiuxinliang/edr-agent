[CmdletBinding()]
param([string] $RepoRoot = (Split-Path -Parent $PSScriptRoot))

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Load only the real evidence functions. Never execute the updater entry point,
# inspect an installed log, invoke an installer, or send an upload in this test.
$source = Join-Path $RepoRoot 'scripts/edr_agent_inplace_update.ps1'
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($source, [ref] $tokens, [ref] $parseErrors)
if ($parseErrors.Count) { throw 'updater source failed to parse' }
foreach ($name in @('Get-Sha256', 'Get-InstallerLogEvidence', 'Get-InstallerEvidenceId')) {
  $functions = @($ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
  }, $true))
  if ($functions.Count -ne 1) { throw "evidence function is not unique: $name" }
  . ([scriptblock]::Create($functions[0].Extent.Text))
}

$cases = @(
  @{ Name='user_path'; Raw='path=C:\Users\Fictional Reviewer\AppData\Local\sample.bin'; Forbidden=@('Fictional', 'sample.bin') },
  @{ Name='quoted_user_path'; Raw='path="C:\Users\Fictional Reviewer\AppData\Local\sample.bin" error_code=1603'; Forbidden=@('Fictional', 'sample.bin') },
  @{ Name='legacy_user_path'; Raw="path='C:\Documents and Settings\Fictional Reviewer\sample.bin'"; Forbidden=@('Fictional', 'sample.bin') },
  @{ Name='url_no_query'; Raw='download https://example.invalid/internal/FICTIONAL_PROJECT.zip'; Forbidden=@('example.invalid', 'FICTIONAL_PROJECT') },
  @{ Name='url_userinfo'; Raw='download https://FICTIONAL_USER:FICTIONAL_PASS@example.invalid/package.zip'; Forbidden=@('FICTIONAL_USER', 'FICTIONAL_PASS', 'example.invalid') },
  @{ Name='url_query'; Raw='https://example.invalid/package?key=FICTIONAL_QUERY'; Forbidden=@('example.invalid', 'FICTIONAL_QUERY') },
  @{ Name='double_quote'; Raw='password="FICTIONAL_FIRST FICTIONAL_SECOND"'; Forbidden=@('FICTIONAL_FIRST', 'FICTIONAL_SECOND') },
  @{ Name='single_quote'; Raw="token='FICTIONAL_FIRST FICTIONAL_SECOND'"; Forbidden=@('FICTIONAL_FIRST', 'FICTIONAL_SECOND') },
  @{ Name='multiline'; Raw="secret=`"FICTIONAL_FIRST`r`nFICTIONAL_SECOND`""; Forbidden=@('FICTIONAL_FIRST', 'FICTIONAL_SECOND') },
  @{ Name='unicode'; Raw=('password="' + [char] 0x5BC6 + ' ' + [char] 0x6587 + '"'); Forbidden=@([string] [char] 0x5BC6, [string] [char] 0x6587) },
  @{ Name='json_key'; Raw='"access_token": "FICTIONAL_FIRST FICTIONAL_SECOND"'; Forbidden=@('FICTIONAL_FIRST', 'FICTIONAL_SECOND') },
  @{ Name='escaped_quotes'; Raw='password="FICTIONAL_FIRST\" FICTIONAL_SECOND"'; Forbidden=@('FICTIONAL_FIRST', 'FICTIONAL_SECOND') },
  @{ Name='doubled_quotes'; Raw='password="FICTIONAL_FIRST"" FICTIONAL_SECOND"'; Forbidden=@('FICTIONAL_FIRST', 'FICTIONAL_SECOND') },
  @{ Name='single_doubled_quotes'; Raw="secret='FICTIONAL_FIRST'' FICTIONAL_SECOND'"; Forbidden=@('FICTIONAL_FIRST', 'FICTIONAL_SECOND') },
  @{ Name='backtick_quote'; Raw='password="FICTIONAL_FIRST`" FICTIONAL_SECOND"'; Forbidden=@('FICTIONAL_FIRST', 'FICTIONAL_SECOND') },
  @{ Name='folded_value'; Raw="secret=FICTIONAL_FIRST`r`n  FICTIONAL_SECOND"; Forbidden=@('FICTIONAL_FIRST', 'FICTIONAL_SECOND') },
  @{ Name='folded_authorization'; Raw="Authorization: Bearer FICTIONAL_FIRST`r`n  FICTIONAL_SECOND"; Forbidden=@('FICTIONAL_FIRST', 'FICTIONAL_SECOND') },
  @{ Name='bare_bearer'; Raw='request Bearer FICTIONAL_TOKEN'; Forbidden=@('FICTIONAL_TOKEN') },
  @{ Name='private_key'; Raw="-----BEGIN PRIVATE KEY-----`r`nFICTIONAL_BODY`r`n-----END PRIVATE KEY-----"; Forbidden=@('FICTIONAL_BODY') },
  @{ Name='truncate_after_redaction'; Raw=('a' * 4300) + "`npassword=`"" + ('FICTIONAL_LONG ' * 800) + '"'; Forbidden=@('FICTIONAL_LONG') },
  @{ Name='utf8_tail'; Raw=([string] [char] 0x4E2D * 1500); Forbidden=@([string] [char] 0xFFFD) },
  @{ Name='supplementary_tail'; Raw=([char]::ConvertFromUtf32(0x1F600) * 1500); Forbidden=@([string] [char] 0xFFFD) },
  @{ Name='unterminated_quote'; Raw='password="FICTIONAL_FIRST FICTIONAL_SECOND'; Forbidden=@('FICTIONAL_FIRST', 'FICTIONAL_SECOND'); Unterminated=$true }
)

$root = Join-Path ([IO.Path]::GetTempPath()) ('edr-installer-redaction-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
$failures = @()
try {
  foreach ($case in $cases) {
    $path = Join-Path $root ($case.Name + '.log')
    $raw = "phase=install`r`n" + $case.Raw
    if (-not $case.ContainsKey('Unterminated')) { $raw += "`r`nphase=done error_code=1603" }
    # BOM ensures Windows PowerShell 5.1 and PowerShell 7 read the same Unicode.
    [IO.File]::WriteAllText($path, $raw, [Text.UTF8Encoding]::new($true))
    $evidence = Get-InstallerLogEvidence -Path $path
    $bytes = [IO.File]::ReadAllBytes($evidence.Path)
    $snapshot = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    foreach ($marker in $case.Forbidden) {
      if ($snapshot.Contains($marker)) { $failures += "$($case.Name): forbidden marker survived" }
    }
    if ($evidence.Status -cne 'ready' -or $evidence.Path -cne "$path.redacted" -or
        $evidence.Sha256 -cne (Get-Sha256 -Path $evidence.Path) -or
        $evidence.Size -ne $bytes.Length -or $bytes.Length -gt 4096 -or
        $evidence.OriginalSize -ne (Get-Item -LiteralPath $path).Length -or
        $snapshot -cne $evidence.Summary) { $failures += "$($case.Name): snapshot metadata/bound mismatch" }
    if (-not $case.ContainsKey('Unterminated') -and -not $snapshot.Contains('phase=done error_code=1603')) {
      $failures += "$($case.Name): safe phase and error code were lost"
    }
  }
  $id = Get-InstallerEvidenceId -TaskId 'synthetic-task' -CommandId 'synthetic-command'
  if ($id -cne (Get-InstallerEvidenceId -TaskId 'synthetic-task' -CommandId 'synthetic-command') -or
      $id -ceq (Get-InstallerEvidenceId -TaskId 'other-task' -CommandId 'synthetic-command') -or
      $id -ceq (Get-InstallerEvidenceId -TaskId 'synthetic-task' -CommandId 'other-command')) {
    $failures += 'evidence ID lost deterministic task/command binding'
  }
  if ($failures.Count) { throw ($failures -join "`n") }
  Write-Host "PASS: $($cases.Count) synthetic installer log cases; real snapshot bytes/hash/size and UTF-8 bound; deterministic evidence ID"
} finally {
  Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
