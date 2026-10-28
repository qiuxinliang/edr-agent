#Requires -Version 5.1
# CI lifecycle callers only; this helper is not installed on endpoints.
function Start-LifecycleWindowsPowerShell {
  param(
    [Parameter(Mandatory=$true)][string]$EncodedCommand,
    [Parameter(Mandatory=$true)][string]$StandardOutput,
    [Parameter(Mandatory=$true)][string]$StandardError
  )
  # Match the existing cache-recovery/CTest boundary: PS7 module locations
  # cannot supply PS5.1's inbox modules. These callers launch sequentially;
  # clear only the process value during inheritance, then restore it even if
  # process creation fails. No user or machine environment is modified.
  $previousModulePath = [Environment]::GetEnvironmentVariable('PSModulePath', [EnvironmentVariableTarget]::Process)
  try {
    [Environment]::SetEnvironmentVariable('PSModulePath', $null, [EnvironmentVariableTarget]::Process)
    return (Start-Process -FilePath (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') `
      -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand',$EncodedCommand) `
      -RedirectStandardOutput $StandardOutput -RedirectStandardError $StandardError -PassThru)
  } finally {
    [Environment]::SetEnvironmentVariable('PSModulePath', $previousModulePath, [EnvironmentVariableTarget]::Process)
  }
}
