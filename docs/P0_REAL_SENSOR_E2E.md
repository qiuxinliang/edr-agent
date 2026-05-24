# P0 Real Sensor E2E Validation

This document defines the P0 validation path for real endpoint sensors. Replay fixtures prove that the backend and UI can consume `detection_context`; this workflow verifies that a Windows Agent can produce those signals from live telemetry.

## Scope

P0 covers these safe or controlled scenarios:

| Scenario | Default | Expected signal |
| --- | --- | --- |
| PowerShell ScriptBlock / AMSI content | on | `script_sensor`, `script_or_encoded_payload`, targeted `pmfe_scan` |
| Ransomware file-rate counter | on | `ransom_behavior` |
| Registry Run key persistence | opt-in | `persistence_change` |
| WebShell semantic file write | opt-in | `webshell_semantic`, `webshell_files`, targeted `pmfe_scan` |
| TLS certificate anomaly | opt-in | `tls_anomaly` |
| LSASS MiniDump command-line telemetry | opt-in | `credential_dump_indicator`, targeted `pmfe_scan` |

The default run avoids persistence writes, Web root writes, external TLS requests, and LSASS-related command lines. Opt-in scenarios are still bounded and cleaned up, but should be run on a lab endpoint.

## Prerequisites

- Windows endpoint with the EDR Agent installed and running.
- Agent is configured to send ingest to the platform.
- PowerShell execution is allowed for local scripts.
- Optional: platform API access for `/api/v1/alerts`. If auth is enabled, pass `-BearerToken`.
- Optional for WebShell: configure Agent WebShell roots and pass `-WebRoot`.

## Run

Default low-risk validation:

```powershell
cd <repo>\edr-agent
powershell.exe -ExecutionPolicy Bypass -File .\scripts\windows_sensor_e2e.ps1 `
  -ApiBase http://127.0.0.1:8080/api/v1 `
  -EndpointId <endpoint-id> `
  -WaitSeconds 90
```

Lab validation with controlled opt-in scenarios:

```powershell
cd <repo>\edr-agent
powershell.exe -ExecutionPolicy Bypass -File .\scripts\windows_sensor_e2e.ps1 `
  -ApiBase http://127.0.0.1:8080/api/v1 `
  -EndpointId <endpoint-id> `
  -BearerToken <token-if-needed> `
  -EnablePersistence `
  -EnableWebShell -WebRoot C:\inetpub\wwwroot `
  -EnableTls `
  -WaitSeconds 120
```

LSASS command-line validation is separated deliberately:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\scripts\windows_sensor_e2e.ps1 `
  -EndpointId <endpoint-id> `
  -EnableLsassCommandLine `
  -WaitSeconds 120
```

## Output

The script prints a unique `RunId` such as:

```text
EDR-SENSOR-E2E-2f7a8c0b6d11
```

It writes a JSON summary to `%TEMP%\<RunId>-result.json` unless `-OutFile` is provided. The summary includes:

- `run_id`
- triggered, skipped, and failed scenarios
- expected signals per scenario
- `/alerts` API result when API checking is enabled

If API auth is unavailable, run with `-SkipApiCheck` and search the alert page for the printed `RunId`.

## Pass Criteria

P0 is considered passed when:

- The default run triggers PowerShell and ransomware counter scenarios without script errors.
- At least one alert or endpoint event can be correlated by `RunId`, endpoint, and time window.
- `detection_context.signals.script_sensor=true` is visible for the PowerShell scenario.
- `detection_context.signals.ransom_behavior=true` is visible for the file-rate scenario, or the event is visible in endpoint telemetry for threshold tuning.
- In lab opt-in mode, WebShell and persistence scenarios produce `webshell_semantic` and `persistence_change` respectively.
- Any targeted PMFE trigger stays scoped to single-process scan; `single_process_minidump` should remain false unless high-confidence multi-source evidence is intentionally produced.

## Notes

- This is not an exploit harness. It uses benign commands and marker strings to exercise sensors.
- The script cleans up created files and registry values unless `-NoCleanup` is set.
- Keep replay fixture validation in CI:

```bash
cd edr-backend
./scripts/smoke_detection_replay_fixtures.sh
```

Replay statistics remain the guardrail for backend and UI contracts. This Windows script is the guardrail for live sensor collection.
