# EDR Agent Setup UI

This directory contains the product-grade Windows installer shell for EDR Agent.

The UI is a WPF + WebView2 wrapper around the existing Inno installer:

- `edr_agent_setup_ui.exe` renders the high-fidelity installer experience and collects operator input.
- `edr_agent_setup.exe` remains the authoritative elevated installer and runs the existing Inno + PowerShell workflow.
- Diagnostics are collected from the UI layer, Inno log, and Agent bootstrap reports.

## Build

Run on Windows after the bundled Inno installer has been built:

```powershell
.\install\windows-setup-ui\Build-SetupUi.ps1 `
  -SetupExe .\edr_agent_setup.exe `
  -AppVersion 2.1.150 `
  -OutputZip .\edr_agent_setup_ui.zip
```

The output zip contains:

- `edr_agent_setup_ui.exe`
- self-contained .NET Desktop runtime files
- WebView2 loader/runtime files from the NuGet package
- `Assets\installer.html`
- adjacent `edr_agent_setup.exe`
- `VERSION`
- `setup-ui-manifest.json`

## Runtime Notes

The UI package is self-contained for .NET Desktop runtime compatibility. It still requires Microsoft Edge WebView2 Evergreen Runtime. Windows 11 devices normally have it; locked-down enterprise images should preinstall WebView2 or use the traditional `edr_agent_setup.exe` fallback.

The UI process runs as the current user. The embedded setup executable triggers UAC only when the real install starts.
