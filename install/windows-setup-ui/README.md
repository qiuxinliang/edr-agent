# FDSecurity Setup UI

This directory contains the product-grade Windows installer shell for FDSecurity.

The UI is a WPF + WebView2 wrapper around the existing Inno installer:

- `FDSecuritySetupUI.exe` renders the high-fidelity installer experience and collects operator input.
- `FDSecuritySetup.exe` remains the authoritative elevated installer and runs the existing Inno + PowerShell workflow.
- Diagnostics are collected from the UI layer, Inno log, and Agent bootstrap reports.

## Build

Run on Windows after the bundled Inno installer has been built:

```powershell
.\install\windows-setup-ui\Build-SetupUi.ps1 `
  -SetupExe .\FDSecuritySetup.exe `
  -AppVersion 2.1.150 `
  -BootstrapTrustPublicKeyPem .\bootstrap_trust_public_key.pem `
  -OutputZip .\FDSecuritySetupUI.zip
```

The output zip contains:

- `FDSecuritySetupUI.exe`
- .NET Desktop runtime files when built in `self-contained` or `compact` mode
- WebView2 loader/runtime files from the NuGet package
- `Assets\installer.html`
- adjacent `FDSecuritySetup.exe`
- `VERSION`
- `setup-ui-manifest.json`
- optional `bootstrap_trust_public_key.pem`

Runtime modes:

- `self-contained` is the default enterprise-safe package. It includes the .NET Desktop runtime and enables ReadyToRun for faster startup, but it is the largest package.
- `compact` still includes the .NET Desktop runtime, but disables ReadyToRun to reduce package size at the cost of a slightly slower first launch.
- `framework-dependent` is the smallest package and requires .NET Desktop Runtime 8 to already exist on the endpoint.

Example compact build:

```powershell
.\install\windows-setup-ui\Build-SetupUi.ps1 `
  -SetupExe .\FDSecuritySetup.exe `
  -AppVersion 2.1.150 `
  -RuntimeMode compact `
  -OutputZip .\FDSecuritySetupUI-compact.zip
```

Every build prints a size report for the zip, bundled setup, estimated .NET/WPF runtime files, and the largest files in the publish directory.

## Unified Private Deployment Bootstrap

Private deployments can keep one unified setup package by using a signed bootstrap manifest instead of embedding a tenant-specific CA in the installer.

The setup package carries only the product bootstrap public key. Customer-specific values are provided by `setup-preconfig.json`:

```json
{
  "preconfigured": true,
  "bootstrapManifestUrl": "https://download.example.com/edr/bootstrap/customer-a.json"
}
```

The bootstrap manifest is verified locally before any trust material is used. The signed payload may provide `api_base`, `enroll_token`, `proxy_mode`, `relay_url`, and either `tls_ca_pem` or `tls_leaf_sha256`. The UI then passes only verified bootstrap material to the elevated enroll script.

Envelope format:

```json
{
  "alg": "RS256",
  "key_id": "bootstrap-rsa-v1",
  "payload_b64": "base64url(payload-json)",
  "signature": "base64url(rsa-sha256(payload_b64))"
}
```

Payload example:

```json
{
  "not_before": "2026-06-20T00:00:00Z",
  "not_after": "2026-07-20T00:00:00Z",
  "api_base": "https://edr.example.local:8080/api/v1",
  "enroll_token": "enr_xxx",
  "tls_ca_pem": "-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----"
}
```

`tls_leaf_sha256` is also supported for certificate pinning. It is the SHA-256 hash of the server leaf certificate DER bytes, not a global insecure TLS switch.

## Runtime Notes

The UI package is self-contained for .NET Desktop runtime compatibility. It still requires Microsoft Edge WebView2 Evergreen Runtime. Windows 11 devices normally have it; locked-down enterprise images should preinstall WebView2 or use the traditional `FDSecuritySetup.exe` fallback.

The UI process runs as the current user. The embedded setup executable triggers UAC only when the real install starts.
