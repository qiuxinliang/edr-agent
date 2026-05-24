# Hardware Key Enrollment

Endpoint enrollment sends a CSR to the platform. The platform returns `client_cert` and `ca_cert`; it never returns `client_key`.

## Windows CNG Non-Exportable Key

```powershell
$env:EDR_API_BASE = "https://edr.example.com"
$env:EDR_ENROLL_TOKEN = "<token>"
$env:EDR_KEY_PROVIDER = "cng"
$env:EDR_CNG_PROVIDER_NAME = "Microsoft Software Key Storage Provider"
$env:EDR_CNG_KEY_NAME = "EDR-Agent-$env:COMPUTERNAME"
.\scripts\edr_agent_install.ps1
```

The installer uses `certreq.exe` with `Exportable = FALSE` and `KeyExportPolicy = 0`, then accepts the issued certificate into `LocalMachine\My`.

## Windows TPM Key

```powershell
$env:EDR_KEY_PROVIDER = "tpm"
$env:EDR_CNG_PROVIDER_NAME = "Microsoft Platform Crypto Provider"
.\scripts\edr_agent_install.ps1
```

If `EDR_TPM_KEY_URI` is set, the installer switches to OpenSSL TPM provider mode instead of Windows CNG.

## PKCS#11

```bash
export EDR_KEY_PROVIDER=pkcs11
export EDR_PKCS11_KEY_URI='pkcs11:token=EDR;object=agent-key;type=private'
export EDR_PKCS11_OPENSSL_MODE=engine
python3 scripts/edr_agent_install.py
```

For OpenSSL 3 provider mode, set `EDR_PKCS11_OPENSSL_MODE=provider` and optionally `EDR_PKCS11_MODULE`.

## Runtime Note

The current gRPC runtime uses PEM `client_key`. When `client_key_provider` is `cng`, `tpm`, or `pkcs11`, the Agent records the metadata and refuses to pretend it can use that key for PEM-based mTLS. This is the compatibility guard until the Windows Schannel or hardware-key transport adapter is enabled.
