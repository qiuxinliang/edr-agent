# Windows USB signing release

## Ownership and release path

Use `edr-agent client release` with `release_mode=usb` and a **new version**.
Do not replace individual EXEs inside an already published release.

1. GitHub's native AMD64 and ARM64 builders run the release gates and produce
   intermediate `usb-input-*` artifacts bound to the workflow commit and hashes.
2. The dedicated `edr-usb-signing` Windows runner signs first-party executable
   entry points using the current user's USB certificate. No PFX or PIN is sent
   to GitHub. Upstream WinDivert and Velociraptor signatures are not replaced.
3. `Complete-WindowsUsbRelease.ps1` rebuilds Inno from signed inputs, signs the
   outer installer and existing native Setup UI, updates integrity manifests,
   and creates detached SHA-256 CMS signatures. Signing changes runtime identity,
   so the release is classified `installer_required`, not `binary_hot`.
4. Both architecture closures must finish before final assets are uploaded to
   the draft. Native install/upgrade/rollback jobs run before publication.
5. Import the complete published bundle into the platform. The platform still
   requires trusted publisher thumbprints, a valid code-signing chain, matching
   manifests and exact artifact hashes. A GitHub signing success does not prove
   platform trust configuration or endpoint installation success.

## Dedicated runner

The runner must run interactively as the user owning `Cert:\CurrentUser\My`.
Do not install it as a SYSTEM service: that identity cannot use the user's USB
key. Use an ephemeral runner with labels `self-hosted,Windows,edr-usb-signing`;
register it for one release, run `run.cmd`, and allow it to unregister after its
one job. Keep UTM running, the Windows user signed in and the USB redirected.
Enter PIN prompts directly in Windows; never put the PIN in an argument, file,
repository variable or GitHub secret. Restrict runner/registration directories
to the signing user and SYSTEM. Do not assign pull-request jobs to this runner.

Current local tools:

- Official Microsoft SDK x86 SignTool: `C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x86\signtool.exe`.
- Inno compiler: `C:\EDRSigning\InnoSetup6\ISCC.exe`.
- GitHub CLI: `C:\EDRSigning\gh\bin\gh.exe` (add this directory to runner PATH).
- Runner: `C:\EDRSigning\runner`.

The x86 tool is intentional for the installed USB middleware. The vendor's
similarly named `signtool.exe` is not interchangeable with Microsoft's CMS
options. SignTool calls have a 180-second timeout and fail closed; unlock the
token and diagnose a timed-out call before retrying. No unsigned fallback exists
in the USB finalization job. Use a fresh output directory for each attempt.

## Repository variables (all public metadata)

| Variable | Value |
| --- | --- |
| `WINDOWS_USB_THUMBPRINT` | Exact code-signing certificate SHA-1 thumbprint |
| `WINDOWS_USB_SIGNER_SUBJECT` | Canonical Go `x509.Certificate.Subject.String()` from that same certificate |
| `WINDOWS_USB_SIGNTOOL_PATH` | Absolute Microsoft SignTool path above |
| `WINDOWS_USB_INNO_PATH` | Absolute Inno compiler path above |

Windows's display subject and Go's canonical subject differ in attribute order,
escaping and unknown OIDs. Do not copy the Windows certificate display string
into `WINDOWS_USB_SIGNER_SUBJECT`. Derive it from the public certificate with
the platform's Go X.509 parser, verify its thumbprint, then set the variable.
The backend's strict subject comparison remains unchanged. Certificate rotation
requires updating both public identity variables and the platform trust policy.
Do not change `WINDOWS_RELEASE_MODE` globally until a full USB release passes.

## Verification and recovery

`tests/test_windows_store_signing.ps1 -SignTool <path>` creates a temporary
software code-signing certificate, exercises detached CMS and tamper rejection,
then removes its own certificate/key. GitHub runs it on both native builders
for USB releases. Add `-Thumbprint <USB certificate>` to test the real token;
this mode never removes the real certificate or key. Syntax validation includes
all new scripts. Native lifecycle gates are not replaced by these unit checks.

If registration or signing fails, retain the protected diagnostic log, remove
unused short-lived registration material, and re-register an ephemeral runner
for the next attempt. Do not republish an immutable release or disable platform
signature verification to work around a failure.
