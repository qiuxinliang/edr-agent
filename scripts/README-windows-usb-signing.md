# Windows USB signing release

## Responsibility boundary

Use `edr-agent client release` with `release_mode=usb` and a new version.
USB is the default for both tags and manual runs. `prepare-release` resolves the
mode once and all build/sign/lifecycle/publish gates consume that output. Missing
repository variables cannot disable signing. Tag releases reject `unsigned`;
only an explicit manual `release_mode=unsigned` permits an unsigned test release.
Set `WINDOWS_RELEASE_MODE=usb` in the repository for older workflows that still
depend on this variable. A new source commit requires a new release version.

GitHub compiles, assembles Inno installers, creates ZIPs, verifies hashes and
publishes. UTM only signs allowlisted EXEs and small detached CMS manifests.
It never downloads a complete package, source tree, DLL set or rules bundle,
and needs no Inno compiler or GitHub release-write permission.

| Phase | GitHub sends to USB | USB returns | GitHub then does |
| --- | --- | --- | --- |
| native | FDSensor, installer worker, uninstaller, two collectors, Setup UI EXEs | Signed EXEs and request-bound receipt | Verify unchanged program payload and publisher; rebuild Inno |
| installer | FDSecuritySetup.exe and small setup-ui-manifest.json | Signed installer; manifest with updated installer hash and CMS | Verify only that hash changed; assemble runtime/UI ZIPs and final release hashes |
| manifest | Final artifact-manifest.json | Same JSON plus detached CMS | Verify all final hashes; upload to draft and run native lifecycle gates |

The installer EXE necessarily contains the packaged payload. That EXE must be
signed after assembly; it cannot reuse the pre-assembly signature. It is the
only packaged payload sent to USB: runtime ZIPs, Setup UI ZIPs and source state
remain on GitHub. Final manifests are signed after ZIP hashing; there is no
whole-ZIP signing or local repackaging.

`package-state-*` artifacts are hosted-only checkpoints (3-day retention).
`usb-<phase>-request-<arch>` contains a flat allowlist and request identity
(commit/version/architecture/phase, SHA256, size); no arbitrary extension or
extra file is accepted. The private signing repository runs its reviewed snapshot
of the signing helpers, never source code from a public request. First-party signatures are checked for exact
publisher and timestamp; byte-level checks reject replacement with a different,
otherwise correctly signed program. Upstream WinDivert/Velociraptor signatures
are not replaced.

Both architectures must validate before draft uploads. The publish job remains
gated on native install, upgrade and rollback tests. Runtime identity is rebuilt
from signed components and forces `installer_required`, not `binary_hot`.
Existing PFX and unsigned release paths remain supported.

## Runner lifecycle and security

The fixed runner belongs ONLY to private `qiuxinliang/edr-agent-signing`.
The public repository dispatches a private request from a GitHub-hosted runner;
it has no runner registered on the USB host. Private hosted admission validates
the exact source repository, release workflow, active run attempt, commit,
tag/version (or manual main release) and both architecture artifact IDs before
scheduling the hardware host. The private host rechecks source freshness before
signing and before returning results. Private signing results are downloaded
back into the original run and pass the unchanged hosted integrity gates.

The runner runs interactively as the certificate owner, never as SYSTEM.
Register once WITHOUT `--ephemeral`, using labels
`self-hosted,Windows,edr-usb-signing`. Install the private repository's
`scripts/Install-RunnerLogonTask.ps1` once elevated. It starts the fixed runner
when the signing user logs on, prevents duplicate starts and restarts unexpected
exits (1-minute delay, up to 999 restarts; inspect the task if exhausted).
Keep UTM running, its user
signed in and the USB redirected. Enter PINs directly in Windows; never export
the key or store PINs in scripts, arguments, variables or GitHub secrets.

This pipeline still has THREE sequential USB jobs (both architectures in each),
all served by the same private runner. No per-phase registration or Mac daemon
is required. Do not register this persistent runner with the public repository.
The hosted bridge has a 30-minute wait deadline and cancels its known private run
on failure/cancellation. Source freshness checks also prevent stale queued jobs
from signing/returning results. Signing jobs
serialize on `edr-usb-token`, have a 20-minute deadline, and SignTool has a
180-second per-call deadline. No untrusted PR jobs, unsigned fallback, or key
export is allowed. Restrict runner directories to the signing user and SYSTEM.

Required local tool: official Microsoft SDK SignTool, e.g.
`C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x86\signtool.exe`.
The x86 tool matches the local USB middleware. UTM no longer needs Inno or
GitHub CLI for signing jobs; artifacts are transferred using Actions.

## Repository variables (public metadata)

- `WINDOWS_USB_THUMBPRINT`: exact certificate SHA1 thumbprint.
- `WINDOWS_USB_SIGNER_SUBJECT`: that certificate's canonical Go
  `x509.Certificate.Subject.String()`, not Windows's display string.
- `WINDOWS_USB_SIGNTOOL_PATH`: official local SignTool path.

`WINDOWS_USB_INNO_PATH` is no longer consumed. Hosted packaging uses its installed
Inno Setup 6 compiler and fails clearly if missing. Backend trusted roots,
publisher allowlist, strict subject validation and all manifest hashes remain
required. Until the hardware path passes, USB releases remain blocked rather
than falling back to unsigned publication.

## One-time cross-repository access

Configure `USB_SIGNING_TOKEN` in BOTH repositories: a dedicated fine-grained PAT
limited to `edr-agent` and `edr-agent-signing`, Actions read/write and automatic
Metadata read ONLY. It dispatches/reads private signing runs and reads public
request artifacts; it does not need Contents write, administration or key access.
Use `gh secret set USB_SIGNING_TOKEN --repo <repository>` interactively, never
commit the credential or reuse a personal CLI OAuth token. Rotate before expiry.
The private signing repository must remain private, restricted to trusted release
maintainers, with no PR-triggered hardware jobs. Review signing-code updates
separately; a source release must not automatically replace trusted signing code.

`WINDOWS_USB_THUMBPRINT` and `WINDOWS_USB_SIGNTOOL_PATH` are also configured in the
private repository. The public repository retains publisher configuration for
hosted verification. A missing token/private workflow fails before native builds.
An offline runner is reported as waiting, then terminal failure, never unsigned
success. Existing release tags retain their old workflows; publish a NEW version
after merging this bridge, do not retag immutable releases.

## Verification and recovery

`tests/test_windows_usb_exchange.ps1` checks identity, allowlists, duplicates,
tampering, unexpected ZIPs, program-payload replacement and CMS response binding.
With `-SignTool <path> -Thumbprint <USB thumbprint>` it also compiles a disposable
test EXE and validates a real timestamped USB signature. It removes only its
own temporary files/software test certificate, never the USB certificate.
`tests/test_windows_store_signing.ps1` covers SignTool's detached CMS encoding.
Syntax and exchange checks run on both native build hosts.

A failed signing phase produces no publishable success. Retry from the prior
hosted checkpoint with a fresh response directory; reuse the fixed private runner;
never overwrite an immutable published release. Import the verified final bundle
into the platform; CI success alone does not prove platform trust or endpoint
installation success.
