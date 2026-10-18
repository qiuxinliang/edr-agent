# Disposable exact 692 → 695 / 697 recovery cohorts

The existing `prepare_disposable_695.py` filename remains the compatibility entry
point. Its default remains cohort 695. `recovery_cohorts.json` is the single QA
pin owner shared by preparation, the manual workflow selector, the original Go
file-list exporter, and the bounded raw-evidence collector. Only the literal
695 and 697 selectors exist; there is no caller source/run/asset URL override.
The Go overlay embeds the same JSON bytes copied into its existing source-owner
directory; this adds no product dependency or runtime component.

Cohort 695 retains the original source/run/tool and published Headless/preflight
pins below. Cohort 697 names source `f672059aec426aafe00b216c482dc151b96226c9`
and native run `39078106854/1`. Its bound candidate release is `416133839`,
run `39080074060/1`; passed native artifact is `12118710280`. Actual original
handler proof SHA starts `5263b6bee76c`; the independently exported P5 SHA is
`aeead1e75ba84453ec6c03f4b487dfa5381ceb29069c39be95ee79cec8997d3c`.
The full exact pins live only in the authoritative JSON, not these short labels.
The workflow first checks out its own QA source to read this data, then resolves
the closed profile before product checkout. Any missing/UNBOUND pin still refuses
before product I/O, and never selects695 as a fallback.

These actual published/byte/preflight/export bindings do not imply a697 recovery
pass. Root must separately approve applying this QA data and a single disposable
run; no live API authentication, catalog import or endpoint deployment happened
in the in-process handler verification. The original 695 bytes and failed
cohorts are immutable evidence. The driver, 45/30/900-second limits, service
sampler and collector's 24-name/1MiB-per-file/8MiB-total contract are unchanged.
The new artifact name includes its actual cohort; 697 cannot be labelled 695.

This QA profile exists only for the current shutdown-stage investigation. After
that diagnostic cohort has a fixed accepted/failed evidence record and no active
consumer, remove its executable selector/profile together while retaining the
immutable external evidence; it is not a generic release catalog or product
configuration. Do not edit a closed profile to retarget a different product.


This is a manually dispatched, GitHub-hosted Windows ARM64 test. It uses the
existing Headless checkpoint, backend builder, native storage fixture and embedded
updater owners. It adds no production API/CLI, signing material, catalog entry,
endpoint task, publisher call, Release asset or product payload. Apply and dispatch
remain with the release owner. No workflow run or recovery result is implied by
this proposal.

## Immutable inputs

- Baseline `win_3.2.692`, source `a978ec83deacf7cd78c273d82630b457c5f39251`,
  published release ID `415024985`; never “latest”.
- Target `win_3.2.695`, source `694a4f47cfd55a7c98f8dab62617520c0c6251b1`,
  Headless release run `39054352162`.
- Passed ARM64 native tool artifact `12107948816`, run `39051197046/1`, same
  source; exact archive SHA/size and production PE/DLL closure are mandatory.
- Original backend `platform/internal/installer/full_installer.go` SHA
  `695c9a0de7d9fe7714918147982aec29aa8061c058702a427a9dee268f2e43a9`.
  Its 4,126 bytes are supplied as canonical base64 input, not copied into this
  repository. The exact bytes exist only under `RUNNER_TEMP` after validation.
- Actual original-handler verification wrapper, SHA-pinned by the caller. Its
  schema is `edr.ci-original-handler-verification.v1`, origin
  `ci_original_handler_verification`, `authenticated_platform_http=false`.
  It binds the original handler SHA, builder SHA, actual source/run/arch, raw
  manifest, Agent, Headless ZIP, exact preflight response and expected P5 SHA.
  An ordinary HTTP body, UNBOUND data, synthetic receipt or mismatched hash fails.
  This input does **not** establish platform API authentication or live policy.

## Workflow and package preparation

The existing registered lifecycle workflow keeps its original five workflow-call
inputs, default native job and permissions. Its manual form adds five optional
inputs (ten total). Only explicit `cache_recovery_subset=true` selects this
manual-only job; the normal native job keeps its original default behavior. This
independent job explicitly overrides inherited permissions with `contents: read`
and `actions: read`, a same-repository token, one disposable `windows-11-arm`
runner and a 90-minute outer job limit. It fails unless the selected exact target profile is closed, baseline692,
Headless and ARM64 are explicitly selected. Dispatch data travels through environment variables, never shell
source interpolation. No cross-repository or P0 key is needed. Missing permission,
HTTP 403, missing/expired artifact or a failed exact-byte check is terminal;
there is no token fallback, scope expansion or automatic retry.

The existing checkpoint's complete Headless publication contract requires the
original six assets. Only each ARM64 ZIP and manifest are downloaded. The raw
Agent is verified from that ZIP against its original Release metadata. Baseline
and target are staged by the existing `stage_headless` owner. The passed native
artifact has an exact bounded archive inventory, then the original stager plus
strict snapshot consumer verify native machine, size, hash and dependency closure.

The stdlib Go file-list overlay calls the supplied, fixed-hash original
`BuildHeadlessFullInstaller`. It does not reimplement or vendor that function.
The resulting P5 ZIP must equal the actual original-handler P5 SHA byte for byte
and is created exclusively in the fresh private directory. It is never registered,
promoted, made latest, added to a Release or sent to an endpoint.

## Actual recovery path

Before machine changes the driver verifies the passed TOOL manifest/complete
closure and all source inputs, and refuses any pre-existing real installation,
ProgramData directory, installer service/task alias or Agent process alias.

A two-second real native library fixture creates synthetic owners and the new
floor schema. The test copies only that fixture's DB/WAL/SHM into its owned
private directory and snapshots owner/ref/fact/command/hash state. **The library
prepares the new schema before either installed runtime; this is not Agent first
migration.**

The normal public config template keeps its original budgets and TTLs. Five public
scalars bind the synthetic endpoint, tenant, loopback-only REST address, queue and
cache. Each `Installed()` check verifies the original complete config SHA, those
scalars, the exact service executable/generation/runtime hashes, SCM image path,
and the actual process command line emitted by both existing service owners:
`"FDSensor.exe" --service --service-name "FDSecurityAgent" --config "…\agent.toml"`.
There must be exactly one `--config`. Raw command lines are never returned.
This proves configuration binding, not actual cache admission or migration.

The target's existing `--storage-space-preflight` owner derives the local free
floor from this config and owner inventory, with its unchanged 15-second native
watchdog (20-second parent observation/cleanup bound). This entry point performs
no Agent initialization, collection, migration, maintenance or network. The
actual updater floor is `max(native owner floor, manifest minimum, explicit
higher_min_free_bytes)`; the optional input defaults to zero. The selected numeric
values, config hash and native output hash are retained. Queue/evidence budgets
are not substituted for the command-owner free-floor formula. A higher override
is labeled explicit, not the default. No policy/default is modified.

The original 692 Headless setup installs the baseline. Its original embedded
updater runs the target's real `installer_required` class with the verified P5.
The driver waits for the exact journal's health stage and verified previous 692
backup before stopping its owned service to induce failure. It requires original
automatic rollback and journal/report terminal evidence, then uses the restored
692 owner for normal recovery upgrade. Finally the current embedded owner uses
normal same-version Headless repair after removing only this fixture's own Inno
uninstaller pair. Owner snapshots must remain equal after each transition.

The updater's 900-second requested window and outer observation do not establish
an internal absolute-expiry guarantee. SCM operations run in owned 45-second
children with up to 10 seconds kill grace; a timed-out SCM request is not claimed
cancelled. Timeout cleanup failure includes only its exception type and remains
failed/unknown. The 90-minute workflow limit is an overall backstop, not a hard
bound on every Windows kernel operation.

## Required evidence and limits

All preparation, native owner, rollback and repair checks must actually execute
before reporting this subset passed. Pure helper mocks, YAML parsing and
PowerShell ParseFile are separate checks. `test_recovery_driver_contracts.ps1`
loads only six hash-bound AST function definitions and runs eight file/mock
contracts; it never evaluates driver top-level or starts a native process. Unknown output or operation state fails.
The private QA upload retains a fixed whitelist for seven days: eight selected
synthetic metadata snapshots, the three transitions' exact intent, original
updater report/journal, stdout/stderr, and the single requested health trigger.
These are only this CI fixture's public identities, loopback endpoints and
credential-free updater parameters, not real Agent logs. A separate collector
binds the exact input/stage/summary and phase identities, refuses reparses,
reads each file at most declared-size+1 and checks handle/path identity before
and after. Per file is at most1MiB; all copied bytes plus the SHA/size manifest
are at most8MiB. Zero-byte stdout/stderr is legitimate. The original bytes are
copied exclusively, not reserialized. Unlisted files are never traversed or
read. Products, config, environment, keys, evidence DB/WAL/SHM, parameter XML,
full Agent/installer logs and any other directory remain excluded.

A passed driver requires all24 whitelisted files; missing evidence refuses
collection. For failed/unknown phases, the collector retains available bound
files and explicitly lists not-observed names without inferring that an action
did not occur or that recovery succeeded. No matching owned summary means no
export; oversize, identity changes or other validation errors fail collection
and never upload unverified partial copies. A SHA manifest binds every copied
file; its own hash is emitted to the CI step log. A successful collector is not
a recovery pass. The source's unknown child state is not promoted to terminal
by a stable file read.

This subset does not prove platform-authenticated or signed remote command
transport, true Agent first migration, normal parent-context admission, arbitrary
power-loss recovery, full updater interrupt coverage, real-data migration/deletion,
72-hour retention or whole-Agent load. Existing 695 updater timestamp/time-zone
and cross-time-zone resume concerns remain separate; successful fresh local
transitions must not be used to erase that independently confirmed issue.
