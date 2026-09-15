# Windows release flow

The release workflow is restored to the path before commit `cd8c25eb` introduced
USB signing. Later Agent fixes and built-in collector runtime/hash checks remain.

The job graph is prepare draft, native AMD64/ARM64 build and tests, native
install/upgrade/rollback validation, then combined Release publication. There is
no private-repository dispatch, self-hosted USB job, hosted signed-file repackaging,
or candidate/release-purpose selector in the public workflow.

Manual runs support the original `unsigned` and `signed` modes. Tag runs use
`WINDOWS_RELEASE_MODE`, falling back to `unsigned`. `signed` is the original
GitHub-hosted PFX path, not USB. Unsigned output must remain explicitly labelled;
restoring this workflow does not relax platform/Agent trust policy or guarantee
that a platform requiring signatures will accept the unsigned bundle. Native
lifecycle tests, package hashes, policy/rule verification and published-release
immutability are unchanged.

Existing runs and tags keep their workflow snapshot. Use a new version/ref that
contains the restoration; rerunning an old tag still shows the old jobs.

Private signing repository, runner registration, certificate and secrets are not
deleted. They are no longer referenced by this public release pipeline and can
be revisited separately if hardware signing is needed later.
