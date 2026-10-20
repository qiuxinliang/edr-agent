# Bounded preprocessing stop diagnostic

`test_preprocess_stop_boundary` measures the current real preprocessing loop,
P0 emitter, IR loader and SQLite owners. The native comparison workflow builds
this opt-in target explicitly; it is not part of ALL or the release CTest count.
Production sources and shipped binaries are unchanged by this fixture.

The generator wraps calls once, retaining evaluation order and return values,
and verifies that removing the probes reproduces both original sources exactly.
The target reuses the runtime test objects, replacing only pipeline, P0 emitter
and the original policy owner with its existing deny-action test hook.

On Windows, one parent launches two fresh, Job-owned child processes, once each:
canonical authenticated IR ready, then genuinely missing IR. Together they have
85 seconds of work plus five seconds of terminal cleanup, a sampled cumulative
256 MiB fixture file-length guard and a combined 1 MiB worker-log guard. These
are sampled limits, not an OS disk quota. Unknown exit, forced termination,
missing completion receipts or failed cleanup fail the diagnostic. Artifacts
contain fixed numeric logs, hashes and source closure, never SQLite or rules.

Each child offers 16 synthetic process/network/file slots for its own live
process generation, sets the stop flag, and directly enters the real worker
loop. Windows child identities and observation times differ across variants;
compare their normalized input shape, not equality of raw input hashes.
The test separately reports a cold process-evidence request and seed creation,
then resets counters before measuring the loop. Stage timings are inclusive:
never add parent and child totals. The parent callback has no direct wrapper;
zero calls at stage 29 do not establish that it was not executed.

The fixture verifies one pre-existing necessary source owner's frozen bytes.
It does not verify every new input's durable disposition, SCM behavior, the
public start/join path, a running Agent, collectors, AVE, transport, or crash
recovery. Passing it is diagnostic evidence, not Service rollback acceptance.
No external action or network transport is initialized. Remove these probes
when the slow boundary is resolved and its focused regression owns coverage.
