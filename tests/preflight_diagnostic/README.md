# Frozen read-only startup preflight diagnostic

This test-only tool builds the original read-only routine and a temporary copy
with bounded in-memory phase and first-failure observation. It is not linked
into an Agent or installer. Product sources are never changed. Normal Agent
collection, writes, uploads and maintenance do not gain instrumentation.

Both storage modules are pinned to their canonical Git-blob SHA-256 at
`984b955a64f5513377c465426faf45f9a0e9bf72`. Original 723 has the same two modules.
The builder accepts only LF versus CRLF checkout differences, recording both
actual checkout and canonical digests. No other source variation is accepted.
The original private memory catalog, SQL, read-only target open, 200 ms busy
timeout, 1,000-operation progress interval and 2-second internal deadline are
unchanged. All callers must preserve the 6-second external process timeout.

Windows requires an x64 MSVC developer environment and an already verified
original 723 source checkout plus original runtime. It builds only two small
executables. It uses the installed Windows SDK SQLite header for declarations;
an import library is generated from the original package's `sqlite3.dll`
exports. It never links or substitutes system `winsqlite3.dll`. Compilation,
header or runtime failures are terminal; no fallback compiler/library is used.
Compiler, SDK header, copied original DLLs, source and result hashes are retained
in `build-manifest.json` and compiler/import logs.

```powershell
python tests/preflight_diagnostic/build.py `
  --baseline-source baseline-source `
  --baseline-runtime packages/baseline `
  --output preflight-tools
python tests/preflight_diagnostic/verify.py `
  --probe-root preflight-tools --output preflight-synthetic-results
```

`--source` aliases `--baseline-source`. `--sqlite-dll` can select the exact
verified package DLL instead of `--baseline-runtime`. Both are mutually
exclusive. The output directory must not already exist.

On a non-Windows host, omit the runtime argument to link the host system SQLite.
That is explicitly host-only validation, not Windows or historical CI evidence.

```sh
python3 -IB tests/preflight_diagnostic/build.py --source . --output /tmp/fresh-probe
python3 -IB tests/preflight_diagnostic/verify.py \
  --probe-root /tmp/fresh-probe --output /tmp/fresh-probe-cases
python3 -IB tests/preflight_diagnostic/test_build.py
```

The tools are named `preflight-original[.exe]` and `preflight-trace[.exe]`.
Their two arguments are the authorized DB path and configured budget in MiB;
zero retains the original default. Process exit 0 means a diagnostic ran;
JSON `result` is authoritative: 0 allowed, 1 capacity refusal, -1 unavailable.
The JSON is less than 8 KiB. Only static source SQL is emitted. Bindings,
evidence contents, dynamic schema identifiers, SQLite free-text errors and
environment variables are excluded. The first failure is never replaced by a
later close or terminal deadline check. SQLite may maintain SHM reader records;
DB and WAL are read only. The probe itself adds some work within the original
deadline, so near-deadline inputs require an original-versus-trace comparison.

The 12 synthetic cases compare both routines on the same input, verify DB/WAL
length and SHA after each, and retain raw stdout/stderr before assertions. They
cover committed WAL, invalid clocks, schema/format rejection and an exclusive
lock. They do not identify the unavailable historical CI first SQL, test the
2-second interruption branch, or replace actual 723/746 installer acceptance.
