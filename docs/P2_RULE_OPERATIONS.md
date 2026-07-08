# P2 Rule Operations

This pass keeps the existing engines and adds operational controls around them.

## Shellcode YARA Rules

- `edr_shellcode_known_init(rules_dir)` still falls back to builtin byte/semantic matchers.
- When YARA is available and `rules_dir` contains `.yar` / `.yara` files, rules are compiled atomically and replace the old rule set only after compile success.
- `edr_shellcode_known_reload_periodic(rules_dir, interval_s)` keeps the hot-reload path.
- `edr_shellcode_known_get_status()` exposes rule source, version, loaded file count, last reload time and last error.
- Version source priority:
  - `EDR_SHELLCODE_YARA_RULES_VERSION`
  - `${rules_dir}/VERSION`
  - fallback `yara-files-N`

The Agent `engine_health.shellcode` payload now includes `rule_version`, `rules_source`, `rules_loaded`, `last_reload_unix_s` and `last_error`.

## Forensic YARA Rules

`yara_scan` supports two rule sources:

1. inline `rules` in the command payload, used first for operator-supplied or catalog-expanded rules;
2. local forensic rules when inline rules are omitted.

Local forensic rule source priority is:

- `[command].forensic_yara_rules_dir`
- `EDR_YARA_RULES_DIR`
- fallback `rules/forensic`

The packaged Windows layout installs the local forensic rule set under `rules\\forensic`; shellcode and webshell rule sets are installed under `rules\\shellcode` and `rules\\webshell`. Runtime DLLs and rule directories are separate assets: the DLL makes the libyara engine available, while the rule directories provide signatures. Rule compile failures fail the scan explicitly; the degraded substring fallback is used only when `EDR_YARA_ALLOW_BUILTIN_FALLBACK=1` is set.

## WebShell AST / Token Rules

`src/webshell_detector/webshell_semantic.c` is a shared lightweight semantic layer used by Linux and Windows detectors. It scores:

- tainted request sources: `$_POST`, `$_GET`, `request.getParameter`, `Request.Form`, etc.
- execution sinks: `eval`, `system`, `Runtime.exec`, `Process.Start`, etc.
- decoders and dynamic calls: base64/gzip/ROT13/reflection/`call_user_func`/`String.fromCharCode`.
- write/upload/dropper behavior: `file_put_contents`, `move_uploaded_file`, Java stream input, `.php/.jsp/.aspx` output.
- memory loader hints: `ClassLoader`, `Assembly.Load`, `defineClass`, delegate/reflection loaders.

Detections emit `ast_score` and `token_score` in the WebShell ETW1 payload, so downstream `detection_context` can explain why the file was suspicious.

## AVE Tenant Noise And Canary Evaluation

`ave_suppression` now supports two operational tables in `behavior_policy_db_path`.

`ave_tenant_noise_policy`:

```sql
CREATE TABLE ave_tenant_noise_policy (
  tenant_id TEXT NOT NULL,
  model_version TEXT NOT NULL,
  rule_name TEXT NOT NULL,
  min_confidence REAL DEFAULT 0,
  max_confidence REAL DEFAULT 1,
  action TEXT NOT NULL,
  score_delta REAL DEFAULT 0,
  policy_version TEXT,
  gray_percent INTEGER DEFAULT 0,
  is_active INTEGER DEFAULT 1,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
```

Supported `action` values are `suppress`, `review`, `observe`, and `allow`. `tenant_id`, `model_version`, and `rule_name` support `*` wildcard rows.

`ave_model_gray_eval` stores shadow/canary evaluation output:

```sql
CREATE TABLE ave_model_gray_eval (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT,
  model_version TEXT,
  policy_version TEXT,
  rule_name TEXT,
  raw_confidence REAL,
  adjusted_confidence REAL,
  decision TEXT,
  shadow_verdict TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

This gives the server a stable source for model gray-release hit rate, false-positive feedback, rollback and tenant policy effectiveness.
