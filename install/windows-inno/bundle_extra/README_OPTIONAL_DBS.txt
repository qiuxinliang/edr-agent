Optional SQLite data files (EDR Agent)

- edr_queue.db: Created at runtime if offline queue is used (default path may be under install dir
  or overridden by agent.toml / environment). Not shipped; no action needed for a clean install.

- cert_whitelist / IOC / file-hash DBs: Optional. If agent.toml points to paths under {app}\data\,
  place or sync vendor-supplied .db files there. The agent can operate with cert_whitelist_db_path
  empty; Stage0 still uses built-in trust rules + WinVerifyTrust for common cases.

- Empty schemas are not required for a working install. Populate DBs from your platform release process.

For ONNX models, copy static.onnx / behavior.onnx (and any others your build expects) into the
install staging folder edr-agent\models\ before building the installer, or add them to {app}\models
post-install. The repository models\ folder may only contain README until you sync from your model pipeline.
