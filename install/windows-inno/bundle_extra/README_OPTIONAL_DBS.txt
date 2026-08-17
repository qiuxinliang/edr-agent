Optional SQLite data files (FDSecurity)

For the full list of what the bundled zip covers vs what ships separately, see BUNDLE_README.txt next to FDSensor.exe.

- edr_queue.db: Created at runtime if offline queue is used (default path may be under install dir
  or overridden by agent.toml / environment). Not shipped; no action needed for a clean install.

- cert_whitelist / IOC / file-hash DBs: Optional. If agent.toml points to paths under {app}\data\,
  place or sync vendor-supplied .db files there. The agent can operate with cert_whitelist_db_path
  empty; Stage0 still uses built-in trust rules + WinVerifyTrust for common cases.

- Empty schemas are not required for a working install. Populate DBs from your platform release process.

Endpoint ONNX models and federated-training artifacts are intentionally not supported by this package.
Use signed IOC, certificate/hash allow-lists, and rules supplied through the platform release process.
