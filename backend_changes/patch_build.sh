#!/bin/bash
set -euo pipefail

# Patch build.go with RTR route registrations.
# Usage: bash patch_build.sh [path/to/internal/server/build.go]

FILE="${1:-internal/server/build.go}"
if [[ ! -f "$FILE" ]]; then
  echo "build.go not found: $FILE" >&2
  exit 1
fi

patch_after_pattern() {
  local marker="$1"
  local already="$2"
  local insertion="$3"
  if grep -q "$already" "$FILE"; then
    return 0
  fi
  awk -v marker="$marker" -v insertion="$insertion" '
    $0 ~ marker { print; print insertion; next }
    { print }
  ' "$FILE" > "$FILE.tmp"
  mv "$FILE.tmp" "$FILE"
  if ! grep -q "$already" "$FILE"; then
    echo "failed to patch $already into $FILE" >&2
    exit 1
  fi
}

patch_after_pattern \
  'v1.GET.*\/shell\/:task_id\/result.*hShell.GetShellResult' \
  'PostShellOpen' \
  '	v1.POST("/endpoints/:id/shell/open", middleware.RequireLicenseWriteAllowed(adminRepo, platformService.ActionCommandDispatch), middleware.RequirePermission("endpoint:forensic"), hShell.PostShellOpen)
	v1.POST("/endpoints/:id/shell/input", middleware.RequireLicenseWriteAllowed(adminRepo, platformService.ActionCommandDispatch), middleware.RequirePermission("endpoint:forensic"), hShell.PostShellInput)
	v1.POST("/endpoints/:id/shell/close", middleware.RequireLicenseWriteAllowed(adminRepo, platformService.ActionCommandDispatch), middleware.RequirePermission("endpoint:forensic"), hShell.PostShellClose)'

patch_after_pattern \
  'v1.POST.*\/forensic\/schedule.*hForensicP2.PostScheduledForensic' \
  'PostDeepForensic' \
  '	v1.POST("/endpoints/:id/forensic/deep", middleware.RequireLicenseWriteAllowed(adminRepo, platformService.ActionCommandDispatch), middleware.RequirePermission("endpoint:forensic"), hForensicP2.PostDeepForensic)'

echo "build.go patched"
