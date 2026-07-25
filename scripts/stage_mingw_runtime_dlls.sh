#!/usr/bin/env bash
# Stage the complete non-system DLL closure next to a MinGW-built executable.
set -euo pipefail

EXE_PATH="${1:?usage: $0 <exe> <dependency-prefix> [mingw-gcc] [mingw-objdump]}"
DEPS_PREFIX="${2:?usage: $0 <exe> <dependency-prefix> [mingw-gcc] [mingw-objdump]}"
MINGW_GCC="${3:-x86_64-w64-mingw32-gcc}"
MINGW_OBJDUMP="${4:-x86_64-w64-mingw32-objdump}"
OUTPUT_DIR="$(cd "$(dirname "$EXE_PATH")" && pwd)"
EXE_PATH="$OUTPUT_DIR/$(basename "$EXE_PATH")"

if [[ ! -f "$EXE_PATH" ]]; then
  echo "ERROR: Windows executable not found: $EXE_PATH" >&2
  exit 2
fi
if [[ ! -d "$DEPS_PREFIX/bin" ]]; then
  echo "ERROR: MinGW dependency runtime directory not found: $DEPS_PREFIX/bin" >&2
  exit 2
fi
if ! command -v "$MINGW_GCC" >/dev/null 2>&1 && [[ ! -x "$MINGW_GCC" ]]; then
  echo "ERROR: MinGW GCC not found: $MINGW_GCC" >&2
  exit 2
fi
if ! command -v "$MINGW_OBJDUMP" >/dev/null 2>&1 && [[ ! -x "$MINGW_OBJDUMP" ]]; then
  echo "ERROR: MinGW objdump not found: $MINGW_OBJDUMP" >&2
  exit 2
fi

is_windows_system_dll() {
  local name
  name="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "$name" in
    api-ms-win-*.dll|ext-ms-win-*.dll|advapi32.dll|bcrypt.dll|cfgmgr32.dll|comctl32.dll|comdlg32.dll|crypt32.dll|dbghelp.dll|dnsapi.dll|dwmapi.dll|gdi32.dll|imm32.dll|iphlpapi.dll|kernel32.dll|kernelbase.dll|msvcrt.dll|mswsock.dll|netapi32.dll|ntdll.dll|ole32.dll|oleaut32.dll|powrprof.dll|psapi.dll|rpcrt4.dll|secur32.dll|setupapi.dll|shell32.dll|shlwapi.dll|tdh.dll|ucrtbase.dll|user32.dll|userenv.dll|version.dll|wevtapi.dll|winhttp.dll|winmm.dll|winspool.drv|wintrust.dll|ws2_32.dll|wtsapi32.dll)
      return 0
      ;;
  esac
  return 1
}

resolve_runtime_dll() {
  local dll="$1"
  local candidate sysroot
  for candidate in \
    "$DEPS_PREFIX/bin/$dll" \
    "$DEPS_PREFIX/debug/bin/$dll"; do
    if [[ -f "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  candidate="$("$MINGW_GCC" -print-file-name="$dll" 2>/dev/null || true)"
  if [[ -n "$candidate" && "$candidate" != "$dll" && -f "$candidate" ]]; then
    printf '%s\n' "$candidate"
    return 0
  fi

  sysroot="$("$MINGW_GCC" -print-sysroot 2>/dev/null || true)"
  if [[ -n "$sysroot" && -d "$sysroot" ]]; then
    for candidate in \
      "$sysroot/bin/$dll" \
      "$sysroot/x86_64-w64-mingw32/bin/$dll" \
      "$sysroot/mingw/bin/$dll"; do
      if [[ -f "$candidate" ]]; then
        printf '%s\n' "$candidate"
        return 0
      fi
    done
    candidate="$(find "$sysroot" -maxdepth 5 -type f -name "$dll" -print -quit 2>/dev/null || true)"
    if [[ -n "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  fi
  return 1
}

queue=("$EXE_PATH")
staged=()

enqueue_once() {
  local candidate="$1"
  local queued
  for queued in "${queue[@]}"; do
    if [[ "$queued" == "$candidate" ]]; then
      return 0
    fi
  done
  queue[${#queue[@]}]="$candidate"
}

record_staged_once() {
  local dll="$1"
  local current
  if (( ${#staged[@]} > 0 )); then
    for current in "${staged[@]}"; do
      if [[ "$current" == "$dll" ]]; then
        return 0
      fi
    done
  fi
  staged[${#staged[@]}]="$dll"
}

index=0
while (( index < ${#queue[@]} )); do
  target="${queue[$index]}"
  index=$((index + 1))
  "$MINGW_OBJDUMP" -p "$target" >/dev/null

  while IFS= read -r dll; do
    [[ -z "$dll" ]] && continue
    if is_windows_system_dll "$dll"; then
      continue
    fi

    if ! source_path="$(resolve_runtime_dll "$dll")"; then
      echo "ERROR: unresolved non-system runtime dependency '$dll' required by $(basename "$target")." >&2
      exit 3
    fi
    destination="$OUTPUT_DIR/$dll"
    if [[ "$source_path" != "$destination" ]]; then
      cp -f "$source_path" "$destination"
    fi
    record_staged_once "$dll"
    enqueue_once "$destination"
  done < <("$MINGW_OBJDUMP" -p "$target" | awk '/DLL Name:/ {print $3}')
done

echo "OK: staged ${#staged[@]} non-system runtime DLL(s) beside $(basename "$EXE_PATH")."
if (( ${#staged[@]} > 0 )); then
  for dll in "${staged[@]}"; do
    echo "  $dll"
  done
fi
