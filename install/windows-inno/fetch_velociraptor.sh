#!/usr/bin/env bash
# 获取官方 Velociraptor v0.77.1(Windows/amd64)二进制 + AGPL 合规文件,供取证采集器调用。
#
# 设计要点:
#   - **版本与哈希 pin**:只接受 SHA256 匹配的官方二进制,不匹配立即中止(防供应链篡改)。
#   - **AGPL 合规**:同步拉取官方 LICENSE,写 SOURCE 指引;二者缺失即失败(分发义务硬约束)。
#   - **未修改二进制**:外部子进程调用 = mere aggregation,AGPLv3 不传染本产品自有代码。
#   - **离线友好**:已存在且哈希匹配则跳过下载;可用 EDR_VELO_LOCAL 指向本地预备件。
#
# 用法:
#   ./fetch_velociraptor.sh                       # 下载到默认 stage 目录
#   EDR_VELO_OUT=/path ./fetch_velociraptor.sh    # 覆盖输出目录
#   EDR_VELO_LOCAL=/path/to/velociraptor.exe ./fetch_velociraptor.sh   # 用本地件(仍校验哈希)
#   EDR_VELO_SHA256=<hex> ./fetch_velociraptor.sh # 覆盖 pin(换版本时)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

VELO_VERSION="v0.77.1"
VELO_ASSET="velociraptor-${VELO_VERSION}-windows-amd64.exe"
VELO_URL="https://github.com/Velocidex/velociraptor/releases/download/${VELO_VERSION}/${VELO_ASSET}"
LICENSE_URL="https://raw.githubusercontent.com/Velocidex/velociraptor/${VELO_VERSION}/LICENSE"
# pin:对官方 v0.77.1 windows-amd64 实测核正(2026-06)。换版本必须同步更新或用 EDR_VELO_SHA256 覆盖。
VELO_SHA256="${EDR_VELO_SHA256:-c91cf8a32731c4c45c148393bc7d2af688c392194a9fffc4535e8b583260d55e}"

OUT_DIR="${EDR_VELO_OUT:-$SCRIPT_DIR/collector_stage}"
VELO_OUT="$OUT_DIR/velociraptor.exe"
LICENSE_OUT="$OUT_DIR/velociraptor.LICENSE.txt"
SOURCE_OUT="$OUT_DIR/velociraptor.SOURCE.txt"

mkdir -p "$OUT_DIR"

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}';
  else echo "no sha256 tool (sha256sum/shasum)" >&2; return 1; fi
}

verify() {
  local got; got="$(sha256_of "$1")" || return 1
  if [[ "$got" != "$VELO_SHA256" ]]; then
    echo "SHA256 mismatch for $1" >&2
    echo "  expected: $VELO_SHA256" >&2
    echo "  got:      $got" >&2
    return 1
  fi
}

# 1) 获取二进制(本地预备 > 已存在且匹配 > 下载)
if [[ -n "${EDR_VELO_LOCAL:-}" ]]; then
  echo "==> using local velociraptor: $EDR_VELO_LOCAL"
  cp -a "$EDR_VELO_LOCAL" "$VELO_OUT"
elif [[ -f "$VELO_OUT" ]] && verify "$VELO_OUT" 2>/dev/null; then
  echo "==> velociraptor.exe already present and verified, skip download"
else
  echo "==> downloading $VELO_ASSET"
  curl -fL --retry 3 --max-time 600 -o "$VELO_OUT" "$VELO_URL"
fi

# 2) 哈希 pin 校验(任何来源都必须过)
echo "==> verifying SHA256 pin"
verify "$VELO_OUT" || { echo "ABORT: velociraptor binary failed integrity check" >&2; exit 1; }
echo "    OK: $VELO_SHA256"

# 3) AGPL 合规:LICENSE(同步拉取) + SOURCE 指引(缺失即失败)
if [[ ! -s "$LICENSE_OUT" ]]; then
  echo "==> fetching AGPLv3 LICENSE"
  curl -fL --retry 3 --max-time 60 -o "$LICENSE_OUT" "$LICENSE_URL" \
    || { echo "ABORT: cannot fetch Velociraptor LICENSE (AGPL 分发义务必须随附)" >&2; exit 1; }
fi
[[ -s "$LICENSE_OUT" ]] || { echo "ABORT: empty LICENSE file" >&2; exit 1; }

cat > "$SOURCE_OUT" <<EOF
Velociraptor — 第三方取证引擎(外部调用,未修改)
====================================================

版本(pinned): ${VELO_VERSION}
资产:         ${VELO_ASSET}
SHA256:       ${VELO_SHA256}
官方下载:     ${VELO_URL}
源代码(对应 tag): https://github.com/Velocidex/velociraptor/tree/${VELO_VERSION}
许可:         AGPLv3(见同目录 velociraptor.LICENSE.txt)

合规声明:
  本产品(FDSecurity EDR)以**未修改的官方 Velociraptor 二进制**作为独立子进程外部调用
  (mere aggregation),不内嵌/链接/repack 其代码,故 AGPLv3 不传染本产品自有代码。
  依 AGPLv3 分发义务,本目录随附其许可全文与上述源代码获取地址。
EOF

echo "==> wrote AGPL compliance files:"
echo "    $LICENSE_OUT"
echo "    $SOURCE_OUT"
echo "OK: collector stage at $OUT_DIR"
ls -la "$OUT_DIR"
