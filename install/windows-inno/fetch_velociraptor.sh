#!/usr/bin/env bash
# 从官方 GitHub Release 获取 Velociraptor(多架构:amd64/intel + arm64),用于平台自托管分发。
#
# 设计(诚实、可审计):
#   - **不硬编码可能过时的哈希**:从 GitHub Release API 解析资产名与官方 digest(sha256:...),
#     下载后本地 sha256 必须与官方 digest 一致;运维亦可用 EDR_VELO_SHA256_<ARCH> 覆盖做强 pin。
#   - **多架构**:默认拉 windows-amd64 + windows-arm64;某架构官方未构建则**如实跳过**(不伪造)。
#   - **AGPL 合规**:每架构随附 LICENSE 全文 + SOURCE 指引;velo 存在而合规件缺失即失败。
#   - **离线友好**:已存在且校验通过则跳过下载;EDR_VELO_LOCAL_<ARCH> 可指向本地预备件(仍校验)。
#
# 用法:
#   ./fetch_velociraptor.sh                         # 拉 amd64+arm64 到 collector_stage/<arch>/
#   EDR_VELO_ARCHES="amd64" ./fetch_velociraptor.sh # 仅某些架构(空格分隔)
#   EDR_VELO_VERSION=v0.77.1 ./fetch_velociraptor.sh
#   EDR_VELO_SHA256_amd64=<hex> ./fetch_velociraptor.sh   # 强 pin 覆盖(可选)
#   EDR_VELO_LOCAL_arm64=/path/velo-arm64.exe ./fetch_velociraptor.sh  # 用本地件
#
# 产出: collector_stage/<arch>/{velociraptor.exe, velociraptor.LICENSE.txt, velociraptor.SOURCE.txt}
# 上传到平台(运维中心→响应中心→取证采集器),或交给打包脚本。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

VERSION="${EDR_VELO_VERSION:-v0.77.1}"
ARCHES="${EDR_VELO_ARCHES:-amd64 arm64}"
OUT_ROOT="${EDR_VELO_OUT:-$SCRIPT_DIR/collector_stage}"
REPO="Velocidex/velociraptor"
API="https://api.github.com/repos/$REPO/releases/tags/$VERSION"

need() { command -v "$1" >/dev/null 2>&1 || { echo "FATAL: 需要 $1" >&2; exit 1; }; }
need curl

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}';
  else echo "FATAL: 无 sha256sum/shasum" >&2; return 1; fi
}

lc() { tr '[:upper:]' '[:lower:]'; }

# 拉取一次 release 元数据缓存(资产名 / 下载链接 / 官方 digest)。
RELEASE_JSON="$(mktemp)"
trap 'rm -f "$RELEASE_JSON"' EXIT
echo "==> 查询官方 Release: $REPO@$VERSION"
if ! curl -fsSL -H "Accept: application/vnd.github+json" "$API" -o "$RELEASE_JSON"; then
  echo "FATAL: 无法访问 GitHub Release API(本机需可达 github.com)。" >&2
  echo "       离线场景:用 EDR_VELO_LOCAL_<arch> 指向预先下好的官方二进制。" >&2
  exit 1
fi

# 从 release json 中解析某架构的资产 name/url/digest。优先 python3(健壮),回退 grep。
resolve_asset() {
  local arch="$1" field="$2"  # field: name|url|digest
  if command -v python3 >/dev/null 2>&1; then
    # 程序经 heredoc(stdin)传入;release json 路径与参数经 argv 传入(避免与 stdin 冲突)。
    python3 - "$RELEASE_JSON" "$arch" "$field" <<'PY'
import sys, json
path, arch, field = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, encoding="utf-8") as f:
    data = json.load(f)
want = f"windows-{arch}.exe"
for a in data.get("assets", []):
    name = a.get("name", "")
    if name.lower().endswith(want) and "velociraptor" in name.lower():
        if field == "name": print(name)
        elif field == "url": print(a.get("browser_download_url", ""))
        elif field == "digest": print((a.get("digest") or "").replace("sha256:", ""))
        break
PY
  else
    # 粗回退:无 python3 时只取 url(digest 留空,靠 LOCAL/强 pin)
    grep -oE "https://[^\"]*velociraptor[^\"]*windows-${arch}\.exe" "$RELEASE_JSON" | head -1
  fi
}

fetch_arch() {
  local arch="$1"
  local out_dir="$OUT_ROOT/$arch"
  local velo_out="$out_dir/velociraptor.exe"
  local lic_out="$out_dir/velociraptor.LICENSE.txt"
  local src_out="$out_dir/velociraptor.SOURCE.txt"
  mkdir -p "$out_dir"

  local name url digest
  name="$(resolve_asset "$arch" name || true)"
  url="$(resolve_asset "$arch" url || true)"
  digest="$(resolve_asset "$arch" digest || true)"

  # 运维强 pin 覆盖
  local pin_var="EDR_VELO_SHA256_${arch}"
  local pin="${!pin_var:-}"
  [[ -n "$pin" ]] && digest="$pin"

  # 本地预备件覆盖
  local local_var="EDR_VELO_LOCAL_${arch}"
  local local_bin="${!local_var:-}"

  if [[ -n "$local_bin" ]]; then
    echo "==> [$arch] 使用本地件: $local_bin"
    cp -a "$local_bin" "$velo_out"
  elif [[ -z "$url" ]]; then
    echo "!!  [$arch] 官方 $VERSION 未发布 windows-$arch 资产 → 跳过(不伪造)。" >&2
    echo "    如需该架构:自行从源码构建或换版本,再用 EDR_VELO_LOCAL_$arch 提供。" >&2
    rmdir "$out_dir" 2>/dev/null || true
    return 0
  else
    if [[ -f "$velo_out" && -n "$digest" ]] && [[ "$(sha256_of "$velo_out" | lc)" == "$(echo "$digest" | lc)" ]]; then
      echo "==> [$arch] 已存在且校验通过,跳过下载。"
    else
      echo "==> [$arch] 下载 $name"
      curl -fL --retry 3 --max-time 900 -o "$velo_out" "$url"
    fi
  fi

  # 校验(有 digest 才能强校验;无 digest 则警告)
  if [[ -n "$digest" ]]; then
    local got; got="$(sha256_of "$velo_out" | lc)"
    if [[ "$got" != "$(echo "$digest" | lc)" ]]; then
      echo "FATAL: [$arch] SHA256 不匹配" >&2
      echo "  expected: $digest" >&2
      echo "  got:      $got" >&2
      exit 1
    fi
    echo "    [$arch] SHA256 OK: $got"
  else
    echo "!!  [$arch] 无官方 digest 且未提供 EDR_VELO_SHA256_$arch → 未做哈希 pin(生产建议补 pin)。" >&2
  fi

  # AGPL 合规件(LICENSE 同步拉取 + SOURCE 指引)
  if [[ ! -s "$lic_out" ]]; then
    curl -fsSL --retry 3 --max-time 60 \
      -o "$lic_out" "https://raw.githubusercontent.com/$REPO/$VERSION/LICENSE" \
      || { echo "FATAL: [$arch] 无法获取 AGPLv3 LICENSE(分发义务必须随附)" >&2; exit 1; }
  fi
  [[ -s "$lic_out" ]] || { echo "FATAL: [$arch] LICENSE 为空" >&2; exit 1; }

  cat > "$src_out" <<EOF
Velociraptor — 第三方取证引擎(外部调用,未修改)
====================================================
版本(pinned): ${VERSION}
架构:         windows-${arch}
资产:         ${name:-velociraptor-${VERSION}-windows-${arch}.exe}
SHA256:       ${digest:-(未 pin,见上)}
官方下载:     ${url:-https://github.com/${REPO}/releases/tag/${VERSION}}
源代码(tag):  https://github.com/${REPO}/tree/${VERSION}
许可:         AGPLv3(见同目录 velociraptor.LICENSE.txt)

合规声明: 本产品以未修改的官方 Velociraptor 二进制作为独立子进程外部调用(mere aggregation),
不内嵌/链接/repack 其代码,AGPLv3 不传染本产品自有代码;依分发义务随附许可全文与源获取地址。
EOF

  echo "==> [$arch] OK → $out_dir"
  ls -la "$out_dir"
}

echo "目标架构: $ARCHES"
for a in $ARCHES; do
  fetch_arch "$a"
done
echo "ALL DONE. stage 根目录: $OUT_ROOT"
