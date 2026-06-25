#!/usr/bin/env bash
# Standard Linux host isolation hook for FDSecurity.
#
# 由 agent 通过 EDR_ISOLATE_HOOK 或内置默认 enforcement 调用,语义对齐
# windows_isolate_host.ps1:enable 把主机网络切到默认拒绝,仅放行 loopback、
# 已建立连接、DNS 与管理服务器;remove 撤销并恢复;status 打印当前状态。
#
# 优先 nftables(独立 table inet <prefix>,可整体删除,不污染既有规则);
# 无 nft 时回退 iptables(保存/恢复 INPUT/OUTPUT 默认策略)。
#
# 环境变量(与 ps1 对齐):
#   EDR_CMD_ID                      agent 写入的命令 id(记录用)
#   EDR_ISOLATE_RULE_PREFIX         默认 EDR-Isolate → nft 表名 edr_isolate
#   EDR_ISOLATE_STATE_PATH          默认 /var/lib/fdsecurity/isolation/state
#   EDR_ISOLATE_ALLOW_REMOTE_ADDRS  逗号分隔 IP/CIDR(管理服务器,agent 会自动注入后端 IP)
#   EDR_ISOLATE_ALLOW_REMOTE_PORTS  逗号分隔端口,默认 443,50051
#   EDR_ISOLATE_DRY_RUN=1           只打印不执行
#
# 退出码:0 成功 / 1 失败(权限/无可用后端工具/规则应用失败)。
set -u

ACTION="${1:-enable}"
ACTION="$(printf '%s' "$ACTION" | tr '[:upper:]' '[:lower:]')"

PREFIX="${EDR_ISOLATE_RULE_PREFIX:-EDR-Isolate}"
# nft 标识符不允许 '-',规整为下划线小写。
TABLE="$(printf '%s' "$PREFIX" | tr '[:upper:]-' '[:lower:]_')"
STATE_PATH="${EDR_ISOLATE_STATE_PATH:-/var/lib/fdsecurity/isolation/state}"
PORTS="${EDR_ISOLATE_ALLOW_REMOTE_PORTS:-443,50051}"
ADDRS_RAW="${EDR_ISOLATE_ALLOW_REMOTE_ADDRS:-}"
DRY_RUN=0
[ "${EDR_ISOLATE_DRY_RUN:-0}" = "1" ] && DRY_RUN=1

log() { printf '%s\n' "$*"; }
err() { printf '%s\n' "$*" >&2; }

run() {
  # 执行一条命令;DRY_RUN 时只回显。
  if [ "$DRY_RUN" = "1" ]; then
    log "DRYRUN: $*"
    return 0
  fi
  "$@"
}

require_root() {
  [ "$DRY_RUN" = "1" ] && return 0   # dry-run 不改动,允许非 root 预览
  if [ "$(id -u)" != "0" ]; then
    err "Host isolation requires root (run agent as a privileged service)."
    exit 1
  fi
}

ensure_state_dir() {
  d="$(dirname "$STATE_PATH")"
  [ -d "$d" ] || run mkdir -p "$d"
}

# 把逗号分隔串转成空格分隔(去空项)。
csv_to_list() { printf '%s' "$1" | tr ',' ' '; }

have() { command -v "$1" >/dev/null 2>&1; }

# ---------------- nftables 实现 ----------------
nft_enable() {
  # 重新构建:先删旧表(幂等),再建默认 drop 的 input/output,放行白名单。
  run nft delete table inet "$TABLE" 2>/dev/null || true

  ports_nft="$PORTS"   # 已是逗号形式,nft set 直接用 {443,50051}
  # 组装规则脚本(单次 nft -f,避免逐条失败留下半套规则)。
  script="$(mktemp)"
  {
    echo "table inet $TABLE {"
    echo "  chain input {"
    echo "    type filter hook input priority 0; policy drop;"
    echo "    iif lo accept"
    echo "    ct state established,related accept"
    echo "  }"
    echo "  chain output {"
    echo "    type filter hook output priority 0; policy drop;"
    echo "    oif lo accept"
    echo "    ct state established,related accept"
    echo "    udp dport 53 accept"
    echo "    tcp dport 53 accept"
    for a in $(csv_to_list "$ADDRS_RAW"); do
      [ -n "$a" ] || continue
      echo "    ip daddr $a tcp dport {$ports_nft} accept"
    done
    echo "  }"
    echo "}"
  } >"$script"

  if [ "$DRY_RUN" = "1" ]; then
    log "DRYRUN: nft -f <<"
    cat "$script"
    rm -f "$script"
    return 0
  fi
  if ! nft -f "$script"; then
    rm -f "$script"
    err "nft: failed to apply isolation ruleset"
    return 1
  fi
  rm -f "$script"
  return 0
}

nft_remove() { run nft delete table inet "$TABLE" 2>/dev/null || true; return 0; }

nft_status() {
  log "engine: nftables"
  nft list table inet "$TABLE" 2>/dev/null || log "(no isolation table '$TABLE')"
}

# ---------------- iptables 回退实现 ----------------
ipt_enable() {
  # 保存现有默认策略以便恢复。
  in_pol="$(iptables -S INPUT 2>/dev/null | head -1 | awk '{print $2}')"
  out_pol="$(iptables -S OUTPUT 2>/dev/null | head -1 | awk '{print $2}')"
  [ -n "$in_pol" ] || in_pol="ACCEPT"
  [ -n "$out_pol" ] || out_pol="ACCEPT"
  if [ "$DRY_RUN" != "1" ]; then
    printf 'engine=iptables\nINPUT_POLICY=%s\nOUTPUT_POLICY=%s\n' "$in_pol" "$out_pol" >>"$STATE_PATH"
  fi

  run iptables -I INPUT 1 -i lo -j ACCEPT
  run iptables -I INPUT 2 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  run iptables -I OUTPUT 1 -o lo -j ACCEPT
  run iptables -I OUTPUT 2 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  run iptables -I OUTPUT 3 -p udp --dport 53 -j ACCEPT
  run iptables -I OUTPUT 4 -p tcp --dport 53 -j ACCEPT
  ports_csv="$PORTS"
  for a in $(csv_to_list "$ADDRS_RAW"); do
    [ -n "$a" ] || continue
    run iptables -I OUTPUT 5 -d "$a" -p tcp -m multiport --dports "$ports_csv" -j ACCEPT
  done
  run iptables -P INPUT DROP
  run iptables -P OUTPUT DROP
  return 0
}

ipt_remove() {
  in_pol="ACCEPT"; out_pol="ACCEPT"
  if [ -f "$STATE_PATH" ]; then
    v="$(grep '^INPUT_POLICY=' "$STATE_PATH" 2>/dev/null | tail -1 | cut -d= -f2)"; [ -n "$v" ] && in_pol="$v"
    v="$(grep '^OUTPUT_POLICY=' "$STATE_PATH" 2>/dev/null | tail -1 | cut -d= -f2)"; [ -n "$v" ] && out_pol="$v"
  fi
  run iptables -P INPUT "$in_pol"
  run iptables -P OUTPUT "$out_pol"
  # 删除我们插入的放行规则(按内容匹配,容错执行)。
  run iptables -D INPUT -i lo -j ACCEPT 2>/dev/null || true
  run iptables -D INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
  run iptables -D OUTPUT -o lo -j ACCEPT 2>/dev/null || true
  run iptables -D OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
  run iptables -D OUTPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || true
  run iptables -D OUTPUT -p tcp --dport 53 -j ACCEPT 2>/dev/null || true
  ports_csv="$PORTS"
  for a in $(csv_to_list "$ADDRS_RAW"); do
    [ -n "$a" ] || continue
    run iptables -D OUTPUT -d "$a" -p tcp -m multiport --dports "$ports_csv" -j ACCEPT 2>/dev/null || true
  done
  return 0
}

ipt_status() {
  log "engine: iptables"
  iptables -S INPUT 2>/dev/null | head -1
  iptables -S OUTPUT 2>/dev/null | head -1
}

# ---------------- 调度 ----------------
case "$ACTION" in
  enable)
    require_root
    ensure_state_dir
    if [ "$DRY_RUN" != "1" ]; then
      printf 'command_id=%s\nenabled_at_utc=%s\n' "${EDR_CMD_ID:-}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$STATE_PATH"
    fi
    if have nft; then
      nft_enable || exit 1
    elif have iptables; then
      ipt_enable || exit 1
    else
      err "neither nft nor iptables available; cannot isolate"
      exit 1
    fi
    log "Isolation enabled (allow addrs: ${ADDRS_RAW:-none}, ports: $PORTS). State: $STATE_PATH"
    ;;
  remove|disable|restore)
    require_root
    if have nft; then
      nft_remove
    fi
    if have iptables && [ -f "$STATE_PATH" ] && grep -q '^engine=iptables' "$STATE_PATH" 2>/dev/null; then
      ipt_remove
    fi
    [ "$DRY_RUN" = "1" ] || rm -f "$STATE_PATH" 2>/dev/null || true
    log "Isolation removed."
    ;;
  status)
    if have nft && nft list table inet "$TABLE" >/dev/null 2>&1; then
      nft_status
    elif have iptables; then
      ipt_status
    else
      log "no firewall backend available"
    fi
    [ -f "$STATE_PATH" ] && log "State file: $STATE_PATH"
    ;;
  *)
    err "usage: $0 {enable|remove|status}"
    exit 1
    ;;
esac
