#!/usr/bin/env bash
set -euo pipefail

PROGRAM_NAME="xdpdrv-guard"
VERSION="0.1.0"

BASE_DIR="/home/xdpdrv-guard"
BUILD_DIR="$BASE_DIR/build"
SRC_FILE="$BUILD_DIR/xdp_syn_guard.c"
OBJ_FILE="$BUILD_DIR/xdp_syn_guard.o"
CONF_FILE="/etc/xdpdrv-guard.conf"
EXAMPLE_CONF="$BASE_DIR/xdpdrv-guard.conf.example"
STATE_DIR="/var/lib/xdpdrv-guard"
STATE_FILE="$STATE_DIR/runtime.env"
SYSTEMD_UNIT_FILE="/etc/systemd/system/xdpdrv-guard.service"
SYSTEMD_UNIT_NAME="xdpdrv-guard.service"
SERVICE_ENV_FILE="/etc/default/xdpdrv-guard"
FW_STATE_FILE="$STATE_DIR/firewall.env"
FW_TABLE_FAMILY="inet"
FW_TABLE_NAME="xdpdrv_guard"
FW_CHAIN_NAME="xdpdrv_guard_input"

DEFAULT_ALLOWED_TCP_PORTS=""
DEFAULT_ALLOWED_UDP_PORTS=""
DEFAULT_IFACE=""
DEFAULT_AUTO_ALLOW_SSH_PORTS="0"
DEFAULT_ALLOWED_TCP_SYN_RATE_PER_SEC="0"
DEFAULT_BLOCK_PUBLIC_TCP_PORTS=""
DEFAULT_TELEGRAM_ENABLED="0"
DEFAULT_TELEGRAM_BOT_TOKEN=""
DEFAULT_TELEGRAM_CHAT_ID=""

log() { printf '[%s] %s\n' "$PROGRAM_NAME" "$*"; }
err() { printf '[%s] ERROR: %s\n' "$PROGRAM_NAME" "$*" >&2; }

require_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    err "This command must be run as root."
    exit 1
  fi
}

usage() {
  cat <<'EOF'
Usage:
  xdpdrv-guard.sh up [--iface IFACE] [--with-deps] [--with-config] [--no-persist] [--skip-self-test]
  xdpdrv-guard.sh down [--iface IFACE] [--keep-service] [--keep-fw]
  xdpdrv-guard.sh doctor [--iface IFACE] [--quick]
  xdpdrv-guard.sh tg-test
  xdpdrv-guard.sh value-report [--iface IFACE] [--seconds N]
  xdpdrv-guard.sh surface-audit [--iface IFACE]

Description:
  - Only uses xdpdrv mode (native). Never falls back to xdpgeneric.
  - Current guard logic: drops unsolicited TCP SYN packets targeting closed ports.
  - Allowed TCP ports are configured via ALLOWED_TCP_PORTS (supports ports and ranges).
  - Optional UDP guard: when ALLOWED_UDP_PORTS is non-empty, UDP packets to non-allowed destination ports are dropped at XDP.
  - Firewall module is decoupled: it creates dedicated nft table/chain and syncs static SYN-drop rules from ALLOWED_TCP_PORTS.

Business actions:
  up              -> business bring-up: optional deps/config, self-test, runtime protect, optional boot persistence
  down            -> business bring-down: disable persistence, detach xdp, remove decoupled nft table
  doctor          -> unified diagnosis pipeline (status + firewall + health + self-test)

Config file:
  /etc/xdpdrv-guard.conf

Examples:
  sudo xdpdrv-guard.sh up --iface eth0 --with-deps --with-config
  sudo xdpdrv-guard.sh doctor --iface eth0
  sudo xdpdrv-guard.sh down --iface eth0
  sudo xdpdrv-guard.sh tg-test
  sudo xdpdrv-guard.sh value-report --iface eth0 --seconds 15
  sudo xdpdrv-guard.sh surface-audit --iface eth0
EOF
}

parse_iface() {
  local iface=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --iface)
        iface="${2:-}"
        shift 2
        ;;
      *)
        shift
        ;;
    esac
  done

  if [[ -n "$iface" ]]; then
    echo "$iface"
    return
  fi

  if [[ -n "${IFACE:-}" ]]; then
    echo "$IFACE"
    return
  fi

  iface=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')
  if [[ -z "$iface" ]]; then
    err "Could not auto-detect default interface. Use --iface."
    exit 1
  fi
  echo "$iface"
}

detect_os_id() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    echo "${ID:-unknown}"
    return
  fi
  echo "unknown"
}

is_supported_os() {
  local os_id
  os_id="$(detect_os_id)"
  case "$os_id" in
    debian|ubuntu) return 0 ;;
    *) return 1 ;;
  esac
}

require_supported_os() {
  local os_id
  os_id="$(detect_os_id)"
  if is_supported_os; then
    return 0
  fi
  err "Unsupported OS: $os_id (supported: debian, ubuntu)"
  exit 1
}

normalize_arch() {
  local raw="${1:-$(uname -m)}"
  case "$raw" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    armv7l|armv7|armhf) echo "armv7" ;;
    *) echo "unknown" ;;
  esac
}

is_supported_arch() {
  local arch
  arch="$(normalize_arch "${1:-}")"
  case "$arch" in
    amd64|arm64|armv7) return 0 ;;
    *) return 1 ;;
  esac
}

require_supported_arch() {
  local raw norm
  raw="$(uname -m)"
  norm="$(normalize_arch "$raw")"
  if is_supported_arch "$raw"; then
    return 0
  fi
  err "Unsupported CPU arch: $raw (normalized: $norm; supported: amd64, arm64, armv7)"
  exit 1
}

init_dirs() {
  mkdir -p "$BUILD_DIR" "$STATE_DIR"
}

load_config() {
  ALLOWED_TCP_PORTS="$DEFAULT_ALLOWED_TCP_PORTS"
  ALLOWED_UDP_PORTS="$DEFAULT_ALLOWED_UDP_PORTS"
  IFACE="$DEFAULT_IFACE"
  AUTO_ALLOW_SSH_PORTS="$DEFAULT_AUTO_ALLOW_SSH_PORTS"
  ALLOWED_TCP_SYN_RATE_PER_SEC="$DEFAULT_ALLOWED_TCP_SYN_RATE_PER_SEC"
  BLOCK_PUBLIC_TCP_PORTS="$DEFAULT_BLOCK_PUBLIC_TCP_PORTS"
  TELEGRAM_ENABLED="$DEFAULT_TELEGRAM_ENABLED"
  TELEGRAM_BOT_TOKEN="$DEFAULT_TELEGRAM_BOT_TOKEN"
  TELEGRAM_CHAT_ID="$DEFAULT_TELEGRAM_CHAT_ID"

  if [[ -f "$CONF_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$CONF_FILE"
  fi

  if [[ -z "${ALLOWED_TCP_PORTS:-}" ]]; then
    ALLOWED_TCP_PORTS="$DEFAULT_ALLOWED_TCP_PORTS"
  fi

  if [[ -z "${ALLOWED_UDP_PORTS:-}" ]]; then
    ALLOWED_UDP_PORTS="$DEFAULT_ALLOWED_UDP_PORTS"
  fi

  AUTO_ALLOW_SSH_PORTS="${AUTO_ALLOW_SSH_PORTS:-$DEFAULT_AUTO_ALLOW_SSH_PORTS}"
  ALLOWED_TCP_SYN_RATE_PER_SEC="${ALLOWED_TCP_SYN_RATE_PER_SEC:-$DEFAULT_ALLOWED_TCP_SYN_RATE_PER_SEC}"
  BLOCK_PUBLIC_TCP_PORTS="${BLOCK_PUBLIC_TCP_PORTS:-$DEFAULT_BLOCK_PUBLIC_TCP_PORTS}"

  if ! [[ "$ALLOWED_TCP_SYN_RATE_PER_SEC" =~ ^[0-9]+$ ]]; then
    err "ALLOWED_TCP_SYN_RATE_PER_SEC must be a non-negative integer."
    exit 1
  fi

  TELEGRAM_ENABLED="${TELEGRAM_ENABLED:-$DEFAULT_TELEGRAM_ENABLED}"
  TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-$DEFAULT_TELEGRAM_BOT_TOKEN}"
  TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-$DEFAULT_TELEGRAM_CHAT_ID}"
}

detect_sshd_ports() {
  local ports
  ports=$(ss -H -ltnp 2>/dev/null | awk '/sshd/ {print $4}' | sed -E 's/.*:([0-9]+)$/\1/' | awk '/^[0-9]+$/' | sort -nu | tr '\n' ',' | sed 's/,$//')
  echo "$ports"
}

csv_contains_port() {
  local csv="$1"
  local port="$2"
  IFS=',' read -r -a tokens <<< "$csv"
  for raw in "${tokens[@]}"; do
    local token
    token="$(echo "$raw" | xargs)"
    [[ -z "$token" ]] && continue
    if [[ "$token" == "$port" ]]; then
      return 0
    fi
  done
  return 1
}

append_ports_to_csv() {
  local base_csv="$1"
  local extra_csv="$2"
  local out="$base_csv"

  [[ -z "$extra_csv" ]] && { echo "$out"; return; }

  IFS=',' read -r -a extras <<< "$extra_csv"
  for raw in "${extras[@]}"; do
    local port
    port="$(echo "$raw" | xargs)"
    [[ -z "$port" ]] && continue
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
      continue
    fi
    if (( port < 1 || port > 65535 )); then
      continue
    fi

    if csv_contains_port "$out" "$port"; then
      continue
    fi

    if [[ -z "$out" ]]; then
      out="$port"
    else
      out+=",$port"
    fi
  done

  echo "$out"
}

ensure_ssh_ports_allowed() {
  if [[ "${AUTO_ALLOW_SSH_PORTS:-1}" != "1" ]]; then
    return
  fi

  local ssh_ports merged
  ssh_ports="$(detect_sshd_ports)"
  [[ -z "$ssh_ports" ]] && return

  merged="$(append_ports_to_csv "${ALLOWED_TCP_PORTS:-}" "$ssh_ports")"
  if [[ "$merged" != "${ALLOWED_TCP_PORTS:-}" ]]; then
    ALLOWED_TCP_PORTS="$merged"
    log "Auto-allow SSH ports in runtime policy: $ssh_ports"
  fi
}

validate_tools() {
  command -v ip >/dev/null 2>&1 || { err "ip command not found."; exit 1; }
  command -v clang >/dev/null 2>&1 || { err "clang not found. Please install clang."; exit 1; }
}

require_nft() {
  command -v nft >/dev/null 2>&1 || {
    err "nft command not found. Firewall decoupling module requires nft."
    exit 1
  }
}

tg_is_enabled() {
  [[ "${TELEGRAM_ENABLED:-0}" == "1" ]]
}

tg_is_configured() {
  tg_is_enabled && [[ -n "${TELEGRAM_BOT_TOKEN:-}" ]] && [[ -n "${TELEGRAM_CHAT_ID:-}" ]]
}

tg_send_message() {
  local text="$1"

  if ! tg_is_configured; then
    err "Telegram is not configured. Set TELEGRAM_ENABLED=1, TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in $CONF_FILE"
    return 1
  fi

  command -v curl >/dev/null 2>&1 || {
    err "curl not found. Telegram notify requires curl."
    return 1
  }

  if (( ${#text} > 3900 )); then
    text="${text:0:3900} ..."
  fi

  curl -sS -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    --data-urlencode "chat_id=${TELEGRAM_CHAT_ID}" \
    --data-urlencode "text=${text}" \
    --data-urlencode "disable_web_page_preview=true" >/dev/null
}

install_dependencies() {
  require_root
  require_supported_os
  require_supported_arch

  command -v apt-get >/dev/null 2>&1 || {
    err "apt-get not found on this system."
    exit 1
  }

  log "Installing dependencies (clang, linux-libc-dev, iproute2)"
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y clang linux-libc-dev iproute2
}

validate_iface() {
  local iface="$1"
  ip link show dev "$iface" >/dev/null 2>&1 || { err "Interface $iface not found."; exit 1; }
}

parse_ports_to_c_ranges() {
  local ports_csv="$1"
  local ranges_name="${2:-allowed_tcp_ranges}"
  local err_var_name="${3:-ALLOWED_TCP_PORTS}"
  local out=""
  local count=0

  if [[ -z "$ports_csv" ]]; then
    echo "static const struct port_range ${ranges_name}[] = { { .start = 0, .end = 0 } };"
    echo "static const __u32 ${ranges_name}_len = 0;"
    return
  fi

  IFS=',' read -r -a tokens <<< "$ports_csv"
  for raw in "${tokens[@]}"; do
    local token start end
    token="$(echo "$raw" | xargs)"
    [[ -z "$token" ]] && continue

    if [[ "$token" == *"-"* ]]; then
      start="${token%%-*}"
      end="${token##*-}"
      start="$(echo "$start" | xargs)"
      end="$(echo "$end" | xargs)"

      if ! [[ "$start" =~ ^[0-9]+$ && "$end" =~ ^[0-9]+$ ]]; then
        err "Invalid range token in ${err_var_name}: $token"
        exit 1
      fi
      if (( start < 1 || start > 65535 || end < 1 || end > 65535 || start > end )); then
        err "Out-of-range or reversed range in ${err_var_name}: $token"
        exit 1
      fi
    else
      if ! [[ "$token" =~ ^[0-9]+$ ]]; then
        err "Invalid port token in ${err_var_name}: $token"
        exit 1
      fi
      start="$token"
      end="$token"
      if (( start < 1 || start > 65535 )); then
        err "Port out of range in ${err_var_name}: $token"
        exit 1
      fi
    fi

    if (( count > 0 )); then
      out+=" "
    fi
    out+="{ .start = ${start}, .end = ${end} },"
    count=$((count + 1))
  done

  if (( count == 0 )); then
    echo "static const struct port_range ${ranges_name}[] = { { .start = 0, .end = 0 } };"
    echo "static const __u32 ${ranges_name}_len = 0;"
  else
    echo "static const struct port_range ${ranges_name}[] = { ${out} };"
    echo "static const __u32 ${ranges_name}_len = ${count};"
  fi
}

parse_ports_to_nft_set() {
  local ports_csv="$1"
  local out=""
  local count=0

  if [[ -z "$ports_csv" ]]; then
    echo ""
    return
  fi

  IFS=',' read -r -a tokens <<< "$ports_csv"
  for raw in "${tokens[@]}"; do
    local token start end
    token="$(echo "$raw" | xargs)"
    [[ -z "$token" ]] && continue

    if [[ "$token" == *"-"* ]]; then
      start="${token%%-*}"
      end="${token##*-}"
      start="$(echo "$start" | xargs)"
      end="$(echo "$end" | xargs)"

      if ! [[ "$start" =~ ^[0-9]+$ && "$end" =~ ^[0-9]+$ ]]; then
        err "Invalid range token in ALLOWED_TCP_PORTS: $token"
        exit 1
      fi
      if (( start < 1 || start > 65535 || end < 1 || end > 65535 || start > end )); then
        err "Out-of-range or reversed range in ALLOWED_TCP_PORTS: $token"
        exit 1
      fi
      token="${start}-${end}"
    else
      if ! [[ "$token" =~ ^[0-9]+$ ]]; then
        err "Invalid port token in ALLOWED_TCP_PORTS: $token"
        exit 1
      fi
      start="$token"
      if (( start < 1 || start > 65535 )); then
        err "Port out of range in ALLOWED_TCP_PORTS: $token"
        exit 1
      fi
      token="$start"
    fi

    if (( count > 0 )); then
      out+=", "
    fi
    out+="$token"
    count=$((count + 1))
  done

  echo "$out"
}

generate_c_program() {
  local tcp_ports_decl udp_ports_decl
  tcp_ports_decl="$(parse_ports_to_c_ranges "$ALLOWED_TCP_PORTS" "allowed_tcp_ranges" "ALLOWED_TCP_PORTS")"
  udp_ports_decl="$(parse_ports_to_c_ranges "$ALLOWED_UDP_PORTS" "allowed_udp_ranges" "ALLOWED_UDP_PORTS")"
  local tmp_src
  tmp_src=$(mktemp)

  cat > "$tmp_src" <<EOF
#define KBUILD_MODNAME "xdp_syn_guard"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define SEC(NAME) __attribute__((section(NAME), used))

struct port_range { __u16 start; __u16 end; };

static __always_inline int is_allowed_tcp_port(__u16 dport_host) {
${tcp_ports_decl}
  if (allowed_tcp_ranges_len == 0) {
        return 0;
    }
  for (__u32 i = 0; i < allowed_tcp_ranges_len; i++) {
    if (dport_host >= allowed_tcp_ranges[i].start && dport_host <= allowed_tcp_ranges[i].end) {
            return 1;
        }
    }
    return 0;
}

static __always_inline int is_allowed_udp_port(__u16 dport_host) {
${udp_ports_decl}
  if (allowed_udp_ranges_len == 0) {
        return 1;
    }
  for (__u32 i = 0; i < allowed_udp_ranges_len; i++) {
    if (dport_host >= allowed_udp_ranges[i].start && dport_host <= allowed_udp_ranges[i].end) {
            return 1;
        }
    }
    return 0;
}

static __always_inline int parse_l4_guard(void *data, void *data_end, __u16 h_proto, __u64 nh_off) {
    if (h_proto == __builtin_bswap16(ETH_P_IP)) {
        struct iphdr *iph = data + nh_off;
        if ((void *)(iph + 1) > data_end) return XDP_PASS;
        if (iph->protocol == IPPROTO_TCP) {
            __u64 ihl_len = (__u64)iph->ihl * 4;
            struct tcphdr *tcph = (void *)iph + ihl_len;
            if ((void *)(tcph + 1) > data_end) return XDP_PASS;

            if (tcph->syn && !tcph->ack) {
                __u16 dport = __builtin_bswap16(tcph->dest);
              if (!is_allowed_tcp_port(dport)) {
                    return XDP_DROP;
                }
            }
            return XDP_PASS;
        }

        if (iph->protocol == IPPROTO_UDP) {
            __u64 ihl_len = (__u64)iph->ihl * 4;
            struct udphdr *udph = (void *)iph + ihl_len;
            if ((void *)(udph + 1) > data_end) return XDP_PASS;

            __u16 dport = __builtin_bswap16(udph->dest);
            if (!is_allowed_udp_port(dport)) {
              return XDP_DROP;
            }
            return XDP_PASS;
        }

        return XDP_PASS;
    }

    if (h_proto == __builtin_bswap16(ETH_P_IPV6)) {
        struct ipv6hdr *ip6h = data + nh_off;
        if ((void *)(ip6h + 1) > data_end) return XDP_PASS;
        if (ip6h->nexthdr == IPPROTO_TCP) {
            struct tcphdr *tcph = (void *)(ip6h + 1);
            if ((void *)(tcph + 1) > data_end) return XDP_PASS;

            if (tcph->syn && !tcph->ack) {
                __u16 dport = __builtin_bswap16(tcph->dest);
              if (!is_allowed_tcp_port(dport)) {
                    return XDP_DROP;
                }
            }
            return XDP_PASS;
        }

        if (ip6h->nexthdr == IPPROTO_UDP) {
            struct udphdr *udph = (void *)(ip6h + 1);
            if ((void *)(udph + 1) > data_end) return XDP_PASS;

            __u16 dport = __builtin_bswap16(udph->dest);
            if (!is_allowed_udp_port(dport)) {
              return XDP_DROP;
            }
            return XDP_PASS;
        }

        return XDP_PASS;
    }

    return XDP_PASS;
}

SEC("xdp")
int xdp_syn_guard(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    __u16 h_proto = eth->h_proto;
    __u64 nh_off = sizeof(*eth);

    return parse_l4_guard(data, data_end, h_proto, nh_off);
}

char _license[] SEC("license") = "GPL";
EOF

  if [[ -f "$SRC_FILE" ]] && cmp -s "$tmp_src" "$SRC_FILE"; then
    rm -f "$tmp_src"
    return
  fi

  mv -f "$tmp_src" "$SRC_FILE"
}

compile_program() {
  if [[ -s "$OBJ_FILE" && "$OBJ_FILE" -nt "$SRC_FILE" ]]; then
    log "compile: using cached object $OBJ_FILE"
    return
  fi

  local arch
  arch="$(uname -m)"

  local -a triplet_candidates=()
  case "$arch" in
    x86_64|amd64)
      triplet_candidates=("x86_64-linux-gnu")
      ;;
    aarch64|arm64)
      triplet_candidates=("aarch64-linux-gnu")
      ;;
    armv7l|armv7|armhf)
      triplet_candidates=("arm-linux-gnueabihf" "arm-linux-gnueabi")
      ;;
    *)
      triplet_candidates=("${arch}-linux-gnu")
      ;;
  esac

  local include_flags=("-I/usr/include")
  local t
  for t in "${triplet_candidates[@]}"; do
    if [[ -d "/usr/include/$t" ]]; then
      include_flags+=("-I/usr/include/$t")
    fi
  done

  clang -O2 -target bpf "${include_flags[@]}" -c "$SRC_FILE" -o "$OBJ_FILE"
}

save_state() {
  local iface="$1"
  {
    echo "IFACE=$iface"
    echo "OBJ_FILE=$OBJ_FILE"
    echo "ALLOWED_TCP_PORTS=$ALLOWED_TCP_PORTS"
    echo "ALLOWED_UDP_PORTS=$ALLOWED_UDP_PORTS"
    echo "UPDATED_AT=$(date -Is)"
  } > "$STATE_FILE"
}

attach_xdpdrv() {
  local iface="$1"
  local err_file
  err_file=$(mktemp)

  if ip link set dev "$iface" xdpdrv obj "$OBJ_FILE" sec xdp 2>"$err_file"; then
    rm -f "$err_file"
    return 0
  fi

  err "Failed to attach in xdpdrv mode."
  cat "$err_file" >&2
  rm -f "$err_file"
  return 1
}

detach_xdp_all_modes() {
  local iface="$1"
  ip link set dev "$iface" xdpdrv off >/dev/null 2>&1 || true
  ip link set dev "$iface" xdpgeneric off >/dev/null 2>&1 || true
  ip link set dev "$iface" xdp off >/dev/null 2>&1 || true
}

sum_softirq_vector() {
  local vector="$1"
  awk -v vec="$vector" '
    $1 ~ (vec":") {
      sum=0
      for (i=2; i<=NF; i++) sum += $i
      print sum
      exit
    }
  ' /proc/softirqs
}

read_proc_stat_total_softirq() {
  awk '/^cpu / {print $2+$3+$4+$5+$6+$7+$8+$9+$10+$11, $8; exit}' /proc/stat
}

nft_table_exists() {
  nft list table "$FW_TABLE_FAMILY" "$FW_TABLE_NAME" >/dev/null 2>&1
}

detect_fw_stack() {
  local nft_mode="absent" ufw_mode="absent" ipt_mode="absent"

  if command -v nft >/dev/null 2>&1; then
    nft_mode="present"
  fi

  if command -v ufw >/dev/null 2>&1; then
    ufw_mode="installed"
    if ufw status 2>/dev/null | head -n1 | grep -qi 'Status: active'; then
      ufw_mode="active"
    fi
  fi

  if command -v iptables >/dev/null 2>&1; then
    ipt_mode="$(iptables -V 2>/dev/null | awk '{print $NF}')"
    [[ -z "$ipt_mode" ]] && ipt_mode="present"
  fi

  echo "nft=$nft_mode ufw=$ufw_mode iptables=$ipt_mode"
}

is_tcp_port_effectively_public() {
  local port="$1"

  if ! [[ "$port" =~ ^[0-9]+$ ]]; then
    return 0
  fi

  if command -v nft >/dev/null 2>&1; then
    local rules
    rules=$(nft list ruleset 2>/dev/null || true)

    if [[ "$port" == "22" ]] && echo "$rules" | grep -q 'drop-public-ssh'; then
      return 1
    fi

    if echo "$rules" | grep -Eq "tcp dport ${port} .*iifname != \"tailscale0\".*drop"; then
      return 1
    fi

    if echo "$rules" | grep -Eq "tcp dport ${port} .*drop" && ! echo "$rules" | grep -Eq "tcp dport ${port} .*accept"; then
      return 1
    fi
  fi

  if command -v ufw >/dev/null 2>&1; then
    local ufw_status
    ufw_status=$(ufw status 2>/dev/null || true)
    if echo "$ufw_status" | grep -Eq "^${port}(/tcp)?\s+DENY\s+Anywhere"; then
      return 1
    fi
  fi

  return 0
}

cmd_fw_install() {
  require_root
  require_nft
  load_config
  ensure_ssh_ports_allowed

  local iface
  iface=$(parse_iface "$@")
  validate_iface "$iface"
  init_dirs

  local ports_set syn_rule rate_rule="" hard_drop_set="" hard_drop_rule=""
  ports_set="$(parse_ports_to_nft_set "${ALLOWED_TCP_PORTS:-}")"
  hard_drop_set="$(parse_ports_to_nft_set "${BLOCK_PUBLIC_TCP_PORTS:-}")"

  if [[ -n "$hard_drop_set" ]]; then
    hard_drop_rule="iifname \"${iface}\" tcp dport { ${hard_drop_set} } counter drop comment \"xdpdrv_guard_public_tcp_drop\""
  fi

  if [[ -n "$ports_set" ]]; then
    if (( ALLOWED_TCP_SYN_RATE_PER_SEC > 0 )); then
      rate_rule="iifname \"${iface}\" tcp flags & (syn | ack) == syn tcp dport { ${ports_set} } limit rate over ${ALLOWED_TCP_SYN_RATE_PER_SEC}/second counter drop comment \"xdpdrv_guard_syn_rate_drop\""
    fi
    syn_rule="iifname \"${iface}\" tcp flags & (syn | ack) == syn tcp dport != { ${ports_set} } counter drop comment \"xdpdrv_guard_syn_drop\""
  else
    syn_rule="iifname \"${iface}\" tcp flags & (syn | ack) == syn counter drop comment \"xdpdrv_guard_syn_drop\""
  fi

  if nft_table_exists; then
    nft delete table "$FW_TABLE_FAMILY" "$FW_TABLE_NAME"
  fi

  nft -f - <<EOF
add table $FW_TABLE_FAMILY $FW_TABLE_NAME
add chain $FW_TABLE_FAMILY $FW_TABLE_NAME $FW_CHAIN_NAME { type filter hook input priority -300; policy accept; }
$( [[ -n "$hard_drop_rule" ]] && echo "add rule $FW_TABLE_FAMILY $FW_TABLE_NAME $FW_CHAIN_NAME $hard_drop_rule" )
$( [[ -n "$rate_rule" ]] && echo "add rule $FW_TABLE_FAMILY $FW_TABLE_NAME $FW_CHAIN_NAME $rate_rule" )
add rule $FW_TABLE_FAMILY $FW_TABLE_NAME $FW_CHAIN_NAME $syn_rule
EOF

  {
    echo "FW_TABLE_FAMILY=$FW_TABLE_FAMILY"
    echo "FW_TABLE_NAME=$FW_TABLE_NAME"
    echo "FW_CHAIN_NAME=$FW_CHAIN_NAME"
    echo "IFACE=$iface"
    echo "ALLOWED_TCP_PORTS=$ALLOWED_TCP_PORTS"
    echo "BLOCK_PUBLIC_TCP_PORTS=$BLOCK_PUBLIC_TCP_PORTS"
    echo "UPDATED_AT=$(date -Is)"
  } > "$FW_STATE_FILE"

  log "Firewall decoupled static rules installed on iface=$iface"
  log "Rules are synced from ALLOWED_TCP_PORTS=$ALLOWED_TCP_PORTS"
  if [[ -n "${BLOCK_PUBLIC_TCP_PORTS:-}" ]]; then
    log "Public hard-drop TCP ports on $iface: $BLOCK_PUBLIC_TCP_PORTS"
  fi
  log "No existing user INPUT/FORWARD chain definitions were edited by this script."
  nft -a list table "$FW_TABLE_FAMILY" "$FW_TABLE_NAME" | sed -n '1,80p'
}

cmd_fw_status() {
  local stack table_mode
  stack="$(detect_fw_stack)"
  if nft_table_exists; then
    table_mode="present"
  else
    table_mode="absent"
  fi

  echo "firewall_stack=$stack"
  echo "xdpdrv_guard_table=$table_mode"

  if [[ -f "$FW_STATE_FILE" ]]; then
    echo "fw_state_file=$FW_STATE_FILE"
    cat "$FW_STATE_FILE"
  else
    echo "fw_state_file=absent"
  fi

  if [[ "$table_mode" == "present" ]]; then
    echo
    nft -a list table "$FW_TABLE_FAMILY" "$FW_TABLE_NAME" | sed -n '1,80p'
  fi
}

cmd_fw_remove() {
  require_root
  require_nft

  if nft_table_exists; then
    nft delete table "$FW_TABLE_FAMILY" "$FW_TABLE_NAME"
  fi

  rm -f "$FW_STATE_FILE"
  log "Firewall decoupled table removed."
}

cmd_value_report() {
  require_root
  load_config

  local iface=""
  local seconds=15
  local tg_send=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --iface)
        iface="${2:-}"
        shift 2
        ;;
      --seconds)
        seconds="${2:-}"
        shift 2
        ;;
      --tg)
        tg_send=1
        shift
        ;;
      *)
        err "Unknown option for value-report: $1"
        exit 1
        ;;
    esac
  done

  if [[ -n "$iface" ]]; then
    validate_iface "$iface"
  else
    iface=$(parse_iface)
    validate_iface "$iface"
  fi

  if ! [[ "$seconds" =~ ^[0-9]+$ ]] || (( seconds < 5 || seconds > 300 )); then
    err "--seconds must be an integer between 5 and 300."
    exit 1
  fi

  local xdp_mode="detached"
  if ip -d link show dev "$iface" | grep -q 'xdpgeneric'; then
    xdp_mode="xdpgeneric"
  elif ip -d link show dev "$iface" | grep -q 'xdp '; then
    xdp_mode="xdpdrv"
  fi

  local rx_bytes_1 rx_pkts_1 rx_drop_1 netrx_1 total_1 softirq_1 synrecv_1 est_1
  rx_bytes_1=$(cat "/sys/class/net/$iface/statistics/rx_bytes")
  rx_pkts_1=$(cat "/sys/class/net/$iface/statistics/rx_packets")
  rx_drop_1=$(cat "/sys/class/net/$iface/statistics/rx_dropped")
  netrx_1=$(sum_softirq_vector "NET_RX")
  read -r total_1 softirq_1 <<< "$(read_proc_stat_total_softirq)"
  synrecv_1=$(ss -H -ant state syn-recv | wc -l)
  est_1=$(ss -H -ant state established | wc -l)

  sleep "$seconds"

  local rx_bytes_2 rx_pkts_2 rx_drop_2 netrx_2 total_2 softirq_2 synrecv_2 est_2
  rx_bytes_2=$(cat "/sys/class/net/$iface/statistics/rx_bytes")
  rx_pkts_2=$(cat "/sys/class/net/$iface/statistics/rx_packets")
  rx_drop_2=$(cat "/sys/class/net/$iface/statistics/rx_dropped")
  netrx_2=$(sum_softirq_vector "NET_RX")
  read -r total_2 softirq_2 <<< "$(read_proc_stat_total_softirq)"
  synrecv_2=$(ss -H -ant state syn-recv | wc -l)
  est_2=$(ss -H -ant state established | wc -l)

  local conn_count="N/A" conn_max="N/A"
  if [[ -r /proc/sys/net/netfilter/nf_conntrack_count ]]; then
    conn_count=$(cat /proc/sys/net/netfilter/nf_conntrack_count)
  fi
  if [[ -r /proc/sys/net/netfilter/nf_conntrack_max ]]; then
    conn_max=$(cat /proc/sys/net/netfilter/nf_conntrack_max)
  fi

  local load1 mem_avail_kb
  load1=$(awk '{print $1}' /proc/loadavg)
  mem_avail_kb=$(awk '/MemAvailable:/ {print $2; exit}' /proc/meminfo)

  local report_text
  report_text=$(awk \
    -v iface="$iface" -v sec="$seconds" -v xmode="$xdp_mode" \
    -v rb1="$rx_bytes_1" -v rb2="$rx_bytes_2" -v rp1="$rx_pkts_1" -v rp2="$rx_pkts_2" \
    -v rd1="$rx_drop_1" -v rd2="$rx_drop_2" -v nr1="$netrx_1" -v nr2="$netrx_2" \
    -v t1="$total_1" -v t2="$total_2" -v s1="$softirq_1" -v s2="$softirq_2" \
    -v syn1="$synrecv_1" -v syn2="$synrecv_2" -v est1="$est_1" -v est2="$est_2" \
    -v ccount="$conn_count" -v cmax="$conn_max" -v load1="$load1" -v memkb="$mem_avail_kb" \
    'BEGIN {
      drb=rb2-rb1; drp=rp2-rp1; drd=rd2-rd1; dnr=nr2-nr1;
      dt=t2-t1; ds=s2-s1;
      rx_kbs=drb/1024/sec; pps=drp/sec; drop_ps=drd/sec; netrx_ps=dnr/sec;
      softirq_pct=(dt>0)?(ds*100.0/dt):0;
      conn_pct="N/A";
      if (ccount != "N/A" && cmax != "N/A" && cmax > 0) {
        conn_pct=sprintf("%.2f", ccount*100.0/cmax);
      }

      printf("=== XDP Value Report ===\n");
      printf("iface: %s\n", iface);
      printf("sample_seconds: %d\n", sec);
      printf("xdp_mode: %s\n", xmode);
      printf("rx_rate: %.2f KB/s (%.2f pps)\n", rx_kbs, pps);
      printf("rx_dropped_rate: %.2f pps\n", drop_ps);
      printf("NET_RX_softirq_rate: %.2f /s\n", netrx_ps);
      printf("cpu_softirq_share: %.2f%%\n", softirq_pct);
      printf("tcp_syn_recv: %s -> %s\n", syn1, syn2);
      printf("tcp_established: %s -> %s\n", est1, est2);
      printf("nf_conntrack_usage: %s/%s (%s%%)\n", ccount, cmax, conn_pct);
      printf("load1: %s\n", load1);
      printf("mem_available_mb: %.2f\n", memkb/1024.0);

      printf("\n=== Operator-Focused Value ===\n");
      if (xmode == "xdpdrv") {
        printf("- XDP is active in native mode, dropping invalid SYN traffic before deeper kernel paths.\n");
      } else if (xmode == "xdpgeneric") {
        printf("- XDP is attached in generic mode; protection works but with less performance gain.\n");
      } else {
        printf("- XDP is not attached; early-drop protection is currently inactive.\n");
      }

      if (softirq_pct < 20) {
        printf("- SoftIRQ share is in a healthy range; system should remain responsive under current pressure.\n");
      } else if (softirq_pct < 40) {
        printf("- SoftIRQ share is moderate; monitor closely during attack peaks.\n");
      } else {
        printf("- SoftIRQ share is high; system responsiveness risk is increasing.\n");
      }
    }')

  echo "$report_text"

  if (( tg_send == 1 )); then
    local summary
    summary=$(cat <<EOF
[$PROGRAM_NAME] Value Report
iface=$iface
sample=${seconds}s
xdp=$xdp_mode
$(echo "$report_text" | awk -F': ' '/^rx_rate:|^cpu_softirq_share:|^tcp_syn_recv:|^nf_conntrack_usage:/ {print $1"="$2}')
EOF
)
    tg_send_message "$summary"
    log "Telegram notification sent for value-report."
  fi
}

cmd_tg_test() {
  require_root
  load_config

  local msg
  msg=$(cat <<EOF
[$PROGRAM_NAME] Telegram test
time=$(date -Is)
host=$(hostname)
status=ok
EOF
)

  tg_send_message "$msg"
  log "Telegram test message sent successfully."
}

cmd_surface_audit() {
  require_root
  load_config

  local iface
  local tg_send=0
  local args=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --tg)
        tg_send=1
        shift
        ;;
      *)
        args+=("$1")
        shift
        ;;
    esac
  done

  iface=$(parse_iface "${args[@]}")
  validate_iface "$iface"

  local host_ip4 host_ip6 xdp_mode
  host_ip4=$(ip -4 -o addr show dev "$iface" | awk '{print $4}' | cut -d/ -f1 | head -n1)
  host_ip6=$(ip -6 -o addr show dev "$iface" scope global | awk '{print $4}' | cut -d/ -f1 | head -n1)

  xdp_mode="detached"
  if ip -d link show dev "$iface" | grep -q 'xdpgeneric'; then
    xdp_mode="xdpgeneric"
  elif ip -d link show dev "$iface" | grep -q 'xdp '; then
    xdp_mode="xdpdrv"
  fi

  local score=0
  local -a findings
  local -a advises
  local -a tcp_items
  local -a tcp_effective_items
  local -a udp_items

  local listeners
  listeners=$(ss -H -ltnup 2>/dev/null || true)
  local ln
  while IFS= read -r ln; do
    [[ -z "$ln" ]] && continue
    if ! echo "$ln" | awk '{print $5}' | grep -qE '^(0\.0\.0\.0:|\[::\]:)'; then
      continue
    fi
    local proto local_addr proc
    proto=$(echo "$ln" | awk '{print $1}')
    local_addr=$(echo "$ln" | awk '{print $5}')
    proc=$(echo "$ln" | sed -n 's/.*users:(("\([^"]\+\)".*/\1/p')
    [[ -z "$proc" ]] && proc="unknown"
    if [[ "$proto" == "tcp" ]]; then
      local port
      port=$(echo "$local_addr" | sed -E 's/.*:([0-9]+)$/\1/')
      tcp_items+=("$local_addr ($proc)")
      if is_tcp_port_effectively_public "$port"; then
        tcp_effective_items+=("$local_addr ($proc)")
      fi
    elif [[ "$proto" == "udp" ]]; then
      udp_items+=("$local_addr ($proc)")
    fi
  done <<< "$listeners"

  local public_tcp_count public_tcp_effective_count public_udp_count
  public_tcp_count=${#tcp_items[@]}
  public_tcp_effective_count=${#tcp_effective_items[@]}
  public_udp_count=${#udp_items[@]}

  score=$((score + public_tcp_effective_count * 3 + public_udp_count * 2))
  findings+=("公网TCP监听: $public_tcp_count 项")
  findings+=("公网TCP可达(防火墙后推断): $public_tcp_effective_count 项")
  findings+=("公网UDP暴露: $public_udp_count 项")

  if [[ "$xdp_mode" != "xdpdrv" ]]; then
    score=$((score + 8))
    findings+=("早期防护状态: 未启用原生XDP")
    advises+=("建议在攻击压力较高时启用xdpdrv，降低进入内核的无效流量")
  else
    findings+=("早期防护状态: 原生XDP已启用")
  fi

  local softirq_pct
  softirq_pct=$(awk '
    function readstat(arr,   a,b,c,d,e,f,g,h,i,j) {
      getline line < "/proc/stat"
      split(line, a, " ")
      arr["total"] = a[2]+a[3]+a[4]+a[5]+a[6]+a[7]+a[8]+a[9]+a[10]+a[11]
      arr["soft"] = a[8]
      close("/proc/stat")
    }
    BEGIN {
      readstat(s1)
      system("sleep 1")
      readstat(s2)
      dt=s2["total"]-s1["total"]; ds=s2["soft"]-s1["soft"]
      if (dt>0) printf("%.2f", ds*100.0/dt); else printf("0.00")
    }')

  if awk "BEGIN {exit !($softirq_pct >= 30)}"; then
    score=$((score + 10))
    advises+=("当前软中断占比偏高，建议优先保持XDP开启并压缩不必要公网暴露")
  elif awk "BEGIN {exit !($softirq_pct >= 15)}"; then
    score=$((score + 4))
    advises+=("软中断占比中等，建议持续观测攻击峰值时段")
  fi

  advises+=("建议将公网暴露服务数控制在“业务必要最小集”")
  advises+=("建议关闭可识别服务版本/指纹信息（banner最小化）")

  local risk_level="LOW"
  if (( score >= 30 )); then
    risk_level="HIGH"
  elif (( score >= 16 )); then
    risk_level="MEDIUM"
  fi

  echo "=== Exposure & Resilience Audit (Read-only) ==="
  echo "iface=$iface"
  echo "ipv4=${host_ip4:-N/A}"
  echo "ipv6=${host_ip6:-N/A}"
  echo "early_protection=$xdp_mode"
  echo "softirq_share_1s=${softirq_pct}%"
  echo "risk_score=$score"
  echo "risk_level=$risk_level"
  echo
  echo "[Public Exposure Details]"
  if (( public_tcp_count == 0 )); then
    echo "- TCP: 无公网监听项"
  else
    echo "- TCP (监听层):"
    for item in "${tcp_items[@]}"; do
      echo "  - $item"
    done
  fi
  if (( public_tcp_effective_count == 0 )); then
    echo "- TCP (防火墙后可达): 无明显公网可达项"
  else
    echo "- TCP (防火墙后可达):"
    for item in "${tcp_effective_items[@]}"; do
      echo "  - $item"
    done
  fi
  if (( public_udp_count == 0 )); then
    echo "- UDP: 无公网监听项"
  else
    echo "- UDP:"
    for item in "${udp_items[@]}"; do
      echo "  - $item"
    done
  fi

  echo
  echo "[Risk Summary]"
  for item in "${findings[@]}"; do
    echo "- $item"
  done

  echo
  echo "[Why This Matters for You]"
  if [[ "$xdp_mode" == "xdpdrv" ]]; then
    echo "- 你的服务器在攻击时更不容易出现“能连上但操作卡顿”的维护体验问题"
    echo "- 无效SYN在更早阶段处理，可降低内核后续路径压力"
  else
    echo "- 当前未启用原生XDP，攻击流量会更多进入内核路径，维护流畅度风险更高"
  fi

  echo
  echo "[Action Suggestions]"
  if (( ${#advises[@]} == 0 )); then
    echo "- 当前暴露面已相对收敛，继续保持最小暴露策略"
  else
    for item in "${advises[@]}"; do
      echo "- $item"
    done
  fi

  echo "- 建议固定周期运行: xdpdrv-guard.sh surface-audit --iface $iface"
  echo "- 建议与 value-report 联合观察“暴露面变化”和“系统减负效果”"

  if (( tg_send == 1 )); then
    local summary
    summary=$(cat <<EOF
[$PROGRAM_NAME] Exposure Audit
host=${host_ip4:-N/A}
risk=$risk_level($score)
xdp=$xdp_mode
softirq=${softirq_pct}%
tcp_exposed=$public_tcp_count
udp_exposed=$public_udp_count
EOF
)
    tg_send_message "$summary"
    log "Telegram notification sent for surface-audit."
  fi
}

require_systemd() {
  command -v systemctl >/dev/null 2>&1 || {
    err "systemctl not found. systemd management is unavailable on this host."
    exit 1
  }
}

write_systemd_unit() {
  cat > "$SYSTEMD_UNIT_FILE" <<EOF
[Unit]
Description=XDPDRV Guard (xdpdrv only)
After=local-fs.target systemd-udev-settle.service
Wants=network-pre.target
Before=network-pre.target network.target network-online.target
StartLimitIntervalSec=120
StartLimitBurst=3

[Service]
Type=oneshot
RemainAfterExit=yes
EnvironmentFile=-$SERVICE_ENV_FILE
ExecStartPre=$BASE_DIR/xdpdrv-guard.sh _fw-apply --iface \${IFACE}
ExecStartPre=$BASE_DIR/xdpdrv-guard.sh _health-check --iface \${IFACE}
ExecStart=$BASE_DIR/xdpdrv-guard.sh _runtime-install --iface \${IFACE} --skip-fw
ExecReload=$BASE_DIR/xdpdrv-guard.sh _runtime-install --iface \${IFACE}
ExecStop=$BASE_DIR/xdpdrv-guard.sh _runtime-uninstall --iface \${IFACE}
Restart=on-failure
RestartSec=5s
TimeoutStartSec=120
TimeoutStopSec=30

[Install]
WantedBy=network-pre.target
EOF
}

write_service_env() {
  local iface="$1"
  cat > "$SERVICE_ENV_FILE" <<EOF
# Managed by $PROGRAM_NAME
IFACE=$iface
EOF
}

cmd_probe() {
  require_root
  require_supported_os
  require_supported_arch
  validate_tools
  load_config

  local iface
  iface=$(parse_iface "$@")
  validate_iface "$iface"
  init_dirs

  generate_c_program
  compile_program

  detach_xdp_all_modes "$iface"

  local err_file
  err_file=$(mktemp)

  if ip link set dev "$iface" xdpdrv obj "$OBJ_FILE" sec xdp 2>"$err_file"; then
    log "xdpdrv probe: SUPPORTED on $iface"
    ip -d link show dev "$iface" | sed -n '1,4p'
    ip link set dev "$iface" xdpdrv off >/dev/null 2>&1 || true
    rm -f "$err_file"
    return 0
  fi

  log "xdpdrv probe: NOT SUPPORTED on $iface"
  cat "$err_file" >&2
  rm -f "$err_file"
  return 1
}

cmd_health_check() {
  require_root
  require_supported_os
  require_supported_arch
  validate_tools
  load_config

  local iface
  iface=$(parse_iface "$@")
  validate_iface "$iface"
  init_dirs

  log "health-check: iface=$iface"

  generate_c_program
  compile_program

  local had_xdp=0
  if ip -d link show dev "$iface" | grep -q 'prog/xdp'; then
    had_xdp=1
    log "health-check: existing xdp detected, temporarily detaching for probe"
  fi

  detach_xdp_all_modes "$iface"

  local err_file
  err_file=$(mktemp)
  if ip link set dev "$iface" xdpdrv obj "$OBJ_FILE" sec xdp 2>"$err_file"; then
    ip link set dev "$iface" xdpdrv off >/dev/null 2>&1 || true
    rm -f "$err_file"
    log "health-check: xdpdrv supported"

    if [[ $had_xdp -eq 1 ]]; then
      attach_xdpdrv "$iface"
      log "health-check: previous xdp state restored"
    fi
    return 0
  fi

  err "health-check: xdpdrv not supported"
  cat "$err_file" >&2
  rm -f "$err_file"
  return 1
}

cmd_self_test() {
  require_root
  load_config

  local iface
  iface=$(parse_iface "$@")

  local fail=0
  local os_id arch_raw arch_norm
  os_id="$(detect_os_id)"
  arch_raw="$(uname -m)"
  arch_norm="$(normalize_arch "$arch_raw")"

  local c_reset="" c_green="" c_red="" c_yellow="" c_blue="" c_bold=""
  if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    c_reset='\033[0m'
    c_green='\033[32m'
    c_red='\033[31m'
    c_yellow='\033[33m'
    c_blue='\033[34m'
    c_bold='\033[1m'
  fi

  st_pass() { printf "%b✅ PASS%b %s\n" "$c_green" "$c_reset" "$*"; }
  st_fail() { printf "%b❌ FAIL%b %s\n" "$c_red" "$c_reset" "$*"; }
  st_info() { printf "%bℹ️  INFO%b %s\n" "$c_blue" "$c_reset" "$*"; }
  st_skip() { printf "%b⏭️  SKIP%b %s\n" "$c_yellow" "$c_reset" "$*"; }

  printf "%b🧪 self-test: begin%b\n" "$c_bold" "$c_reset"

  if is_supported_os; then
    st_pass "os: $os_id"
  else
    st_fail "os: $os_id (supported: debian/ubuntu)"
    fail=1
  fi

  if is_supported_arch "$arch_raw"; then
    st_pass "arch: $arch_raw ($arch_norm)"
  else
    st_fail "arch: $arch_raw ($arch_norm), supported: amd64/arm64/armv7"
    fail=1
  fi

  if command -v ip >/dev/null 2>&1; then
    st_pass "tool: ip"
  else
    st_fail "tool: ip"
    fail=1
  fi

  if command -v clang >/dev/null 2>&1; then
    st_pass "tool: clang"
  else
    st_fail "tool: clang"
    fail=1
  fi

  if ip link show dev "$iface" >/dev/null 2>&1; then
    st_pass "iface: $iface"
  else
    st_fail "iface: $iface not found"
    fail=1
  fi

  if command -v systemctl >/dev/null 2>&1; then
    local en ac
    en="$(systemctl is-enabled "$SYSTEMD_UNIT_NAME" 2>/dev/null || true)"
    ac="$(systemctl is-active "$SYSTEMD_UNIT_NAME" 2>/dev/null || true)"
    st_info "systemd: enabled=${en:-unknown} active=${ac:-unknown}"
  else
    st_info "systemd: unavailable"
  fi

  if (( fail == 0 )); then
    if cmd_health_check --iface "$iface" >/tmp/xdpdrv_guard_selftest_health.log 2>&1; then
      st_pass "xdpdrv probe"
    else
      st_fail "xdpdrv probe"
      sed -n '1,80p' /tmp/xdpdrv_guard_selftest_health.log
      fail=1
    fi
  else
    st_skip "xdpdrv probe due to previous failures"
  fi

  if (( fail == 0 )); then
    printf "%b🎉 self-test: PASS%b\n" "$c_green$c_bold" "$c_reset"
    return 0
  fi

  printf "%b🔥 self-test: FAIL%b\n" "$c_red$c_bold" "$c_reset"
  return 1
}

cmd_install() {
  require_root
  require_supported_os
  require_supported_arch
  validate_tools
  load_config
  ensure_ssh_ports_allowed

  local skip_fw=0
  local -a args=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --skip-fw)
        skip_fw=1
        shift
        ;;
      *)
        args+=("$1")
        shift
        ;;
    esac
  done

  local iface
  iface=$(parse_iface "${args[@]}")
  validate_iface "$iface"
  init_dirs

  if [[ $skip_fw -eq 0 ]]; then
    cmd_fw_install --iface "$iface"
  fi

  generate_c_program
  compile_program

  detach_xdp_all_modes "$iface"
  attach_xdpdrv "$iface"
  save_state "$iface"

  log "Installed in xdpdrv mode on $iface"
  ip -d link show dev "$iface" | sed -n '1,4p'
}

cmd_reload() {
  cmd_install "$@"
}

cmd_uninstall() {
  require_root
  load_config

  local iface
  iface=$(parse_iface "$@")
  validate_iface "$iface"

  detach_xdp_all_modes "$iface"
  rm -f "$STATE_FILE"

  log "Uninstalled XDP program from $iface"
  ip -d link show dev "$iface" | sed -n '1,4p'
}

cmd_status() {
  load_config
  local iface
  iface=$(parse_iface "$@")
  validate_iface "$iface"

  echo "program=$PROGRAM_NAME"
  echo "version=$VERSION"
  echo "iface=$iface"
  echo "allowed_tcp_ports=${ALLOWED_TCP_PORTS:-}"
  echo "allowed_udp_ports=${ALLOWED_UDP_PORTS:-}"

  if [[ -f "$STATE_FILE" ]]; then
    echo "state_file=$STATE_FILE"
    cat "$STATE_FILE"
  else
    echo "state_file=absent"
  fi

  echo
  ip -d link show dev "$iface" | sed -n '1,6p'
}

cmd_init_config() {
  require_root
  if [[ -f "$CONF_FILE" ]]; then
    log "$CONF_FILE already exists."
    return 0
  fi
  cp "$EXAMPLE_CONF" "$CONF_FILE"
  log "Created $CONF_FILE"
}

cmd_print_config() {
  cat "$EXAMPLE_CONF"
}

cmd_service_install() {
  require_root
  require_systemd
  load_config

  local iface
  iface=$(parse_iface "$@")
  validate_iface "$iface"

  write_systemd_unit
  write_service_env "$iface"

  systemctl daemon-reload
  systemctl enable "$SYSTEMD_UNIT_NAME" >/dev/null 2>&1 || true
  systemctl restart "$SYSTEMD_UNIT_NAME"

  log "Systemd service installed and started: $SYSTEMD_UNIT_NAME"
  log "Auto-recovery on boot is enabled."
  systemctl --no-pager --full status "$SYSTEMD_UNIT_NAME" | sed -n '1,18p'
}

cmd_service_remove() {
  require_root
  require_systemd

  if systemctl list-unit-files | awk '{print $1}' | grep -qx "$SYSTEMD_UNIT_NAME"; then
    systemctl disable --now "$SYSTEMD_UNIT_NAME" >/dev/null 2>&1 || true
  fi

  rm -f "$SYSTEMD_UNIT_FILE" "$SERVICE_ENV_FILE"
  systemctl daemon-reload

  log "Systemd service removed: $SYSTEMD_UNIT_NAME"
}

cmd_rollback() {
  require_root
  load_config

  local iface
  iface=$(parse_iface "$@")
  validate_iface "$iface"

  if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files | awk '{print $1}' | grep -qx "$SYSTEMD_UNIT_NAME"; then
      systemctl disable --now "$SYSTEMD_UNIT_NAME" >/dev/null 2>&1 || true
    fi
  fi

  detach_xdp_all_modes "$iface"
  rm -f "$STATE_FILE"

  log "Rollback completed on $iface"
  log "- XDP program detached"
  log "- systemd autostart disabled (if previously enabled)"
  ip -d link show dev "$iface" | sed -n '1,4p'
}

cmd_up() {
  require_root

  local with_deps=0
  local with_config=0
  local persist=1
  local do_self_test=1
  local -a args=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --with-deps)
        with_deps=1
        shift
        ;;
      --with-config)
        with_config=1
        shift
        ;;
      --no-persist)
        persist=0
        shift
        ;;
      --skip-self-test)
        do_self_test=0
        shift
        ;;
      *)
        args+=("$1")
        shift
        ;;
    esac
  done

  local iface
  iface=$(parse_iface "${args[@]}")
  validate_iface "$iface"

  log "[up] iface=$iface with_deps=$with_deps with_config=$with_config persist=$persist self_test=$do_self_test"

  if [[ $with_deps -eq 1 ]]; then
    install_dependencies
  fi

  if [[ $with_config -eq 1 ]]; then
    cmd_init_config
  fi

  if [[ $do_self_test -eq 1 ]]; then
    cmd_self_test --iface "$iface"
  fi

  if [[ $persist -eq 1 ]]; then
    cmd_service_install --iface "$iface"
  else
    cmd_install --iface "$iface"
  fi

  log "[up] effective runtime snapshot"
  cmd_status --iface "$iface"
  log "[up] firewall snapshot"
  cmd_fw_status
}

cmd_down() {
  require_root

  local keep_service=0
  local keep_fw=0
  local -a args=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --keep-service)
        keep_service=1
        shift
        ;;
      --keep-fw)
        keep_fw=1
        shift
        ;;
      *)
        args+=("$1")
        shift
        ;;
    esac
  done

  local iface
  iface=$(parse_iface "${args[@]}")
  validate_iface "$iface"

  log "[down] iface=$iface keep_service=$keep_service keep_fw=$keep_fw"

  if [[ $keep_service -eq 0 ]]; then
    cmd_service_remove
  fi

  cmd_uninstall --iface "$iface"

  if [[ $keep_fw -eq 0 ]]; then
    cmd_fw_remove
  fi

  log "[down] completed"
}

cmd_doctor() {
  require_root

  local quick=0
  local -a args=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --quick)
        quick=1
        shift
        ;;
      *)
        args+=("$1")
        shift
        ;;
    esac
  done

  local iface
  iface=$(parse_iface "${args[@]}")
  validate_iface "$iface"

  local failures=0
  echo "=== Doctor Report ==="
  echo "iface=$iface"
  echo "mode=$([[ $quick -eq 1 ]] && echo quick || echo full)"

  echo
  echo "[Check] status"
  if cmd_status --iface "$iface"; then
    echo "result=status:PASS"
  else
    echo "result=status:FAIL"
    failures=$((failures + 1))
  fi

  echo
  echo "[Check] firewall"
  if cmd_fw_status; then
    echo "result=firewall:PASS"
  else
    echo "result=firewall:FAIL"
    failures=$((failures + 1))
  fi

  if [[ $quick -eq 0 ]]; then
    echo
    echo "[Check] health"
    if cmd_health_check --iface "$iface"; then
      echo "result=health:PASS"
    else
      echo "result=health:FAIL"
      failures=$((failures + 1))
    fi

    echo
    echo "[Check] self-test"
    if cmd_self_test --iface "$iface"; then
      echo "result=self-test:PASS"
    else
      echo "result=self-test:FAIL"
      failures=$((failures + 1))
    fi
  fi

  echo
  if [[ $failures -eq 0 ]]; then
    echo "doctor_summary=PASS"
    return 0
  fi

  echo "doctor_summary=FAIL($failures)"
  return 1
}

main() {
  local cmd="${1:-}"
  shift || true

  case "$cmd" in
    up) cmd_up "$@" ;;
    down) cmd_down "$@" ;;
    doctor) cmd_doctor "$@" ;;
    _fw-apply) cmd_fw_install "$@" ;;
    _health-check) cmd_health_check "$@" ;;
    _runtime-install) cmd_install "$@" ;;
    _runtime-uninstall) cmd_uninstall "$@" ;;
    tg-test) cmd_tg_test "$@" ;;
    value-report) cmd_value_report "$@" ;;
    surface-audit) cmd_surface_audit "$@" ;;
    -h|--help|help|"") usage ;;
    *)
      err "Unknown command: $cmd"
      usage
      exit 1
      ;;
  esac
}

main "$@"
