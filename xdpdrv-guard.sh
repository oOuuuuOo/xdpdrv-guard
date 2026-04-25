#!/usr/bin/env bash
set -euo pipefail

PROGRAM_NAME="xdpdrv-guard"
VERSION="0.1.1"

# Auto-detect repo root (AUDIT §3.1): the script can live anywhere as long as
# the BUILD/EXAMPLE artifacts are siblings. Falls back to /home/xdpdrv-guard
# for backwards compatibility with users who packaged the legacy path.
__resolve_base_dir() {
  local self src dir
  self="${BASH_SOURCE[0]:-$0}"
  if [[ -L "$self" ]]; then
    src="$(readlink -f "$self" 2>/dev/null || readlink "$self")"
  else
    src="$self"
  fi
  dir="$(cd "$(dirname "$src")" >/dev/null 2>&1 && pwd)" || dir=""
  if [[ -z "$dir" ]]; then
    echo "/home/xdpdrv-guard"
    return
  fi
  echo "$dir"
}
BASE_DIR="${XDPDRV_GUARD_BASE_DIR:-$(__resolve_base_dir)}"
BUILD_DIR="$BASE_DIR/build"
SRC_FILE="$BUILD_DIR/xdp_syn_guard.c"
OBJ_FILE="$BUILD_DIR/xdp_syn_guard.o"
CONF_FILE="/etc/xdpdrv-guard.conf"
EXAMPLE_CONF="$BASE_DIR/xdpdrv-guard.conf.example"
STATE_DIR="/var/lib/xdpdrv-guard"
STATE_FILE="$STATE_DIR/runtime.env"
LOCK_FILE="/var/lock/xdpdrv-guard.lock"
SYSTEMD_UNIT_FILE="/etc/systemd/system/xdpdrv-guard.service"
SYSTEMD_UNIT_NAME="xdpdrv-guard.service"
SERVICE_ENV_FILE="/etc/default/xdpdrv-guard"
FW_STATE_FILE="$STATE_DIR/firewall.env"
FW_TABLE_FAMILY="inet"
FW_TABLE_NAME="xdpdrv_guard"
FW_CHAIN_NAME="xdpdrv_guard_input"
FW_SYNC_HASH_FILE="$STATE_DIR/firewall_sync.hash"
FW_SYNC_SYSTEMD_SERVICE_FILE="/etc/systemd/system/xdpdrv-guard-fw-sync.service"
FW_SYNC_SYSTEMD_TIMER_FILE="/etc/systemd/system/xdpdrv-guard-fw-sync.timer"
FW_SYNC_ENV_FILE="/etc/default/xdpdrv-guard-sync"
MOTD_SCRIPT_FILE="/etc/update-motd.d/99-xdpdrv-guard"

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
  xdpdrv-guard.sh config-ui [--iface IFACE]
  xdpdrv-guard.sh rules-ui [--iface IFACE]
  xdpdrv-guard.sh fw-sync-install [--iface IFACE]
  xdpdrv-guard.sh fw-sync-remove
  xdpdrv-guard.sh fw-sync-status
  xdpdrv-guard.sh fw-sync-now [--iface IFACE]
  xdpdrv-guard.sh motd-install [--iface IFACE]
  xdpdrv-guard.sh motd-remove
  xdpdrv-guard.sh login-report [--iface IFACE]
  xdpdrv-guard.sh --version | -V

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
  sudo xdpdrv-guard.sh config-ui --iface eth0
  sudo xdpdrv-guard.sh rules-ui --iface eth0
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
  mkdir -p "$(dirname "$LOCK_FILE")"
}

# Serialize mutating commands so concurrent timer-driven syncs, manual `up`
# invocations, and config-ui edits cannot race on $CONF_FILE / OBJ build.
# AUDIT §1.6. Reentrant within the same process.
__lock_held=0
acquire_install_lock() {
  if (( __lock_held )); then return 0; fi
  mkdir -p "$(dirname "$LOCK_FILE")" 2>/dev/null || true
  exec 9<>"$LOCK_FILE" 2>/dev/null || {
    err "Cannot open lock file $LOCK_FILE"
    exit 1
  }
  if ! command -v flock >/dev/null 2>&1; then
    # flock missing: degrade to a best-effort PID note, but proceed.
    log "warning: flock not found; serialization weakened."
    __lock_held=1
    return 0
  fi
  if ! flock -w 30 -x 9; then
    err "Another $PROGRAM_NAME operation is in progress (lock=$LOCK_FILE). Aborting."
    exit 1
  fi
  __lock_held=1
}

CONF_ALLOWED_KEYS=(
  ALLOWED_TCP_PORTS
  ALLOWED_UDP_PORTS
  IFACE
  AUTO_ALLOW_SSH_PORTS
  ALLOWED_TCP_SYN_RATE_PER_SEC
  BLOCK_PUBLIC_TCP_PORTS
  TELEGRAM_ENABLED
  TELEGRAM_BOT_TOKEN
  TELEGRAM_CHAT_ID
)

# Verify a config-style file is owned by root and not world/group writable.
# Refuse to load if it is, since we will assign values into the running shell.
# See AUDIT §1.3.
verify_conf_perms() {
  local path="$1"
  [[ -f "$path" ]] || return 0
  local owner mode mode_num
  owner="$(stat -c '%u' "$path" 2>/dev/null || echo -1)"
  mode="$(stat -c '%a' "$path" 2>/dev/null || echo 777)"
  if [[ "$owner" != "0" ]]; then
    err "Refusing to load $path: owner uid=$owner (expected 0/root)."
    exit 1
  fi
  # Reject any group- or world-writable bit.
  if [[ "$mode" =~ ^[0-7]+$ ]]; then
    mode_num=$((8#$mode))
    if (( mode_num & 0022 )); then
      err "Refusing to load $path: mode=$mode is group/world writable (max 0644 or 0600)."
      exit 1
    fi
  fi
}

# Whitelist parser for config-style key=value files. Only assigns to keys
# explicitly listed in CONF_ALLOWED_KEYS; rejects command substitution and
# other shell metachars in the value. Strips a single layer of surrounding
# single or double quotes.
parse_conf_file() {
  local path="$1"
  [[ -f "$path" ]] || return 0
  verify_conf_perms "$path"

  local line lineno=0 key val first last
  while IFS= read -r line || [[ -n "$line" ]]; do
    lineno=$((lineno + 1))
    # strip leading whitespace
    line="${line#"${line%%[![:space:]]*}"}"
    [[ -z "$line" || "${line:0:1}" == "#" ]] && continue
    if [[ ! "$line" =~ ^([A-Z_][A-Z0-9_]*)=(.*)$ ]]; then
      continue
    fi
    key="${BASH_REMATCH[1]}"
    val="${BASH_REMATCH[2]}"
    # strip trailing inline comment ONLY when value not quoted (best-effort)
    # — we keep the implementation conservative: do not auto-strip; users
    # should not append `# comment` after a bare value.
    # Strip surrounding quotes if matched.
    first="${val:0:1}"; last="${val: -1}"
    if [[ ${#val} -ge 2 ]]; then
      if [[ ( "$first" == '"' && "$last" == '"' ) || ( "$first" == "'" && "$last" == "'" ) ]]; then
        val="${val:1:${#val}-2}"
      fi
    fi
    # Reject obvious shell injection vectors: command substitution, backticks,
    # statement separators, redirection. Plain text values do not need these.
    if [[ "$val" == *'$('* || "$val" == *'\`'* || "$val" == *';'* || \
          "$val" == *'&&'* || "$val" == *'||'* || "$val" == *'|'* || \
          "$val" == *'>'* || "$val" == *'<'* ]]; then
      err "Refusing unsafe value at $path:$lineno for key $key"
      exit 1
    fi
    # Whitelist key.
    local allowed=0 k
    for k in "${CONF_ALLOWED_KEYS[@]}"; do
      if [[ "$k" == "$key" ]]; then allowed=1; break; fi
    done
    if (( ! allowed )); then
      continue
    fi
    printf -v "$key" '%s' "$val"
  done < "$path"
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

  parse_conf_file "$CONF_FILE"

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
  # Match the canonical `users:(("sshd",pid=...))` field that ss prints.
  # Avoids matching unrelated binaries with "sshd" as a substring of their
  # name or command line (AUDIT §3.4).
  local ports
  ports=$(ss -H -ltnp 2>/dev/null \
    | awk '$0 ~ /users:\(\("sshd",/ {print $4}' \
    | sed -E 's/.*:([0-9]+)$/\1/' \
    | awk '/^[0-9]+$/' \
    | sort -nu \
    | tr '\n' ',' \
    | sed 's/,$//')
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

ensure_config_file() {
  if [[ ! -f "$CONF_FILE" ]]; then
    cp "$EXAMPLE_CONF" "$CONF_FILE"
  fi
}

set_config_string_value() {
  local key="$1"
  local value="$2"
  ensure_config_file

  local tmp
  tmp=$(mktemp)
  awk -v k="$key" -v v="$value" '
    BEGIN { done=0 }
    $0 ~ "^" k "=" {
      print k "=\"" v "\""
      done=1
      next
    }
    { print }
    END {
      if (!done) {
        print k "=\"" v "\""
      }
    }
  ' "$CONF_FILE" > "$tmp"
  mv -f "$tmp" "$CONF_FILE"
}

is_valid_port_token() {
  local token="$1"
  local start end

  token="$(echo "$token" | xargs)"
  [[ -z "$token" ]] && return 1

  if [[ "$token" == *"-"* ]]; then
    start="${token%%-*}"
    end="${token##*-}"
    [[ "$start" =~ ^[0-9]+$ && "$end" =~ ^[0-9]+$ ]] || return 1
    (( start >= 1 && start <= 65535 && end >= 1 && end <= 65535 && start <= end )) || return 1
    return 0
  fi

  [[ "$token" =~ ^[0-9]+$ ]] || return 1
  (( token >= 1 && token <= 65535 )) || return 1
  return 0
}

expand_ports_csv_to_lines() {
  local csv="$1"
  local err_var_name="${2:-PORTS}"

  [[ -z "$csv" ]] && return 0

  IFS=',' read -r -a tokens <<< "$csv"
  for raw in "${tokens[@]}"; do
    local token start end p
    token="$(echo "$raw" | xargs)"
    [[ -z "$token" ]] && continue

    if ! is_valid_port_token "$token"; then
      err "Invalid port token in ${err_var_name}: $token"
      exit 1
    fi

    if [[ "$token" == *"-"* ]]; then
      start="${token%%-*}"
      end="${token##*-}"
      for (( p=start; p<=end; p++ )); do
        echo "$p"
      done
    else
      echo "$token"
    fi
  done | sort -n -u
}

compress_ports_lines_to_csv() {
  local out
  out="$({
    awk '
      NR == 1 {
        start = $1
        prev = $1
        next
      }
      {
        if ($1 == prev + 1) {
          prev = $1
          next
        }
        if (n > 0) {
          printf(",")
        }
        if (start == prev) {
          printf("%d", start)
        } else {
          printf("%d-%d", start, prev)
        }
        n++
        start = $1
        prev = $1
      }
      END {
        if (NR == 0) {
          exit
        }
        if (n > 0) {
          printf(",")
        }
        if (start == prev) {
          printf("%d", start)
        } else {
          printf("%d-%d", start, prev)
        }
      }
    '
  } | tr -d '\n')"
  echo "$out"
}

normalize_ports_csv() {
  local csv="$1"
  local err_var_name="${2:-PORTS}"
  local lines
  lines="$(expand_ports_csv_to_lines "$csv" "$err_var_name")"
  if [[ -z "$lines" ]]; then
    echo ""
    return
  fi
  echo "$lines" | compress_ports_lines_to_csv
}

csv_add_token_compact() {
  local base_csv="$1"
  local token_csv="$2"
  local merged lines

  [[ -z "$token_csv" ]] && { echo "$base_csv"; return; }
  merged="$base_csv"
  if [[ -n "$merged" ]]; then
    merged+=",$token_csv"
  else
    merged="$token_csv"
  fi

  lines="$(expand_ports_csv_to_lines "$merged" "PORTS")"
  [[ -z "$lines" ]] && { echo ""; return; }
  echo "$lines" | compress_ports_lines_to_csv
}

csv_remove_token_compact() {
  local base_csv="$1"
  local token_csv="$2"
  local base_file remove_file out_file

  [[ -z "$base_csv" ]] && { echo ""; return; }
  [[ -z "$token_csv" ]] && { echo "$base_csv"; return; }

  base_file=$(mktemp)
  remove_file=$(mktemp)
  out_file=$(mktemp)

  expand_ports_csv_to_lines "$base_csv" "PORTS" > "$base_file"
  expand_ports_csv_to_lines "$token_csv" "PORTS" > "$remove_file"
  comm -23 "$base_file" "$remove_file" > "$out_file" || true

  local out=""
  if [[ -s "$out_file" ]]; then
    out="$(compress_ports_lines_to_csv < "$out_file")"
  fi

  rm -f "$base_file" "$remove_file" "$out_file"
  echo "$out"
}

port_in_csv() {
  local csv="$1"
  local port="$2"
  [[ -z "$csv" ]] && return 1
  [[ "$port" =~ ^[0-9]+$ ]] || return 1

  IFS=',' read -r -a tokens <<< "$csv"
  for raw in "${tokens[@]}"; do
    local token start end
    token="$(echo "$raw" | xargs)"
    [[ -z "$token" ]] && continue
    if [[ "$token" == *"-"* ]]; then
      start="${token%%-*}"
      end="${token##*-}"
      if (( port >= start && port <= end )); then
        return 0
      fi
    else
      if (( port == token )); then
        return 0
      fi
    fi
  done
  return 1
}

discover_listening_ports() {
  {
    ss -H -lnt4 2>/dev/null | awk '{print "tcp|"$4"|ipv4"}'
    ss -H -lnt6 2>/dev/null | awk '{print "tcp|"$4"|ipv6"}'
    ss -H -lnu4 2>/dev/null | awk '{print "udp|"$4"|ipv4"}'
    ss -H -lnu6 2>/dev/null | awk '{print "udp|"$4"|ipv6"}'
  } | awk -F'|' '
    {
      proto=$1
      local_addr=$2
      stack=$3
      port=local_addr
      sub(/^.*:/, "", port)
      if (port ~ /^[0-9]+$/) {
        print proto "|" port "|" stack
      }
    }
  ' | sort -t'|' -k1,1 -k2,2n -k3,3 -u
}

render_port_rules_table() {
  local -a rows
  local line

  mapfile -t rows < <(discover_listening_ports)
  printf "%-6s %-7s %-6s %-8s\n" "PROTO" "PORT" "STACK" "XDP"
  printf "%-6s %-7s %-6s %-8s\n" "-----" "----" "-----" "---"

  if (( ${#rows[@]} == 0 )); then
    echo "(no listening sockets discovered by ss)"
    return
  fi

  for line in "${rows[@]}"; do
    local proto port stack allow_state="BLOCK"
    IFS='|' read -r proto port stack <<< "$line"

    if [[ "$proto" == "tcp" ]]; then
      if port_in_csv "${ALLOWED_TCP_PORTS:-}" "$port"; then
        allow_state="ALLOW"
      fi
    else
      if [[ -z "${ALLOWED_UDP_PORTS:-}" ]] || port_in_csv "${ALLOWED_UDP_PORTS:-}" "$port"; then
        allow_state="ALLOW"
      fi
    fi

    printf "%-6s %-7s %-6s %-8s\n" "$proto" "$port" "$stack" "$allow_state"
  done
}

collect_ports_from_lines() {
  local out_csv=""
  local token
  while IFS= read -r token; do
    token="$(echo "$token" | xargs)"
    [[ -z "$token" ]] && continue
    if ! is_valid_port_token "$token"; then
      continue
    fi
    out_csv="$(csv_add_token_compact "$out_csv" "$token")"
  done
  echo "$out_csv"
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

/* IPv6 extension header protocol numbers — not always exposed by <linux/in.h>. */
#ifndef IPPROTO_HOPOPTS
#define IPPROTO_HOPOPTS  0
#endif
#ifndef IPPROTO_ROUTING
#define IPPROTO_ROUTING  43
#endif
#ifndef IPPROTO_FRAGMENT
#define IPPROTO_FRAGMENT 44
#endif
#ifndef IPPROTO_DSTOPTS
#define IPPROTO_DSTOPTS  60
#endif

/* 802.1Q / 802.1ad ethertypes — DOUBLE_TAG often missing on older headers. */
#ifndef ETH_P_8021Q
#define ETH_P_8021Q  0x8100
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

struct vlan_hdr_local {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

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

        /*
         * Later-fragment IPv4 packets carry no L4 header; we can't read
         * dport, so we have nothing to filter on — pass to kernel.
         * AUDIT §2.3.
         */
        __u16 frag_off_h = __builtin_bswap16(iph->frag_off);
        if ((frag_off_h & 0x1FFF) != 0) {
            return XDP_PASS;
        }

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

        /*
         * Walk IPv6 extension header chain (HBH/DESTOPT/ROUTING) before
         * touching L4. Fragment header => no full L4 in this packet, PASS.
         * Bounded by 6 iterations so the verifier accepts the loop.
         * See AUDIT §1.2.
         */
        __u8 nexthdr = ip6h->nexthdr;
        unsigned char *cur = (unsigned char *)(ip6h + 1);

        #pragma unroll
        for (int __i = 0; __i < 6; __i++) {
            if (nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP) break;
            if (nexthdr == IPPROTO_HOPOPTS ||
                nexthdr == IPPROTO_DSTOPTS ||
                nexthdr == IPPROTO_ROUTING) {
                struct ipv6_opt_hdr *opt = (struct ipv6_opt_hdr *)cur;
                if ((void *)(opt + 1) > data_end) return XDP_PASS;
                __u32 hdr_len = ((__u32)opt->hdrlen + 1) * 8;
                if ((void *)(cur + hdr_len) > data_end) return XDP_PASS;
                nexthdr = opt->nexthdr;
                cur += hdr_len;
                continue;
            }
            if (nexthdr == IPPROTO_FRAGMENT) {
                /* Fragmented v6 packet — no usable L4 header here. */
                return XDP_PASS;
            }
            /* AH, ESP, MH, NONE, unknown — let kernel handle. */
            return XDP_PASS;
        }

        if (nexthdr == IPPROTO_TCP) {
            struct tcphdr *tcph = (struct tcphdr *)cur;
            if ((void *)(tcph + 1) > data_end) return XDP_PASS;

            if (tcph->syn && !tcph->ack) {
                __u16 dport = __builtin_bswap16(tcph->dest);
                if (!is_allowed_tcp_port(dport)) {
                    return XDP_DROP;
                }
            }
            return XDP_PASS;
        }

        if (nexthdr == IPPROTO_UDP) {
            struct udphdr *udph = (struct udphdr *)cur;
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

    /*
     * Unwrap up to two VLAN tags (covers single-tagged 802.1Q and
     * Q-in-Q / 802.1ad). Without this, VLAN-trunked traffic on the host
     * NIC bypasses the SYN guard entirely. AUDIT §2.3.
     */
    #pragma unroll
    for (int __vi = 0; __vi < 2; __vi++) {
        if (h_proto != __builtin_bswap16(ETH_P_8021Q) &&
            h_proto != __builtin_bswap16(ETH_P_8021AD)) break;
        struct vlan_hdr_local *vh = (struct vlan_hdr_local *)((unsigned char *)data + nh_off);
        if ((void *)(vh + 1) > data_end) return XDP_PASS;
        h_proto = vh->h_vlan_encapsulated_proto;
        nh_off += sizeof(*vh);
    }

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
  # Cache by content hash, not mtime (AUDIT §3.6): a stray `touch SRC` would
  # otherwise force a needless recompile, and the inverse — restoring an old
  # SRC over a newer OBJ — could leave a stale .o on disk.
  local hash_file="${OBJ_FILE}.srchash"
  local cur_hash=""
  if [[ -s "$SRC_FILE" ]] && command -v sha256sum >/dev/null 2>&1; then
    cur_hash="$(sha256sum "$SRC_FILE" | awk '{print $1}')"
  fi
  if [[ -s "$OBJ_FILE" && -n "$cur_hash" && -f "$hash_file" ]]; then
    local prev_hash
    prev_hash="$(cat "$hash_file" 2>/dev/null || true)"
    if [[ "$prev_hash" == "$cur_hash" ]]; then
      log "compile: using cached object $OBJ_FILE (sha256 match)"
      return
    fi
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
  if [[ -n "$cur_hash" ]]; then
    printf '%s\n' "$cur_hash" > "$hash_file"
  fi
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

# Emit one "<lo> <hi>" pair per nft rule that drops TCP traffic on a fixed
# dport / dport range / dport set, EXCLUDING our own self-managed table
# (that table only drops `dport != {...}` and would otherwise show up here
# as "drop everything", masking which ports are actually blocked).
# Used by is_tcp_port_effectively_public. AUDIT §3.3.
_nft_collect_tcp_drop_dports() {
  nft -j list ruleset 2>/dev/null | jq -r --arg self_table "$FW_TABLE_NAME" '
    def expand(r):
      if (r | type) == "number" then [{m: r, M: r}]
      elif (r | type) == "object" and (r | has("range")) then [{m: r.range[0], M: r.range[1]}]
      elif (r | type) == "object" and (r | has("set")) then
        [ r.set[] |
          if (type == "number") then {m: ., M: .}
          elif (type == "object" and has("range")) then {m: .range[0], M: .range[1]}
          else empty end
        ]
      else [] end;
    .nftables[]?
    | select(has("rule"))
    | .rule
    | select((.table // "") != $self_table)
    | select(any(.expr[]?;
                 (type == "string" and . == "drop") or
                 (type == "object" and has("drop"))))
    | .expr[]?
    | select(type == "object" and has("match"))
    | .match
    | select((.left // {}) | type == "object")
    | select(((.left.payload // {}) | type) == "object")
    | select((.left.payload.protocol // "") == "tcp")
    | select((.left.payload.field // "") == "dport")
    | select((.op // "==") == "==")
    | (expand(.right))[]
    | "\(.m) \(.M)"
  ' 2>/dev/null
}

is_tcp_port_effectively_public() {
  local port="$1"

  if ! [[ "$port" =~ ^[0-9]+$ ]]; then
    return 0
  fi

  if command -v nft >/dev/null 2>&1; then
    if command -v jq >/dev/null 2>&1; then
      local lo hi line
      while IFS=' ' read -r lo hi; do
        [[ -z "$lo" || -z "$hi" ]] && continue
        if (( port >= lo && port <= hi )); then
          return 1
        fi
      done < <(_nft_collect_tcp_drop_dports)
    else
      # Fallback: stricter regex. Anchor the port number with word boundaries
      # to avoid '8080' matching when looking for '80'.
      local rules
      rules=$(nft list ruleset 2>/dev/null || true)

      if [[ "$port" == "22" ]] && echo "$rules" | grep -q 'drop-public-ssh'; then
        return 1
      fi

      if echo "$rules" | grep -Eq "tcp dport ${port}([ ,}].*)?drop"; then
        if ! echo "$rules" | grep -Eq "tcp dport ${port}([ ,}].*)?accept"; then
          return 1
        fi
      fi
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
  acquire_install_lock
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

collect_firewall_allowed_tcp_ports_nft() {
  command -v nft >/dev/null 2>&1 || return 0
  nft list ruleset 2>/dev/null | awk '
    /tcp dport/ && /accept/ {
      line=$0
      if (match(line, /tcp dport \{[^}]+\}/)) {
        token=substr(line, RSTART, RLENGTH)
        gsub(/^tcp dport \{/, "", token)
        gsub(/\}$/, "", token)
        n=split(token, arr, ",")
        for (i=1; i<=n; i++) {
          gsub(/^[ \t]+|[ \t]+$/, "", arr[i])
          print arr[i]
        }
      } else if (match(line, /tcp dport [0-9]+(-[0-9]+)?/)) {
        token=substr(line, RSTART, RLENGTH)
        gsub(/^tcp dport /, "", token)
        print token
      }
    }
  '
}

collect_firewall_allowed_tcp_ports_iptables() {
  command -v iptables >/dev/null 2>&1 || return 0
  iptables -S INPUT 2>/dev/null | awk '
    /-p tcp/ && /-j ACCEPT/ {
      line=$0
      if (match(line, /--dports [0-9,:-]+/)) {
        token=substr(line, RSTART, RLENGTH)
        gsub(/^--dports /, "", token)
        gsub(/:/, "-", token)
        n=split(token, arr, ",")
        for (i=1; i<=n; i++) print arr[i]
      } else if (match(line, /--dport [0-9:]+/)) {
        token=substr(line, RSTART, RLENGTH)
        gsub(/^--dport /, "", token)
        gsub(/:/, "-", token)
        print token
      }
    }
  '
}

collect_firewall_allowed_tcp_ports_ufw() {
  command -v ufw >/dev/null 2>&1 || return 0
  ufw status 2>/dev/null | awk '
    /ALLOW/ {
      if (match($0, /^[0-9]+(\/tcp)?[[:space:]]+ALLOW/)) {
        token=$1
        gsub(/\/tcp$/, "", token)
        print token
      }
    }
  '
}

discover_firewall_allowed_tcp_ports() {
  {
    collect_firewall_allowed_tcp_ports_nft
    collect_firewall_allowed_tcp_ports_iptables
    collect_firewall_allowed_tcp_ports_ufw
  } | collect_ports_from_lines
}

firewall_fingerprint() {
  # Goal: hash a stable view of *foreign* firewall state, ignoring:
  #   1. The self-managed table ($FW_TABLE_FAMILY $FW_TABLE_NAME) — otherwise our own rules feed back into the hash.
  #   2. Volatile per-rule counters — `counter packets N bytes M` (nft) and `[N:M]` (iptables-save) tick on every matched packet
  #      and would force a re-sync (and full XDP reattach) every poll cycle. See AUDIT §1.1.
  {
    if command -v nft >/dev/null 2>&1; then
      echo "=== NFT ==="
      nft list ruleset 2>/dev/null \
        | awk -v skip="table ${FW_TABLE_FAMILY} ${FW_TABLE_NAME}" '
            BEGIN { depth=0; skipping=0 }
            {
              line=$0
              if (skipping == 0 && index(line, skip) > 0 && match(line, /\{[[:space:]]*$/)) {
                skipping=1; depth=1; next
              }
              if (skipping) {
                n=gsub(/\{/, "{", line); depth += n
                m=gsub(/\}/, "}", line); depth -= m
                if (depth <= 0) skipping=0
                next
              }
              print
            }
          ' \
        | sed -E 's/counter packets [0-9]+ bytes [0-9]+//g; s/[[:space:]]+$//' \
        || true
    fi
    if command -v iptables-save >/dev/null 2>&1; then
      echo "=== IPTABLES ==="
      # iptables-save without -c omits packet/byte counters; strip any leading [N:M] just in case.
      iptables-save 2>/dev/null | sed -E 's/^\[[0-9]+:[0-9]+\] //' || true
    elif command -v iptables >/dev/null 2>&1; then
      echo "=== IPTABLES ==="
      iptables -S 2>/dev/null || true
    fi
    if command -v ufw >/dev/null 2>&1; then
      echo "=== UFW ==="
      ufw status 2>/dev/null || true
    fi
  } | sha256sum | awk '{print $1}'
}

write_fw_sync_systemd_unit() {
  cat > "$FW_SYNC_SYSTEMD_SERVICE_FILE" <<EOF
[Unit]
Description=XDPDRV Guard firewall sync hook
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=-$FW_SYNC_ENV_FILE
ExecStart=$BASE_DIR/xdpdrv-guard.sh _fw-sync-run --iface \${IFACE}

# Same sandbox profile as the main service (AUDIT §1.6).
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$BUILD_DIR $STATE_DIR /var/lock /run
ProtectKernelTunables=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_NETLINK AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=CAP_NET_ADMIN CAP_BPF CAP_SYS_ADMIN CAP_SYS_RESOURCE CAP_DAC_READ_SEARCH
EOF

  cat > "$FW_SYNC_SYSTEMD_TIMER_FILE" <<EOF
[Unit]
Description=Run xdpdrv firewall sync hook every 30s

[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
AccuracySec=5s
Unit=$(basename "$FW_SYNC_SYSTEMD_SERVICE_FILE")
Persistent=true

[Install]
WantedBy=timers.target
EOF
}

cmd_fw_sync_now() {
  require_root
  acquire_install_lock
  load_config

  local iface
  iface=$(parse_iface "$@")
  validate_iface "$iface"

  # Two-layer model (AUDIT §1.4):
  #   - Persistent baseline: ALLOWED_TCP_PORTS in $CONF_FILE (user-managed; never written back from sync).
  #   - Runtime merged view: baseline ∪ ports currently accepted by the host firewall stack.
  # If the operator removes a port from ufw/iptables/nft, the next sync round
  # naturally drops it from the runtime view because the merge is recomputed
  # from scratch each time, instead of accumulating into the conf forever.
  local baseline discovered runtime_ports
  baseline="${ALLOWED_TCP_PORTS:-}"
  discovered="$(discover_firewall_allowed_tcp_ports)"

  runtime_ports="$baseline"
  if [[ -n "$discovered" ]]; then
    runtime_ports="$(csv_add_token_compact "$runtime_ports" "$discovered")"
  fi
  runtime_ports="$(normalize_ports_csv "$runtime_ports" "ALLOWED_TCP_PORTS")"

  if [[ "$runtime_ports" != "$baseline" ]]; then
    log "fw-sync runtime view (baseline + firewall stack): $runtime_ports"
    log "fw-sync baseline (unchanged in $CONF_FILE): ${baseline:-<empty>}"
  else
    log "Firewall sync completed (no runtime port change)."
  fi

  # Apply via the runtime-merged port list without mutating $CONF_FILE.
  ALLOWED_TCP_PORTS="$runtime_ports"
  cmd_install --iface "$iface"
}

cmd_fw_sync_run() {
  require_root
  init_dirs

  local iface
  iface=$(parse_iface "$@")
  validate_iface "$iface"

  local current_hash old_hash=""
  current_hash="$(firewall_fingerprint)"
  if [[ -f "$FW_SYNC_HASH_FILE" ]]; then
    old_hash="$(cat "$FW_SYNC_HASH_FILE" 2>/dev/null || true)"
  fi

  if [[ "$current_hash" != "$old_hash" ]]; then
    log "Firewall change detected, syncing XDP rules."
    cmd_fw_sync_now --iface "$iface"
    echo "$current_hash" > "$FW_SYNC_HASH_FILE"
    return 0
  fi

  log "Firewall unchanged, skip sync."
}

cmd_fw_sync_install() {
  require_root
  require_systemd

  local iface
  iface=$(parse_iface "$@")
  validate_iface "$iface"

  init_dirs
  write_fw_sync_systemd_unit

  cat > "$FW_SYNC_ENV_FILE" <<EOF
# Managed by $PROGRAM_NAME
IFACE=$iface
EOF

  systemctl daemon-reload
  systemctl enable --now "$(basename "$FW_SYNC_SYSTEMD_TIMER_FILE")"
  cmd_fw_sync_run --iface "$iface" || true

  log "Firewall sync hook installed: $(basename "$FW_SYNC_SYSTEMD_TIMER_FILE")"
}

cmd_fw_sync_remove() {
  require_root
  require_systemd

  systemctl disable --now "$(basename "$FW_SYNC_SYSTEMD_TIMER_FILE")" >/dev/null 2>&1 || true
  rm -f "$FW_SYNC_SYSTEMD_SERVICE_FILE" "$FW_SYNC_SYSTEMD_TIMER_FILE" "$FW_SYNC_ENV_FILE" "$FW_SYNC_HASH_FILE"
  systemctl daemon-reload
  log "Firewall sync hook removed."
}

cmd_fw_sync_status() {
  local timer_name service_name
  timer_name="$(basename "$FW_SYNC_SYSTEMD_TIMER_FILE")"
  service_name="$(basename "$FW_SYNC_SYSTEMD_SERVICE_FILE")"

  echo "fw_sync_timer_file=$FW_SYNC_SYSTEMD_TIMER_FILE"
  echo "fw_sync_service_file=$FW_SYNC_SYSTEMD_SERVICE_FILE"
  echo "fw_sync_hash_file=$FW_SYNC_HASH_FILE"
  if [[ -f "$FW_SYNC_HASH_FILE" ]]; then
    echo "fw_sync_hash=$(cat "$FW_SYNC_HASH_FILE")"
  else
    echo "fw_sync_hash=absent"
  fi

  if command -v systemctl >/dev/null 2>&1; then
    local timer_enabled timer_active service_active
    timer_enabled="$(systemctl is-enabled "$timer_name" 2>/dev/null || true)"
    timer_active="$(systemctl is-active "$timer_name" 2>/dev/null || true)"
    service_active="$(systemctl is-active "$service_name" 2>/dev/null || true)"
    [[ -z "$timer_enabled" ]] && timer_enabled="disabled"
    [[ -z "$timer_active" ]] && timer_active="inactive"
    [[ -z "$service_active" ]] && service_active="inactive"
    echo "timer_enabled=$timer_enabled"
    echo "timer_active=$timer_active"
    echo "service_active=$service_active"
  else
    echo "systemd=absent"
  fi
}

cmd_config_ui() {
  require_root
  load_config

  local iface
  iface=$(parse_iface "$@")
  validate_iface "$iface"

  local discovered_tcp discovered_udp
  discovered_tcp="$(discover_listening_ports | awk -F'|' '$1=="tcp" {print $2}' | sort -n -u | tr '\n' ',' | sed 's/,$//')"
  discovered_udp="$(discover_listening_ports | awk -F'|' '$1=="udp" {print $2}' | sort -n -u | tr '\n' ',' | sed 's/,$//')"

  echo "=== Interactive Config UI ==="
  echo "iface=$iface"
  echo "current ALLOWED_TCP_PORTS=${ALLOWED_TCP_PORTS:-<empty>}"
  echo "current ALLOWED_UDP_PORTS=${ALLOWED_UDP_PORTS:-<empty>}"
  echo ""
  echo "Discovered listening ports from current protocol stack:"
  render_port_rules_table
  echo ""

  local ans
  read -r -p "Add all discovered TCP listening ports into ALLOWED_TCP_PORTS? [y/N]: " ans
  if [[ "$ans" =~ ^[Yy]$ && -n "$discovered_tcp" ]]; then
    ALLOWED_TCP_PORTS="$(csv_add_token_compact "${ALLOWED_TCP_PORTS:-}" "$discovered_tcp")"
  fi

  read -r -p "Add all discovered UDP listening ports into ALLOWED_UDP_PORTS? [y/N]: " ans
  if [[ "$ans" =~ ^[Yy]$ && -n "$discovered_udp" ]]; then
    ALLOWED_UDP_PORTS="$(csv_add_token_compact "${ALLOWED_UDP_PORTS:-}" "$discovered_udp")"
  fi

  read -r -p "Manual append for TCP ports/ranges (empty to skip): " ans
  if [[ -n "$ans" ]]; then
    ALLOWED_TCP_PORTS="$(csv_add_token_compact "$ALLOWED_TCP_PORTS" "$ans")"
  fi

  read -r -p "Manual append for UDP ports/ranges (empty to skip): " ans
  if [[ -n "$ans" ]]; then
    ALLOWED_UDP_PORTS="$(csv_add_token_compact "$ALLOWED_UDP_PORTS" "$ans")"
  fi

  ALLOWED_TCP_PORTS="$(normalize_ports_csv "$ALLOWED_TCP_PORTS" "ALLOWED_TCP_PORTS")"
  ALLOWED_UDP_PORTS="$(normalize_ports_csv "$ALLOWED_UDP_PORTS" "ALLOWED_UDP_PORTS")"

  echo ""
  echo "Preview after edit:"
  echo "ALLOWED_TCP_PORTS=$ALLOWED_TCP_PORTS"
  echo "ALLOWED_UDP_PORTS=$ALLOWED_UDP_PORTS"
  read -r -p "Save to $CONF_FILE and apply immediately? [Y/n]: " ans
  if [[ -z "$ans" || "$ans" =~ ^[Yy]$ ]]; then
    set_config_string_value "ALLOWED_TCP_PORTS" "$ALLOWED_TCP_PORTS"
    set_config_string_value "ALLOWED_UDP_PORTS" "$ALLOWED_UDP_PORTS"
    cmd_install --iface "$iface"
    log "Config updated and runtime reapplied."
  else
    log "Cancelled. No changes were written."
  fi
}

cmd_rules_ui() {
  require_root
  load_config

  local iface
  iface=$(parse_iface "$@")
  validate_iface "$iface"

  while true; do
    echo ""
    echo "=== XDP Port Rules UI ==="
    echo "iface=$iface"
    echo "ALLOWED_TCP_PORTS=${ALLOWED_TCP_PORTS:-<empty>}"
    echo "ALLOWED_UDP_PORTS=${ALLOWED_UDP_PORTS:-<empty>}"
    echo ""
    render_port_rules_table
    echo ""
    echo "1) View rules"
    echo "2) Append TCP rule"
    echo "3) Append UDP rule"
    echo "4) Delete TCP rule"
    echo "5) Delete UDP rule"
    echo "6) Save & apply"
    echo "0) Exit"

    local choice token
    read -r -p "Select: " choice
    case "$choice" in
      1)
        continue
        ;;
      2)
        read -r -p "Input TCP port/range (e.g. 443 or 10000-10100): " token
        if [[ -n "$token" ]]; then
          ALLOWED_TCP_PORTS="$(csv_add_token_compact "$ALLOWED_TCP_PORTS" "$token")"
        fi
        ;;
      3)
        read -r -p "Input UDP port/range (e.g. 53 or 3478-3480): " token
        if [[ -n "$token" ]]; then
          ALLOWED_UDP_PORTS="$(csv_add_token_compact "$ALLOWED_UDP_PORTS" "$token")"
        fi
        ;;
      4)
        read -r -p "Delete TCP port/range: " token
        if [[ -n "$token" ]]; then
          ALLOWED_TCP_PORTS="$(csv_remove_token_compact "$ALLOWED_TCP_PORTS" "$token")"
        fi
        ;;
      5)
        read -r -p "Delete UDP port/range: " token
        if [[ -n "$token" ]]; then
          ALLOWED_UDP_PORTS="$(csv_remove_token_compact "$ALLOWED_UDP_PORTS" "$token")"
        fi
        ;;
      6)
        ALLOWED_TCP_PORTS="$(normalize_ports_csv "$ALLOWED_TCP_PORTS" "ALLOWED_TCP_PORTS")"
        ALLOWED_UDP_PORTS="$(normalize_ports_csv "$ALLOWED_UDP_PORTS" "ALLOWED_UDP_PORTS")"
        set_config_string_value "ALLOWED_TCP_PORTS" "$ALLOWED_TCP_PORTS"
        set_config_string_value "ALLOWED_UDP_PORTS" "$ALLOWED_UDP_PORTS"
        cmd_install --iface "$iface"
        log "Rules saved and runtime reapplied."
        ;;
      0)
        break
        ;;
      *)
        echo "Invalid choice"
        ;;
    esac
  done
}

count_ss_local_port_state() {
  local state="$1"
  ss -H -nt state "$state" 2>/dev/null | awk '
    {
      local_addr=$4
      port=local_addr
      sub(/^.*:/, "", port)
      if (port ~ /^[0-9]+$/) {
        cnt[port]++
      }
    }
    END {
      for (p in cnt) {
        printf("%s %d\n", p, cnt[p])
      }
    }
  '
}

lookup_count_file() {
  local file="$1"
  local port="$2"
  awk -v p="$port" '$1==p {print $2; found=1; exit} END {if (!found) print 0}' "$file"
}

cmd_login_report() {
  load_config

  local iface
  iface=$(parse_iface "$@")
  if ! ip link show dev "$iface" >/dev/null 2>&1; then
    echo "xdpdrv-guard: iface $iface not found"
    return 0
  fi

  local rx_bytes rx_pkts rx_drop
  rx_bytes=$(cat "/sys/class/net/$iface/statistics/rx_bytes" 2>/dev/null || echo 0)
  rx_pkts=$(cat "/sys/class/net/$iface/statistics/rx_packets" 2>/dev/null || echo 0)
  rx_drop=$(cat "/sys/class/net/$iface/statistics/rx_dropped" 2>/dev/null || echo 0)

  local xdp_mode="detached"
  if ip -d link show dev "$iface" | grep -q 'xdpgeneric'; then
    xdp_mode="xdpgeneric"
  elif ip -d link show dev "$iface" | grep -q 'xdp '; then
    xdp_mode="xdpdrv"
  fi

  local syn_file est_file
  syn_file=$(mktemp)
  est_file=$(mktemp)
  count_ss_local_port_state syn-recv | sort -n > "$syn_file"
  count_ss_local_port_state established | sort -n > "$est_file"

  echo "=== XDPDRV Guard Login Report ==="
  echo "time=$(date -Is)"
  echo "iface=$iface"
  echo "xdp_mode=$xdp_mode"
  echo "allowed_tcp_ports=${ALLOWED_TCP_PORTS:-<empty>}"
  echo "allowed_udp_ports=${ALLOWED_UDP_PORTS:-<empty>}"
  echo "rx_packets_total=$rx_pkts rx_bytes_total=$rx_bytes rx_dropped_total=$rx_drop"
  echo ""
  printf "%-6s %-7s %-6s %-12s %-8s %-8s\n" "PROTO" "PORT" "STACK" "DROP_RATIO" "SYN_RECV" "EST"
  printf "%-6s %-7s %-6s %-12s %-8s %-8s\n" "-----" "----" "-----" "----------" "--------" "---"

  local -a rows
  local line
  mapfile -t rows < <(discover_listening_ports)
  if (( ${#rows[@]} == 0 )); then
    echo "(no listening sockets discovered)"
  else
    for line in "${rows[@]}"; do
      local proto port stack drop_ratio syn_count est_count
      IFS='|' read -r proto port stack <<< "$line"
      drop_ratio="0%"

      if [[ "$proto" == "tcp" ]]; then
        if port_in_csv "${BLOCK_PUBLIC_TCP_PORTS:-}" "$port"; then
          drop_ratio="100%"
        elif port_in_csv "${ALLOWED_TCP_PORTS:-}" "$port"; then
          if (( ALLOWED_TCP_SYN_RATE_PER_SEC > 0 )); then
            drop_ratio="0~100%"
          else
            drop_ratio="0%"
          fi
        else
          drop_ratio="100%"
        fi
      else
        if [[ -n "${ALLOWED_UDP_PORTS:-}" ]] && ! port_in_csv "${ALLOWED_UDP_PORTS:-}" "$port"; then
          drop_ratio="100%"
        fi
      fi

      syn_count="$(lookup_count_file "$syn_file" "$port")"
      est_count="$(lookup_count_file "$est_file" "$port")"
      printf "%-6s %-7s %-6s %-12s %-8s %-8s\n" "$proto" "$port" "$stack" "$drop_ratio" "$syn_count" "$est_count"
    done
  fi

  rm -f "$syn_file" "$est_file"
}

cmd_motd_install() {
  require_root
  load_config

  local iface
  iface=$(parse_iface "$@")
  validate_iface "$iface"

  # MOTD hook is read on every SSH login (incl. sftp/scp). Calling the full
  # bash report there made non-interactive sessions noticeably slower —
  # ss/ip/sysfs walks per session. Cache the output in /run and only refresh
  # if the snapshot is older than MOTD_CACHE_TTL_SEC. AUDIT §3.8.
  cat > "$MOTD_SCRIPT_FILE" <<EOF
#!/bin/sh
CACHE=/run/xdpdrv-guard/motd.txt
TTL=60
[ -f "$SERVICE_ENV_FILE" ] && . "$SERVICE_ENV_FILE"
if [ -z "\${IFACE:-}" ]; then
  IFACE="$iface"
fi

mkdir -p /run/xdpdrv-guard 2>/dev/null
if [ -s "\$CACHE" ]; then
  AGE=\$(( \$(date +%s) - \$(stat -c %Y "\$CACHE" 2>/dev/null || echo 0) ))
  if [ "\$AGE" -ge 0 ] && [ "\$AGE" -lt "\$TTL" ]; then
    cat "\$CACHE"
    exit 0
  fi
fi

# Stale or missing — regenerate synchronously, write atomically.
TMP="\$CACHE.\$\$"
if "$BASE_DIR/xdpdrv-guard.sh" login-report --iface "\$IFACE" > "\$TMP" 2>/dev/null; then
  mv -f "\$TMP" "\$CACHE" 2>/dev/null
  cat "\$CACHE" 2>/dev/null
else
  rm -f "\$TMP" 2>/dev/null
  # Last-resort: emit a minimal one-liner so the login isn't blank.
  echo "xdpdrv-guard: report unavailable (iface=\$IFACE)"
fi
EOF
  chmod 0755 "$MOTD_SCRIPT_FILE"

  # Pre-warm cache so the very first login after install is also fast.
  mkdir -p /run/xdpdrv-guard 2>/dev/null || true
  if cmd_login_report --iface "$iface" > /run/xdpdrv-guard/motd.txt.tmp 2>/dev/null; then
    mv -f /run/xdpdrv-guard/motd.txt.tmp /run/xdpdrv-guard/motd.txt 2>/dev/null || true
  else
    rm -f /run/xdpdrv-guard/motd.txt.tmp 2>/dev/null || true
  fi

  log "Installed SSH MOTD report hook (60s cache): $MOTD_SCRIPT_FILE"
}

cmd_motd_remove() {
  require_root
  rm -f "$MOTD_SCRIPT_FILE"
  rm -f /run/xdpdrv-guard/motd.txt 2>/dev/null || true
  log "Removed SSH MOTD report hook."
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

# Sandbox hardening (AUDIT §1.6). Surface area minimization:
#   - Drop process privilege escalation.
#   - Read-only / / usr / etc; only repo build dir, state dir and runtime
#     dir are writable, plus /run for state notifications.
#   - Limit syscall-visible address families and capability set to what
#     the BPF + nftables + iproute2 path actually requires.
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$BUILD_DIR $STATE_DIR /var/lock /run
ProtectKernelTunables=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_NETLINK AF_UNIX AF_INET AF_INET6
# Service runs as root; CapabilityBoundingSet here just caps the maximum
# privilege any child process can acquire/regain to the BPF + netlink set.
CapabilityBoundingSet=CAP_NET_ADMIN CAP_BPF CAP_SYS_ADMIN CAP_SYS_RESOURCE CAP_DAC_READ_SEARCH

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
  acquire_install_lock
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

  # Stage 1: generate + compile first. clang failure now leaves both nft
  # rules and the live XDP program untouched. AUDIT §3.7.
  generate_c_program
  compile_program

  # Stage 2: snapshot the existing self-managed nft table so we can put it
  # back if attach fails after we've already swapped fw rules.
  local fw_snapshot=""
  if [[ $skip_fw -eq 0 ]] && nft_table_exists; then
    fw_snapshot="$(nft list table "$FW_TABLE_FAMILY" "$FW_TABLE_NAME" 2>/dev/null || true)"
  fi

  # Stage 3: replace fw rules.
  if [[ $skip_fw -eq 0 ]]; then
    cmd_fw_install --iface "$iface"
  fi

  # Stage 4: detach + attach the BPF program. On failure, roll the fw back
  # to the snapshot so we don't leave the host with a fresh nft table but
  # no XDP program (the worst of both worlds).
  detach_xdp_all_modes "$iface"
  if ! attach_xdpdrv "$iface"; then
    err "Attach failed; attempting firewall rollback."
    if [[ $skip_fw -eq 0 ]]; then
      if nft_table_exists; then
        nft delete table "$FW_TABLE_FAMILY" "$FW_TABLE_NAME" >/dev/null 2>&1 || true
      fi
      if [[ -n "$fw_snapshot" ]]; then
        if printf '%s\n' "$fw_snapshot" | nft -f - 2>/dev/null; then
          log "Firewall rollback: restored previous $FW_TABLE_NAME table."
        else
          err "Firewall rollback failed; manual nft inspection recommended."
        fi
      else
        log "Firewall rollback: no previous table existed; left removed."
      fi
    fi
    return 1
  fi
  save_state "$iface"

  log "Installed in xdpdrv mode on $iface"
  ip -d link show dev "$iface" | sed -n '1,4p'
}

cmd_reload() {
  cmd_install "$@"
}

cmd_uninstall() {
  require_root
  acquire_install_lock
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
    config-ui) cmd_config_ui "$@" ;;
    rules-ui) cmd_rules_ui "$@" ;;
    _fw-apply) cmd_fw_install "$@" ;;
    _fw-sync-run) cmd_fw_sync_run "$@" ;;
    fw-sync-now) cmd_fw_sync_now "$@" ;;
    fw-sync-install) cmd_fw_sync_install "$@" ;;
    fw-sync-remove) cmd_fw_sync_remove "$@" ;;
    fw-sync-status) cmd_fw_sync_status "$@" ;;
    _health-check) cmd_health_check "$@" ;;
    _runtime-install) cmd_install "$@" ;;
    _runtime-uninstall) cmd_uninstall "$@" ;;
    tg-test) cmd_tg_test "$@" ;;
    value-report) cmd_value_report "$@" ;;
    surface-audit) cmd_surface_audit "$@" ;;
    login-report) cmd_login_report "$@" ;;
    motd-install) cmd_motd_install "$@" ;;
    motd-remove) cmd_motd_remove "$@" ;;
    -V|--version|version)
      printf '%s %s\n' "$PROGRAM_NAME" "$VERSION"
      ;;
    -h|--help|help|"") usage ;;
    *)
      err "Unknown command: $cmd"
      usage
      exit 1
      ;;
  esac
}

main "$@"
