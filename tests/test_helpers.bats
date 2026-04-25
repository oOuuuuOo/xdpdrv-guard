#!/usr/bin/env bats

# Unit tests for pure-bash helpers in xdpdrv-guard.sh.
# Run with: bats tests/

setup() {
    SCRIPT="${BATS_TEST_DIRNAME}/../xdpdrv-guard.sh"
    [ -f "$SCRIPT" ] || skip "xdpdrv-guard.sh not found at $SCRIPT"

    # Source under test guard so main() does not auto-invoke.
    # set +e so the script's `set -euo pipefail` does not abort bats.
    set +e
    __XDPDRV_GUARD_TEST_MODE=1
    export __XDPDRV_GUARD_TEST_MODE
    # shellcheck disable=SC1090
    source "$SCRIPT"
}

# --- trim_ws ---------------------------------------------------------------

@test "trim_ws strips leading and trailing whitespace" {
    [ "$(trim_ws '  22  ')" = "22" ]
    [ "$(trim_ws "$(printf '\t  443  \n')")" = "443" ]
}

@test "trim_ws preserves internal whitespace" {
    # Pure-bash trim does NOT squash internals (different from old echo|xargs).
    [ "$(trim_ws '  22 80  ')" = "22 80" ]
}

@test "trim_ws on empty returns empty" {
    [ -z "$(trim_ws '')" ]
    [ -z "$(trim_ws '   ')" ]
}

# --- is_valid_port_token ---------------------------------------------------

@test "is_valid_port_token accepts a single valid port" {
    is_valid_port_token "22"
    is_valid_port_token "65535"
}

@test "is_valid_port_token accepts a valid range" {
    is_valid_port_token "10000-10100"
}

@test "is_valid_port_token rejects port 0" {
    run is_valid_port_token "0"
    [ "$status" -ne 0 ]
}

@test "is_valid_port_token rejects port 65536" {
    run is_valid_port_token "65536"
    [ "$status" -ne 0 ]
}

@test "is_valid_port_token rejects non-numeric" {
    run is_valid_port_token "abc"
    [ "$status" -ne 0 ]
    run is_valid_port_token "22a"
    [ "$status" -ne 0 ]
}

@test "is_valid_port_token rejects inverted range" {
    run is_valid_port_token "100-50"
    [ "$status" -ne 0 ]
}

@test "is_valid_port_token rejects empty token" {
    run is_valid_port_token ""
    [ "$status" -ne 0 ]
}

# --- normalize_ports_csv ---------------------------------------------------

@test "normalize_ports_csv sorts and deduplicates" {
    result="$(normalize_ports_csv '443,80,22,80,443')"
    [ "$result" = "22,80,443" ]
}

@test "normalize_ports_csv compresses adjacent ports into ranges" {
    result="$(normalize_ports_csv '80,81,82,90,91')"
    [ "$result" = "80-82,90-91" ]
}

@test "normalize_ports_csv merges overlapping ranges" {
    result="$(normalize_ports_csv '10000-10050,10040-10100')"
    [ "$result" = "10000-10100" ]
}

@test "normalize_ports_csv folds single port covered by range" {
    result="$(normalize_ports_csv '10000-10100,10050')"
    [ "$result" = "10000-10100" ]
}

@test "normalize_ports_csv on empty returns empty" {
    result="$(normalize_ports_csv '')"
    [ -z "$result" ]
}

# --- csv_add_token_compact -------------------------------------------------

@test "csv_add_token_compact appends to non-empty base" {
    result="$(csv_add_token_compact '22,80' '443')"
    [ "$result" = "22,80,443" ]
}

@test "csv_add_token_compact treats empty base as new" {
    result="$(csv_add_token_compact '' '443')"
    [ "$result" = "443" ]
}

@test "csv_add_token_compact with empty token leaves base unchanged" {
    result="$(csv_add_token_compact '22,80' '')"
    [ "$result" = "22,80" ]
}

@test "csv_add_token_compact compresses after merge" {
    result="$(csv_add_token_compact '80,81' '82,83')"
    [ "$result" = "80-83" ]
}

@test "csv_add_token_compact dedupes overlapping" {
    result="$(csv_add_token_compact '22,80,443' '80,443,8080')"
    [ "$result" = "22,80,443,8080" ]
}

# --- csv_remove_token_compact ----------------------------------------------

@test "csv_remove_token_compact removes a single port" {
    result="$(csv_remove_token_compact '22,80,443' '80')"
    [ "$result" = "22,443" ]
}

@test "csv_remove_token_compact splits a range when removing middle" {
    result="$(csv_remove_token_compact '10000-10003' '10001')"
    [ "$result" = "10000,10002-10003" ]
}

@test "csv_remove_token_compact yields empty when removing all" {
    result="$(csv_remove_token_compact '22,80' '22,80')"
    [ -z "$result" ]
}

@test "csv_remove_token_compact with empty base returns empty" {
    result="$(csv_remove_token_compact '' '22')"
    [ -z "$result" ]
}

@test "csv_remove_token_compact with empty token is identity" {
    result="$(csv_remove_token_compact '22,80,443' '')"
    [ "$result" = "22,80,443" ]
}

@test "csv_remove_token_compact handles lexical/numeric boundary (99 vs 100)" {
    # Regression: previous comm-based impl tripped on lexical vs numeric
    # ordering at multi-digit boundaries.
    result="$(csv_remove_token_compact '99,100,101' '100')"
    [ "$result" = "99,101" ]
}

# --- port_in_csv -----------------------------------------------------------

@test "port_in_csv finds a single listed port" {
    port_in_csv '22,80,443' '80'
}

@test "port_in_csv finds a port inside a range" {
    port_in_csv '10000-10100' '10050'
}

@test "port_in_csv misses a port not in csv" {
    run port_in_csv '22,80,443' '8080'
    [ "$status" -ne 0 ]
}

@test "port_in_csv on empty csv returns false" {
    run port_in_csv '' '22'
    [ "$status" -ne 0 ]
}

@test "port_in_csv rejects non-numeric port arg" {
    run port_in_csv '22,80' 'abc'
    [ "$status" -ne 0 ]
}

# --- parse_conf_file -------------------------------------------------------

@test "parse_conf_file accepts a clean config" {
    f="$(mktemp)"
    cat > "$f" <<EOF
# comment
ALLOWED_TCP_PORTS="22,80,443"
ALLOWED_UDP_PORTS=
IFACE=eth0
EOF
    chown root:root "$f" 2>/dev/null || true
    chmod 0644 "$f"
    ALLOWED_TCP_PORTS="" ALLOWED_UDP_PORTS="" IFACE=""
    parse_conf_file "$f"
    [ "$ALLOWED_TCP_PORTS" = "22,80,443" ]
    [ -z "$ALLOWED_UDP_PORTS" ]
    [ "$IFACE" = "eth0" ]
    rm -f "$f"
}

_call_parse_in_subshell() {
    # parse_conf_file calls `exit 1` on rejection. Run it in a forked bash
    # so the exit doesn't take down bats itself.
    local conf="$1"
    bash -c "
        set +e
        __XDPDRV_GUARD_TEST_MODE=1
        source '$SCRIPT'
        parse_conf_file '$conf'
    "
}

@test "parse_conf_file rejects command substitution" {
    f="$(mktemp)"
    echo 'ALLOWED_TCP_PORTS=$(/bin/id)' > "$f"
    chown root:root "$f" 2>/dev/null || true
    chmod 0644 "$f"
    run _call_parse_in_subshell "$f"
    [ "$status" -ne 0 ]
    rm -f "$f"
}

@test "parse_conf_file rejects backticks" {
    f="$(mktemp)"
    printf 'ALLOWED_TCP_PORTS=`whoami`\n' > "$f"
    chown root:root "$f" 2>/dev/null || true
    chmod 0644 "$f"
    run _call_parse_in_subshell "$f"
    [ "$status" -ne 0 ]
    rm -f "$f"
}

@test "parse_conf_file rejects statement separator" {
    f="$(mktemp)"
    echo 'ALLOWED_TCP_PORTS=22 ; rm -rf /tmp' > "$f"
    chown root:root "$f" 2>/dev/null || true
    chmod 0644 "$f"
    run _call_parse_in_subshell "$f"
    [ "$status" -ne 0 ]
    rm -f "$f"
}

@test "parse_conf_file ignores keys not on the whitelist" {
    f="$(mktemp)"
    cat > "$f" <<EOF
ALLOWED_TCP_PORTS="22"
NOT_A_REAL_KEY="ignored"
EOF
    chown root:root "$f" 2>/dev/null || true
    chmod 0644 "$f"
    ALLOWED_TCP_PORTS=""
    NOT_A_REAL_KEY="initial"
    parse_conf_file "$f"
    [ "$ALLOWED_TCP_PORTS" = "22" ]
    # whitelist parser MUST NOT overwrite arbitrary names
    [ "$NOT_A_REAL_KEY" = "initial" ]
    rm -f "$f"
}

@test "parse_conf_file refuses world-writable file" {
    [ "$(id -u)" -eq 0 ] || skip "needs root to chown for stable test"
    f="$(mktemp)"
    echo 'ALLOWED_TCP_PORTS="22"' > "$f"
    chown root:root "$f"
    chmod 0666 "$f"
    run _call_parse_in_subshell "$f"
    [ "$status" -ne 0 ]
    rm -f "$f"
}

# --- firewall_fingerprint stripping invariants -----------------------------
# We can't run nft inside CI, so test the awk/sed pipeline directly with
# synthetic input that mirrors `nft list ruleset` output.

@test "fingerprint strip removes counter packets/bytes" {
    input="$(cat <<'EOF'
table inet filter {
	chain input {
		ip saddr 1.2.3.4 counter packets 100 bytes 5000 drop
	}
}
EOF
)"
    out="$(printf '%s\n' "$input" | sed -E 's/counter packets [0-9]+ bytes [0-9]+//g; s/[[:space:]]+$//')"
    [[ "$out" != *"packets 100"* ]]
    [[ "$out" != *"bytes 5000"* ]]
    [[ "$out" == *"ip saddr 1.2.3.4"* ]]
    [[ "$out" == *"drop"* ]]
}

@test "fingerprint strip skips self-managed table block" {
    skip_table="table inet xdpdrv_guard"
    input="$(cat <<'EOF'
table inet filter {
	chain input {
		tcp dport 80 accept
	}
}
table inet xdpdrv_guard {
	chain xdpdrv_guard_input {
		type filter hook input priority -300; policy accept;
		tcp dport 22 accept
	}
}
EOF
)"
    out="$(printf '%s\n' "$input" | awk -v skip="$skip_table" '
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
    ')"
    [[ "$out" == *"table inet filter"* ]]
    [[ "$out" != *"xdpdrv_guard"* ]]
    [[ "$out" == *"tcp dport 80 accept"* ]]
}
