# Changelog

All notable changes to xdpdrv-guard. Versioning follows semver-ish; pre-1.0
the focus is correctness over API stability.

## [0.1.1] — 2026-04-25

Sprint 1 + Sprint 2 from [AUDIT.md](AUDIT.md). All correctness fixes; no
data-plane format changes; existing `/etc/xdpdrv-guard.conf` is forward
compatible.

### Security
- **AUDIT §1.3** — Replaced unconditional `source $CONF_FILE` with a
  whitelist parser (`parse_conf_file`) that rejects shell metachars and
  refuses to load configs that aren't owned by root or are group/world
  writable.
- **AUDIT §1.6** — Hardened both systemd units: `NoNewPrivileges`,
  `ProtectSystem=strict`, `ProtectHome=read-only`, `ProtectKernel*`,
  `RestrictAddressFamilies` and a tight `CapabilityBoundingSet`. Mutating
  commands now serialize via `flock` on `/var/lock/xdpdrv-guard.lock`.

### Fixed
- **AUDIT §1.1** — `firewall_fingerprint` now strips `counter
  packets/bytes` from nft output and `[N:M]` from iptables-save, and
  excludes the self-managed `inet xdpdrv_guard` table. Previously the
  30-second sync timer reattached XDP almost every cycle in production.
- **AUDIT §1.2** — XDP IPv6 path now walks the extension-header chain
  (HBH/DESTOPT/ROUTING up to depth 6, FRAGMENT → PASS) before reading L4.
  Previously `dport` was read out of arbitrary bytes when extension headers
  were present, allowing policy bypass.
- **AUDIT §1.4** — `fw-sync` no longer writes back into `$CONF_FILE`; it
  computes a runtime view = baseline ∪ live firewall ports each round.
  Removing a port from ufw/iptables/nft is now reflected on the next sync,
  and the baseline file no longer accumulates indefinitely.
- **AUDIT §2.3** — XDP entry now unwraps up to two VLAN tags (802.1Q +
  802.1ad / Q-in-Q). Later-fragment IPv4 packets (offset != 0) PASS instead
  of being misread as L4. Previously VLAN-trunked traffic bypassed the
  guard entirely.
- **AUDIT §3.1** — `BASE_DIR` auto-detects the script's own directory
  (with `XDPDRV_GUARD_BASE_DIR` override). The hardcoded
  `/home/xdpdrv-guard` is now only a fallback.
- **AUDIT §3.3** — `is_tcp_port_effectively_public` parses `nft -j` JSON
  via `jq` and skips the self-managed table; the regex path remains as a
  fallback when `jq` is missing.
- **AUDIT §3.4** — `detect_sshd_ports` matches the `users:(("sshd",pid=…))`
  field exactly instead of `awk /sshd/`, so binaries with `sshd` in their
  name (e.g. `sshd-rec`) no longer poison the auto-allow list.
- **AUDIT §3.6** — `compile_program` caches by `sha256sum` of the source
  instead of `mtime`. A stray `touch` no longer forces a recompile.
- **AUDIT §3.7** — `cmd_install` now compiles before touching firewall
  state, snapshots the previous self-managed nft table, and rolls the
  table back if the XDP attach fails.
- **AUDIT §3.8** — MOTD hook reads from `/run/xdpdrv-guard/motd.txt` with
  a 60s TTL cache; SSH/sftp/scp logins no longer trigger a full
  ss/ip/sysfs walk per session.

### Added
- **AUDIT §3.9** — `xdpdrv-guard.sh --version` / `-V` / `version`.

### Changed
- VERSION: 0.1.0 → 0.1.1.

### Not yet addressed
See [AUDIT.md](AUDIT.md) "未触及" section. Highlights: §1.5 / §2.1
(BPF-map-driven port table to eliminate the reattach window), §2.5
(`--json` output), §2.6 (split into `lib/`), §4 (CI / shellcheck / bats /
prebuilt `.o`), §7 (long-term roadmap).
