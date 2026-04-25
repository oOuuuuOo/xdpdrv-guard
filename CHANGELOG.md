# Changelog

All notable changes to xdpdrv-guard. Versioning follows semver-ish; pre-1.0
the focus is correctness over API stability.

## [Unreleased]

### Added
- `xdpdrv-guard.sh --help-all` (also `help-all`) prints an extended help
  page covering every subcommand flag, configuration key, and file
  path, with cross-references to README / runbook / architecture.
- `status`, `fw-status`, `fw-sync-status` now accept `--json` and emit
  a single-line JSON object (`jq`-validated). KV mode unchanged.
- `status` and `fw-status` are now top-level subcommands in their own
  right (previously only invoked indirectly by `doctor`).
- `cmd_status` reports an `xdp_mode` field (`xdpdrv` / `xdpgeneric` /
  `xdp` / `detached`) in both KV and JSON output.

### Performance
- Replaced 12 `$(echo "$x" | xargs)` whitespace-trim sites with a
  pure-bash `trim_ws` helper. Each call previously forked two
  subprocesses; the new path is in-process. Side benefit: the bash
  trim no longer squashes *internal* whitespace, which makes
  malformed CSV cells (e.g. `"22 80"` with no comma) reject earlier
  in `is_valid_port_token` instead of being silently re-formatted.

### Fixed
- `csv_remove_token_compact`: the previous implementation piped a
  numerically-sorted port list into `comm`, which expects
  lexicographically-sorted input. Real removals at multi-digit
  boundaries (e.g. removing `100` from `99,100,101`) emitted
  `comm: file 1 is not in sorted order` warnings to stderr and could
  return wrong results in unusual port mixes. Now sorts with `LC_ALL=C
  sort -u` before `comm` and re-applies numeric sort before the
  range-compress.

### Tests / CI
- New `.github/workflows/ci.yml` with four jobs: `shellcheck` (severity
  warning), `bash -n` syntax check, `bats` unit tests, and
  `clang -target bpf` data-plane compile.
- New `tests/test_helpers.bats` with 36 cases covering port-token
  validation, CSV add / remove / compress, port_in_csv membership,
  conf-file whitelist parsing (including injection-rejection paths),
  and the firewall-fingerprint counter / self-table stripping.
- Script gained a sentinel guard: when sourced with
  `__XDPDRV_GUARD_TEST_MODE=1`, `main()` does not auto-invoke, so test
  harnesses can call individual helpers in isolation.

### Docs
- New `docs/runbook.md` — incident playbook covering 9 scenarios:
  SYN flood overwhelm, legitimate user dropped, conntrack full,
  fw-sync re-attaching every 30 s, install lock contention, conf load
  rejection, XDP not actually attached, full uninstall, SSH lockout.
- New `docs/architecture.md` — design rationale: two-tier defence
  (XDP + nft), data-plane decision tree, control-plane module map,
  fw-sync two-layer model, concurrency, failure / rollback model,
  security boundary.

## [0.1.1] — 2026-04-25

Sprint 1 + Sprint 2 from [AUDIT.md](AUDIT.md). All correctness fixes; no
data-plane format changes; existing `/etc/xdpdrv-guard.conf` is forward
compatible.

### Security
- Replaced unconditional `source $CONF_FILE` with a
  whitelist parser (`parse_conf_file`) that rejects shell metachars and
  refuses to load configs that aren't owned by root or are group/world
  writable.
- Hardened both systemd units: `NoNewPrivileges`,
  `ProtectSystem=strict`, `ProtectHome=read-only`, `ProtectKernel*`,
  `RestrictAddressFamilies` and a tight `CapabilityBoundingSet`. Mutating
  commands now serialize via `flock` on `/var/lock/xdpdrv-guard.lock`.

### Fixed
- `firewall_fingerprint` now strips `counter
  packets/bytes` from nft output and `[N:M]` from iptables-save, and
  excludes the self-managed `inet xdpdrv_guard` table. Previously the
  30-second sync timer reattached XDP almost every cycle in production.
- XDP IPv6 path now walks the extension-header chain
  (HBH/DESTOPT/ROUTING up to depth 6, FRAGMENT → PASS) before reading L4.
  Previously `dport` was read out of arbitrary bytes when extension headers
  were present, allowing policy bypass.
- `fw-sync` no longer writes back into `$CONF_FILE`; it
  computes a runtime view = baseline ∪ live firewall ports each round.
  Removing a port from ufw/iptables/nft is now reflected on the next sync,
  and the baseline file no longer accumulates indefinitely.
- XDP entry now unwraps up to two VLAN tags (802.1Q +
  802.1ad / Q-in-Q). Later-fragment IPv4 packets (offset != 0) PASS instead
  of being misread as L4. Previously VLAN-trunked traffic bypassed the
  guard entirely.
- `BASE_DIR` auto-detects the script's own directory
  (with `XDPDRV_GUARD_BASE_DIR` override). The hardcoded
  `/home/xdpdrv-guard` is now only a fallback.
- `is_tcp_port_effectively_public` parses `nft -j` JSON
  via `jq` and skips the self-managed table; the regex path remains as a
  fallback when `jq` is missing.
- `detect_sshd_ports` matches the `users:(("sshd",pid=…))`
  field exactly instead of `awk /sshd/`, so binaries with `sshd` in their
  name (e.g. `sshd-rec`) no longer poison the auto-allow list.
- `compile_program` caches by `sha256sum` of the source
  instead of `mtime`. A stray `touch` no longer forces a recompile.
- `cmd_install` now compiles before touching firewall
  state, snapshots the previous self-managed nft table, and rolls the
  table back if the XDP attach fails.
- MOTD hook reads from `/run/xdpdrv-guard/motd.txt` with
  a 60s TTL cache; SSH/sftp/scp logins no longer trigger a full
  ss/ip/sysfs walk per session.

### Added
- `xdpdrv-guard.sh --version` / `-V` / `version`.

### Changed
- VERSION: 0.1.0 → 0.1.1.
