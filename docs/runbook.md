# Runbook — xdpdrv-guard

Incident playbook. Each scenario is **symptom → triage → fix → verify**.
Open this when something is on fire; the README is for reading on the
plane.

> **Before you start any incident step**: capture state for the post-mortem.
> ```bash
> sudo /path/to/xdpdrv-guard.sh --version > /tmp/x.txt
> sudo /path/to/xdpdrv-guard.sh doctor --iface eth0 >> /tmp/x.txt 2>&1
> sudo journalctl -u xdpdrv-guard.service -n 200 --no-pager >> /tmp/x.txt
> sudo journalctl -u xdpdrv-guard-fw-sync.service -n 200 --no-pager >> /tmp/x.txt
> sudo nft -a list table inet xdpdrv_guard >> /tmp/x.txt 2>&1
> sudo ip -d link show dev eth0 >> /tmp/x.txt
> ```

---

## Index

1. [Incoming SYN flood is overwhelming the host](#1-incoming-syn-flood-is-overwhelming-the-host)
2. [Legitimate users are getting dropped](#2-legitimate-users-are-getting-dropped)
3. [conntrack table is full](#3-conntrack-table-is-full)
4. [`fw-sync` is reattaching XDP every 30 s](#4-fw-sync-is-reattaching-xdp-every-30-s)
5. [Install / fw-sync command hangs on the lock](#5-install--fw-sync-command-hangs-on-the-lock)
6. [Config file is rejected at load time](#6-config-file-is-rejected-at-load-time)
7. [`up` succeeded but `xdpdrv` is not actually attached](#7-up-succeeded-but-xdpdrv-is-not-actually-attached)
8. [Need to fully roll back / uninstall](#8-need-to-fully-roll-back--uninstall)
9. [Locked yourself out of SSH](#9-locked-yourself-out-of-ssh)

---

## 1. Incoming SYN flood is overwhelming the host

**Symptoms**
- `value-report` shows `softirq` >> normal, RX PPS spiking.
- `ss -s` shows `synrecv` climbing.
- Latency / throughput on legitimate services dropping.

**Triage**
```bash
sudo ./xdpdrv-guard.sh value-report --iface eth0 --seconds 10
ss -s
nstat | grep -E 'TcpExt(SyncookiesSent|TCPReqQ|ListenDrops)'
```
- If **`xdp_mode=detached` or `xdpgeneric`** in the report, XDP isn't
  doing its job — jump to scenario 7.
- If XDP is attached but the SYNs target a port you actually advertise
  (e.g. 443 SYN flood), XDP can't drop them by default — they're
  technically allowed.

**Fix — the flood targets a *closed* port**
- Already mitigated. Confirm via `nft -a list table inet xdpdrv_guard`
  that the `xdpdrv_guard_syn_drop` counter is rising.

**Fix — the flood targets an *allowed* port**
1. Set a SYN rate limit in `/etc/xdpdrv-guard.conf`:
   ```ini
   ALLOWED_TCP_SYN_RATE_PER_SEC=2000   # tune to your peak normal traffic
   ```
2. Reload:
   ```bash
   sudo ./xdpdrv-guard.sh up --iface eth0
   ```
3. Watch the rate-drop counter:
   ```bash
   watch -n2 'sudo nft -a list table inet xdpdrv_guard | grep syn_rate_drop'
   ```

**Fix — flood is huge enough that even the rate limit doesn't help**
- Local mitigation has hit its ceiling. Engage upstream scrubbing
  (cloud provider DDoS protection / scrubber service). Local XDP cannot
  reduce the bandwidth bill once packets reach the NIC.

**Verify**
- `value-report` PPS to softirq ratio drops back to baseline.
- `nstat` `ListenDrops` stops climbing.

---

## 2. Legitimate users are getting dropped

**Symptoms**
- New TCP connections to a service port suddenly fail.
- `value-report` shows `xdpdrv_guard_syn_drop` counter climbing fast.
- A specific port shows `DROP_RATIO=100%` in `login-report`.

**Triage**
```bash
sudo ./xdpdrv-guard.sh login-report --iface eth0
sudo nft -a list table inet xdpdrv_guard
grep ALLOWED_TCP_PORTS /etc/xdpdrv-guard.conf
```

Check whether the port the user wants is in `ALLOWED_TCP_PORTS`. If
not, that's the cause.

**Fix**
```bash
# Quick: add the port via interactive UI, applies immediately
sudo ./xdpdrv-guard.sh rules-ui --iface eth0
# 2) Append TCP rule  → enter "8080" (or "10000-10100")
# 6) Save & apply

# Or: edit conf and reload
sudo $EDITOR /etc/xdpdrv-guard.conf
sudo ./xdpdrv-guard.sh up --iface eth0
```

**Verify**
- Curl/dig/nc the affected port from outside.
- `nft -a list table inet xdpdrv_guard | grep <port>` shows the port now
  in the allow set.

---

## 3. conntrack table is full

**Symptoms**
- `dmesg` reports `nf_conntrack: table full, dropping packet`.
- New connections fail intermittently.

**Triage**
```bash
sudo cat /proc/sys/net/netfilter/nf_conntrack_count
sudo cat /proc/sys/net/netfilter/nf_conntrack_max
sudo conntrack -S
```

If `count >= max - small_buffer`, it's full.

**Fix — short term**
1. Bump the limit:
   ```bash
   echo 524288 | sudo tee /proc/sys/net/netfilter/nf_conntrack_max
   ```
2. Tune timeouts:
   ```bash
   echo 30 | sudo tee /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_syn_recv
   ```

**Fix — root cause**
- A SYN flood driving conntrack growth: see scenario 1, this is the
  same incident at one layer up.
- A misbehaving application leaking sockets: find it with
  `ss -tn | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head`

**Verify**
- `conntrack -C` (count) returns to baseline within minutes.

---

## 4. `fw-sync` is reattaching XDP every 30 s

**Symptoms**
- `journalctl -u xdpdrv-guard-fw-sync.service` shows
  `Firewall change detected, syncing XDP rules.` on every tick.
- Brief connection blips every 30 s.

**Triage**
```bash
sudo ./xdpdrv-guard.sh --version
```
- If it's `0.1.0` or older: this is the AUDIT §1.1 self-loop bug.
  Upgrade to ≥ 0.1.1.

If already on 0.1.1+:
```bash
sudo ./xdpdrv-guard.sh fw-sync-status
# Manually compute the fingerprint twice and diff.
sudo nft list ruleset > /tmp/r1
sleep 5
sudo nft list ruleset > /tmp/r2
diff /tmp/r1 /tmp/r2
```

If `diff` shows real rule changes every few seconds, something else on
the host is rewriting nft (Docker / podman / fail2ban / ufw script).
Identify with `auditctl -w /usr/sbin/nft -p x` or `inotifywait` on
nft state.

**Fix**
- Stop the offending writer, or if it's intended (fail2ban), suppress
  the sync timer briefly:
  ```bash
  sudo systemctl stop xdpdrv-guard-fw-sync.timer
  # Investigate, then either fix the upstream writer or:
  sudo systemctl start xdpdrv-guard-fw-sync.timer
  ```

**Verify**
- 24 h of journalctl shows zero `syncing XDP rules` lines unless you
  actually changed firewall rules.

---

## 5. Install / fw-sync command hangs on the lock

**Symptoms**
```
[xdpdrv-guard] ERROR: Another xdpdrv-guard operation is in progress (lock=/var/lock/xdpdrv-guard.lock). Aborting.
```

**Triage**
```bash
sudo lsof /var/lock/xdpdrv-guard.lock 2>/dev/null
ps -ef | grep -E 'xdpdrv-guard|systemd-run.*xdpdrv'
sudo systemctl status xdpdrv-guard-fw-sync.timer
sudo systemctl status xdpdrv-guard-fw-sync.service
```

Usually it's the fw-sync timer mid-tick. Wait ~30 s and retry — the
lock has a 30 s acquire timeout.

**Fix — stale lock**
If `lsof` shows nothing holds the lock but the script still complains,
the lock is stale (rare; should not happen with `flock`):
```bash
sudo rm /var/lock/xdpdrv-guard.lock     # ONLY when nothing holds it
```

**Verify**
- Re-run your command; it should proceed.

---

## 6. Config file is rejected at load time

**Symptoms**
```
[xdpdrv-guard] ERROR: Refusing to load /etc/xdpdrv-guard.conf: mode=...
[xdpdrv-guard] ERROR: Refusing to load /etc/xdpdrv-guard.conf: owner uid=...
[xdpdrv-guard] ERROR: Refusing unsafe value at /etc/xdpdrv-guard.conf:N for key X
```

**Fix — permission errors**
```bash
sudo chown root:root /etc/xdpdrv-guard.conf
sudo chmod 0644      /etc/xdpdrv-guard.conf
```

**Fix — unsafe value error**
The line in question contains one of:
`$()`, backticks, `;`, `&&`, `||`, `|`, `<`, `>`. Edit the file and
remove them — these are NEVER needed in any whitelisted KEY's value.
```bash
sudo $EDITOR /etc/xdpdrv-guard.conf
sudo ./xdpdrv-guard.sh up --iface eth0   # confirm load succeeds
```

**Verify**
- `sudo ./xdpdrv-guard.sh status --iface eth0` prints values without error.

---

## 7. `up` succeeded but `xdpdrv` is not actually attached

**Symptoms**
- `up` reported success but `ip -d link show dev eth0` shows no
  `xdpdrv/id:`.

**Triage**
```bash
sudo ip -d link show dev eth0 | sed -n '1,6p'
sudo journalctl -u xdpdrv-guard.service -n 100 --no-pager
sudo dmesg | tail -30
```

Typical causes:
- The systemd unit ran on a different (now-renamed) iface.
- The driver doesn't support `xdpdrv` on this kernel build.
- MTU is set above the driver's XDP-supported limit.
- Some other process owns the XDP slot (Cilium, custom XDP daemon).

**Fix**
```bash
# Verify support directly
sudo ./xdpdrv-guard.sh doctor --iface eth0

# Re-attach explicitly
sudo systemctl restart xdpdrv-guard.service

# If something else is holding XDP
sudo bpftool net show
```

**Verify**
- `ip -d link show dev eth0` shows `xdpdrv/id:<N>`.
- `sudo bpftool prog show id <N>` shows `name xdp_syn_guard`.

---

## 8. Need to fully roll back / uninstall

When you want to make this host look like xdpdrv-guard was never here.

```bash
# 1. Stop & remove all systemd state
sudo ./xdpdrv-guard.sh down --iface eth0
sudo ./xdpdrv-guard.sh motd-remove
sudo ./xdpdrv-guard.sh fw-sync-remove

# 2. Sanity: confirm no unit is left enabled
sudo systemctl list-unit-files | grep xdpdrv-guard

# 3. Strip persistence files
sudo rm -f  /etc/xdpdrv-guard.conf \
            /etc/default/xdpdrv-guard \
            /etc/default/xdpdrv-guard-sync \
            /etc/update-motd.d/99-xdpdrv-guard
sudo rm -rf /var/lib/xdpdrv-guard \
            /run/xdpdrv-guard
sudo rm -f  /var/lock/xdpdrv-guard.lock

# 4. Confirm XDP is gone
sudo ip -d link show dev eth0 | grep -E 'xdp(drv|generic)?/id' || echo "no xdp attached"

# 5. (Optional) Remove the repo itself
sudo rm -rf /opt/xdpdrv-guard   # or wherever you put it
```

---

## 9. Locked yourself out of SSH

You're reading this from a different machine because you can't SSH in.

**Cause**: most likely you set `BLOCK_PUBLIC_TCP_PORTS="22"` on the
public iface, or removed `22` from `ALLOWED_TCP_PORTS` and have
`AUTO_ALLOW_SSH_PORTS=0`.

**Recover via cloud-provider serial console / KVM**
1. Open the cloud provider's serial console / VNC / IPMI for the host.
2. Log in locally as root (or `sudo`).
3. Detach XDP and clear the nft tables to restore vanilla state:
   ```bash
   sudo /path/to/xdpdrv-guard.sh down --iface eth0
   ```
4. Edit `/etc/xdpdrv-guard.conf` to add `22` back into
   `ALLOWED_TCP_PORTS`, or set `AUTO_ALLOW_SSH_PORTS=1`.
5. Bring the guard back up:
   ```bash
   sudo /path/to/xdpdrv-guard.sh up --iface eth0
   ```

**Recover without console access (last resort)**
- If you have a separate management iface (tailscale0, mgmt VLAN), SSH
  in via that and follow the steps above.
- If you have nothing else: most cloud providers support a "rescue
  boot" image that mounts your disk read-write. Mount, edit
  `/etc/xdpdrv-guard.conf`, also delete or disable
  `/etc/systemd/system/xdpdrv-guard.service`, reboot.

**Prevent**
- ALWAYS run `up --no-persist` first to dry-run the change without
  enabling the systemd unit. SSH in fresh from another terminal to
  confirm before re-running with persistence.
- Keep a parallel SSH session open in another window during config
  changes. If your edit is bad, the existing session keeps you in.

---

## Where to file a postmortem

If this runbook didn't cover your scenario, capture the diagnostic
bundle from the top of this file plus:
```bash
sudo bpftool prog show 2>/dev/null | head -40
sudo conntrack -S 2>/dev/null
sudo cat /proc/net/softnet_stat
```
…and add a section to this runbook with the symptom, what you did,
and what worked. Future-you will thank past-you.
