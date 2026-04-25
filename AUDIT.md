# xdpdrv-guard 审计报告 / 优化方向 / 任务排期

审计时间: 2026-04-25
审计范围:
- [xdpdrv-guard.sh](xdpdrv-guard.sh) (2574 行 bash 主脚本)
- [build/xdp_syn_guard.c](build/xdp_syn_guard.c) (eBPF 数据面，125 行；脚本会按配置重新生成)
- [README.md](README.md) / [xdpdrv-guard.conf.example](xdpdrv-guard.conf.example)

---

## 修复进度 (Sprint 1 + Sprint 2 + Sprint 3 — 2026-04-25)

### Sprint 1 (P0 止血)

| # | 条目 | 状态 | 落地位置 |
|---|------|------|----------|
| §1.1 | `firewall_fingerprint` 自激回环 | DONE | `firewall_fingerprint()`：剥离 `counter packets/bytes`、`iptables-save` 计数器；过滤自管 `inet xdpdrv_guard` 整张表 |
| §1.2 | IPv6 扩展头解析 (HBH/DESTOPT/ROUTING/FRAGMENT) | DONE | `generate_c_program()` heredoc + `build/xdp_syn_guard.c`：`#pragma unroll` 6 步链式解析；FRAG → `XDP_PASS`；AH/ESP/未知 → `XDP_PASS` |
| §1.3 | 配置文件 source 提权风险 | DONE | 新增 `parse_conf_file()` 白名单解析器 + `verify_conf_perms()` (owner=root, mode≤0644)；拒绝 `$()`/反引号/分号/管道/重定向；替换原 `source` |
| §1.4 | `fw-sync` 单向累积 → conf 单调膨胀 | DONE | `cmd_fw_sync_now()`：改为"持久化基线 + 运行时合并视图"两层模型；不再写回 `$CONF_FILE`；外部 fw 撤销端口下一轮自然移除 |
| §1.6 | systemd 单元加固 + 入口锁 | DONE | `write_systemd_unit()`/`write_fw_sync_systemd_unit()` 增加 NoNewPrivileges/Protect*/RestrictAddressFamilies/CapabilityBoundingSet；`acquire_install_lock()` (`flock` /var/lock/xdpdrv-guard.lock) 串行化 install/uninstall/fw-install/fw-sync-now |
| §3.1 | `BASE_DIR` 与仓库实际路径不一致 | DONE | `__resolve_base_dir()` 自检测脚本所在目录 (兼容符号链接)；保留 `XDPDRV_GUARD_BASE_DIR` 覆盖；旧路径 `/home/xdpdrv-guard` 仅作 fallback |
| §3.4 | `detect_sshd_ports` 子串误匹配 | DONE | `awk` 改用精确字段 `users:(("sshd",`，避免 `sshd-rec` / 自定义二进制名带 sshd 子串误识别 |

### Sprint 2 (P1/P2 — 数据面与开发者体验)

| # | 条目 | 状态 | 落地位置 |
|---|------|------|----------|
| §2.3 | VLAN (802.1Q/802.1ad/Q-in-Q) 解析 + IPv4 分片处理 | DONE | `xdp_syn_guard()`：进入 `parse_l4_guard` 前 `#pragma unroll` 2 层 VLAN 解封；IPv4 分支增加 `frag_off & 0x1FFF != 0 → XDP_PASS`，避免误丢后片 |
| §3.3 | `is_tcp_port_effectively_public` 改 `nft -j` | DONE | 新增 `_nft_collect_tcp_drop_dports()` (`nft -j` + `jq`)；正向解析 dport 数值/range/set，op 仅取 `==`，自管 table 通过 `--arg self_table` 跳过；保留旧 regex 作为 jq 缺失时的 fallback |
| §3.6 | `compile_program` 缓存判定边界 | DONE | 引入 `${OBJ_FILE}.srchash` (`sha256sum`)；source 内容相同即复用 OBJ，绕开 mtime 误判 |
| §3.7 | `cmd_install` 顺序 + 回滚 | DONE | 改为先 generate→compile，再快照旧 nft table，再换 fw，最后 attach；attach 失败时删除新 table 并 `nft -f -` 写回快照 |
| §3.9 | `--version` / `-V` flag | DONE | dispatcher 增加 `-V|--version|version`；`VERSION` 由 0.1.0 → 0.1.1；usage 同步声明 |

### Sprint 3 (轻量收尾)

| # | 条目 | 状态 | 落地位置 |
|---|------|------|----------|
| §3.8 | MOTD 钩子调用主脚本 → 登录变慢 | DONE | `cmd_motd_install()`：MOTD shell 改为读取 `/run/xdpdrv-guard/motd.txt` (60s TTL)，命中即直接 `cat`；过期或缺失则同步生成并原子写回；安装时预热缓存；`cmd_motd_remove()` 清理缓存文件 |
| §3.9 | changelog 缺失 | DONE | 新增 [CHANGELOG.md](CHANGELOG.md) (0.1.1 完整变更记录，按 security / fixed / added / changed / not-yet 分组) |

### 自验
- `bash -n xdpdrv-guard.sh` 全程通过
- 配置解析单元测试: 正常配置成功；`ALLOWED_TCP_PORTS=$(/bin/id)` 注入被拒
- 指纹稳定性单元测试: 仅计数器/自管表变动 → 哈希不变；外部规则真实变更 → 哈希翻转
- jq drop-dport 抽取单元测试 (合成 nft JSON): 正确产出 `80 80` / `8080 8090` / `443 443` / `10000 10010`，正确跳过自管 table 与 accept 规则
- `--version` / `-V` 输出 `xdpdrv-guard 0.1.1`

### 未触及 (留待后续)
- §1.5 / §2.1 (BPF map 化 + 热更不重挂载) — 架构级，需引入 libbpf + skeleton 工具链
- §2.2 (XDP 限速 LRU)、§2.4 (sync 与 reattach 解耦的 map 化路径)
- §2.5 (`--json` 全局输出 + textfile collector)
- §2.6 (脚本拆分到 `lib/`)
- §3.2 (中英文统一)、§3.5 (`echo|xargs` trim 替换)、§3.10 (`save_state` 消费方)
- §4 (CI / shellcheck / bats / 预编译 .o / 文档)
- §7 (长期路线: daemon 化 / GitOps / 自适应学习 / AF_XDP / 合规)

### 待真机回归 (未在本会话内执行)
- `xdpdrv-guard.sh up --iface eth0` 全链路通
- `systemd-analyze security xdpdrv-guard.service` 评分
- 配置变更 + 30s timer 24h 观察, 无非预期 reattach
- `scapy` 注入带 IPv6 HBH/DESTOPT/ROUTING/FRAG 的 SYN, 断言落点
- `scapy` 注入 802.1Q / Q-in-Q 单/双 tag 的 SYN，断言 inner dport 落点
- `iperf3 + scapy` 注入 IPv4 后片报文，断言 PASS (不应被误丢)
- `nft -j` 注入合成规则集，断言 `surface-audit` 中 `effective_public_count` 与预期一致
- 故障注入: 篡改 SRC_FILE 让 clang 失败 / 让 attach 失败，断言 `cmd_install` 自动回滚 nft 至旧快照

---

## 0. 总体结论

项目定位清晰: 仅 xdpdrv 原生模式 + 解耦 nft 兜底，配套 systemd / MOTD / TG 通知 / 报表，业务命令封装合理 (`up`/`down`/`doctor`)。但当前实现存在 **若干高优先级正确性缺陷** (尤以 fw-sync 自激回环、IPv6 扩展头绕过为甚) 与 **架构性瓶颈** (eBPF 端口表静态嵌入 → 每次配置改动都重编译重挂载，违背"无防护真空期"的设计意图)。

报告分两层:
- **§1-§5 是近期 (5-6 周) 的修补 + 重构计划**, 解决正确性、架构瓶颈、可观测性。
- **§7 是 6 个月 → 2 年+ 的演进路线**, 从单机加固脚本演化为分布式安全组件 / 自适应策略引擎 / 通用 L3-L4 数据面，并讨论选型决策点。

---

## 1. 核心缺陷 (P0 — 必须尽快修复)

### 1.1 `firewall_fingerprint` 自激回环 ★★★ 严重 — [DONE 2026-04-25]
- 位置: [xdpdrv-guard.sh:1192-1210](xdpdrv-guard.sh#L1192-L1210)
- 现象: `cmd_fw_install` 安装的规则带 `counter` 关键字 ([xdpdrv-guard.sh:1047,1052,1054,1056](xdpdrv-guard.sh#L1047-L1056))。`nft list ruleset` 输出会包含 `counter packets N bytes M`，每收到一个匹配包就变化。
- 后果: `cmd_fw_sync_run` 每 30 秒计算指纹 → **几乎必然变化** → 调用 `cmd_fw_sync_now` → 调用 `cmd_install` → `detach_xdp_all_modes` + `attach_xdpdrv` 重挂载。**生产环境上 XDP 每 30 秒断一次**，严重背离设计目标。
- 修复方向:
  - 指纹生成时排除自管 table: `nft list ruleset | grep -v 'table inet xdpdrv_guard'`，并 `sed -E 's/counter packets [0-9]+ bytes [0-9]+//g'` 后再 hash。
  - 或更稳妥: 用 `nft -s list ruleset` (stateless) + 过滤自管 table。
  - 即便修好指纹，也应避免 sync 路径触发 reattach (见 1.5 / 2.1)。

### 1.2 IPv6 扩展头未解析 → SYN 防护可被绕过 — [DONE 2026-04-25]
- 位置: [build/xdp_syn_guard.c:75-103](build/xdp_syn_guard.c#L75-L103)
- 现象: 直接 `(void *)(ip6h + 1)` 当作 `tcphdr/udphdr`。若 `ip6h->nexthdr` 是 HBH(0)/DESTOPT(60)/ROUTING(43)/FRAGMENT(44) 之一，紧接的并非 L4 头，dport 解读为垃圾 → `is_allowed_tcp_port` 几乎一定返回 0 → `XDP_DROP`，**或** 命中允许端口 → 误放行恶意 SYN。攻击者可手工构造带扩展头的 v6 SYN 探测/绕过策略。
- 修复方向:
  - 引入 IPv6 扩展头链解析循环 (有限步数以满足 verifier)，跳过 HBH/RTH/DESTOPT，遇到 FRAG 直接 `XDP_PASS` (片段无完整 L4) 或按策略 `XDP_DROP`。
  - 单元测试: 用 `scapy` 在 netns 内构造各类扩展头组合，断言落点。

### 1.3 配置文件以 root 身份 `source` 执行，无白名单 — [DONE 2026-04-25]
- 位置: [xdpdrv-guard.sh:199-202](xdpdrv-guard.sh#L199-L202)
- 现象: `/etc/xdpdrv-guard.conf` 被直接 `source`，任何变量都会被赋值；若该文件被低权限用户覆盖 (例如配置目录 ACL 错误)，可注入任意 bash 命令以 root 身份执行。
- 修复方向:
  - 用 `grep -E '^[A-Z_]+=' "$CONF_FILE" | grep -v -E '\$\(|`|;|&'` 过滤后再读，或写一个白名单 KEY 解析器 (sed 提取 + bash `printf -v`)。
  - 检查 `$CONF_FILE` owner=root, mode<=0644，否则告警拒载。
  - 同步加固 `$SERVICE_ENV_FILE` / `$FW_SYNC_ENV_FILE`。

### 1.4 `cmd_fw_sync_now` 端口单向累积，无收敛 — [DONE 2026-04-25]
- 位置: [xdpdrv-guard.sh:1241-1270](xdpdrv-guard.sh#L1241-L1270)
- 现象: 只 `csv_add_token_compact` 把外部防火墙 accept 端口并入 `ALLOWED_TCP_PORTS`，**从不删除**。一旦运维通过 ufw/iptables 临时放行某端口再撤销，xdpdrv-guard 仍长期保留。`/etc/xdpdrv-guard.conf` 单调膨胀 → 最终防护意义减弱。
- 修复方向:
  - 引入"运行时合并视图 ≠ 持久化基线"的两层模型: 持久化 `ALLOWED_TCP_PORTS` 由用户管理；外部 fw 端口仅在 runtime 合并到 BPF map，不写回 conf。
  - 或保留写回但加 TTL: 增加 `MANAGED_BY_FW_SYNC` 数组，记录"由同步带入"的端口，外部 fw 撤销后下一轮同步即移除。

### 1.5 配置变更 = clang 重编译 + XDP 重挂载，存在防护真空窗口
- 位置: [xdpdrv-guard.sh:744-882, 931-952, 2200-2241](xdpdrv-guard.sh#L744-L882)
- 现象: 端口表写入 C 源码，每改一次配置都触发 `clang` 编译 + `detach_xdp_all_modes` + `attach_xdpdrv`。从 detach 到 attach 之间网卡上 XDP 完全卸载，攻击窗口虽短但确实存在。叠加 1.1/1.4，可能每 30s 重挂载一次。
- 修复方向 (架构级):
  - eBPF 端口策略改为 **BPF map 驱动** (`BPF_MAP_TYPE_HASH` 或 `BPF_MAP_TYPE_ARRAY[65536]` 位图)。配置变更只更新 map 内容，不重编译、不重挂载。
  - 升级到 `bpf_link_update` 或 `XDP_FLAGS_REPLACE` (内核 ≥5.6) 实现原子替换。
  - 详见 §2.1。

### 1.6 systemd 服务无能力裁剪 / 无锁 — [DONE 2026-04-25]
- 位置: [xdpdrv-guard.sh:1989-2016](xdpdrv-guard.sh#L1989-L2016)
- 现象: 单元只 `Type=oneshot` + `Restart=on-failure`，无 `CapabilityBoundingSet`、`NoNewPrivileges`、`ProtectSystem`、`ProtectKernelTunables`。多入口 (timer/MOTD/手工 up/config-ui) 并发可能撞 `$CONF_FILE` 与 OBJ 编译。
- 修复方向:
  - 为 service 增加: `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectKernelTunables=yes`, `CapabilityBoundingSet=CAP_NET_ADMIN CAP_BPF CAP_SYS_ADMIN`, `RestrictAddressFamilies=AF_NETLINK AF_UNIX AF_INET AF_INET6`。
  - 在脚本入口加 `flock -n /var/lock/xdpdrv-guard.lock`，串行化 install/uninstall/sync。

---

## 2. 架构优化方向 (P1)

### 2.1 eBPF: 静态嵌入 → BPF map + libbpf 骨架
- 当前: 端口范围作为 `static const struct port_range[]` 编译进 .o ([build/xdp_syn_guard.c:14-39](build/xdp_syn_guard.c#L14-L39))。线性 O(N) 遍历，N 增长后 verifier 通过性变差。
- 目标:
  - 用 `BPF_MAP_TYPE_ARRAY` 长度 65536 的 u8 位图作 TCP/UDP allow lookup，O(1)。
  - 配套 `BPF_MAP_TYPE_PERCPU_ARRAY` 计数器 (`tcp_syn_drop`, `udp_drop`, `v6_ext_drop`, `frag_pass`, `vlan_pass`)，`value-report` 直读 map 而非 iface 总丢包。
  - 用 `bpftool gen skeleton` + libbpf，生成 CO-RE 友好的对象。可选: 预编译 `.o` 随发布物分发，省掉每台机器装 clang。
- 收益:
  - 配置热更不重挂载 → 真正的 0 真空窗口。
  - 计数粒度细化，运营可读性提升。
  - 端口规模可扩 (上千范围)。

### 2.2 XDP 层加入限速
- 当前 `ALLOWED_TCP_SYN_RATE_PER_SEC` 仅在 nft 链生效 ([xdpdrv-guard.sh:1051-1053](xdpdrv-guard.sh#L1051-L1053))。允许端口遭遇 SYN 洪泛时仍走完 NIC → kernel softirq → nft，浪费 CPU。
- 目标: 在 XDP 中以 `BPF_MAP_TYPE_LRU_HASH` (key=src_ip+dport) + token bucket 实现单 IP+端口维度限速；超阈值 `XDP_DROP`。
- 注意: 限速逻辑需独立开关，避免误伤 NAT 后大量合法用户。

### 2.3 VLAN / 双栈分片处理 — [DONE 2026-04-25]
- VLAN: 加 `ETH_P_8021Q` 解析分支，避免被 802.1Q 包绕过 (机房带 VLAN trunk 的 VPS 真实存在)。或显式记录"不防护 VLAN" + 计数 `vlan_pass`。
- IPv4 分片: `iph->frag_off & htons(0x3FFF)` 非 0 时按策略 `XDP_PASS` 并计数。

### 2.4 解耦 fw-sync 与 XDP reattach
- 当前 sync 路径直接调用 `cmd_install` ([xdpdrv-guard.sh:1265](xdpdrv-guard.sh#L1265))，连带 generate→compile→reattach。
- 目标: sync 只更新 BPF map (依赖 §2.1) + 重写 nft 兜底 table。XDP 程序保持挂载不变。

### 2.5 输出层增加 JSON 模式
- `status`/`fw-status`/`value-report`/`surface-audit`/`login-report` 全部纯文本，无法对接 Prometheus/告警系统。
- 目标: 加 `--json` 全局选项，所有报表可输出结构化结果。
- 附加: 提供 `node_exporter` textfile collector 输出 (`/var/lib/node_exporter/textfile_collector/xdpdrv_guard.prom`)。

### 2.6 脚本拆分
- 2574 行单文件难以维护。建议按职责拆:
  - `lib/common.sh` (log/err/parse_iface/load_config)
  - `lib/ports.sh` (csv 解析与压缩、端口校验)
  - `lib/bpf.sh` (generate_c_program/compile_program/attach/detach)
  - `lib/fw.sh` (cmd_fw_*)
  - `lib/systemd.sh` (write_systemd_unit / fw_sync 单元)
  - `lib/reports.sh` (value-report / surface-audit / login-report)
  - `lib/ui.sh` (config-ui / rules-ui)
  - `lib/tg.sh`
  - `xdpdrv-guard.sh` 仅做 dispatch。
- 同步引入 `shellcheck` + `bats` 测试 (csv 解析、端口压缩、范围合并最容易测)。

---

## 3. 质量与可观测性 (P2)

### 3.1 BASE_DIR 与仓库实际路径不一致 — [DONE 2026-04-25]
- 脚本里 `BASE_DIR="/home/xdpdrv-guard"` ([xdpdrv-guard.sh:7](xdpdrv-guard.sh#L7))，但仓库实际位于 `/home/project/xdpdrv-guard`。README 也按 `/home/xdpdrv-guard/...` 写，造成读者困惑。
- 修复: 用 `BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"` 自检测；README 改为通用安装步骤。

### 3.2 中英文混杂
- README 中文，`usage()` 英文，`surface-audit` 输出中文夹英文 ([xdpdrv-guard.sh:1944-1963](xdpdrv-guard.sh#L1944-L1963))。
- 修复: 统一一种语言；或加 `LANG=zh_CN.UTF-8` / `en_US.UTF-8` 切换。

### 3.3 `is_tcp_port_effectively_public` 过于脆弱 — [DONE 2026-04-25]
- 位置: [xdpdrv-guard.sh:996-1029](xdpdrv-guard.sh#L996-L1029)
- 现象: 用 `grep -Eq` 在 `nft list ruleset` 字符串中找模式，遇到多行规则、`tcp dport != { 22 }` 反向写法、`dport 22-25` 范围语法都会误判。
- 修复: 用 `nft -j list ruleset` (JSON) + `jq` 正向解析；或在 `xdpdrv_guard` 自管 table 内维护策略，避免推断他人规则。

### 3.4 `detect_sshd_ports` 误匹配风险 — [DONE 2026-04-25]
- 位置: [xdpdrv-guard.sh:226-230](xdpdrv-guard.sh#L226-L230)
- 用 `awk '/sshd/'` 子串匹配；`/.../sshd-rec/...` 或自定义二进制名带 sshd 子串都会被误识别。
- 修复: 解析 `users:(("sshd",pid=...))` 段，正则 `users:\(\("sshd"`。

### 3.5 大量 `$(echo "$x" | xargs)` trim
- 多处 ([xdpdrv-guard.sh:238, 257, 375, 381, 442, 458, 510, 535, ...]) 用 `echo|xargs` 去空白。每次 fork 两个进程。
- 修复: bash 内置 `[[ "$x" =~ ^[[:space:]]*(.*[^[:space:]])[[:space:]]*$ ]] && x="${BASH_REMATCH[1]}"` 或简单 `x="${x## }"; x="${x%% }"`。

### 3.6 `compile_program` 缓存判定边界 — [DONE 2026-04-25]
- 位置: [xdpdrv-guard.sh:884-918](xdpdrv-guard.sh#L884-L918)
- 仅对 mtime: 若用户手动 `touch` SRC，OBJ 不会重建。轻量风险但可改用 `sha256sum` 对比。

### 3.7 `cmd_install` 顺序: fw → compile → attach — [DONE 2026-04-25]
- 位置: [xdpdrv-guard.sh:2200-2241](xdpdrv-guard.sh#L2200-L2241)
- 当前先 `cmd_fw_install` 再 `compile_program` + `attach`。若 compile/attach 失败，nft 已被替换，回退困难。
- 修复: compile_program 成功后再切 fw；提供 `rollback` 路径恢复旧 nft snapshot。

### 3.8 MOTD 钩子调用主脚本 — [DONE 2026-04-25]
- 位置: [xdpdrv-guard.sh:1602-1611](xdpdrv-guard.sh#L1602-L1611)
- 每次 SSH 登录跑完整 bash + ss + sysfs 读，非交互场景 (sftp/scp) 也会触发，登录变慢。
- 修复: `login-report` 把结果写入 `/run/xdpdrv-guard/motd.txt` (定时刷新或挂 systemd timer)，MOTD 脚本只 `cat` 缓存。

### 3.9 缺 `--version` / `--help-all` / 无 changelog — [PARTIAL 2026-04-25] (`--version`、`CHANGELOG.md` 已加；`--help-all` 未加)
- 加 `xdpdrv-guard.sh --version`；维护 `CHANGELOG.md`。

### 3.10 `save_state` 写但无人读
- 位置: [xdpdrv-guard.sh:920-929](xdpdrv-guard.sh#L920-L929)
- 当前 `runtime.env` 仅给运维肉眼看；可考虑给 `cmd_status --json` 提供数据源，或干脆删除以减熵。

---

## 4. 测试与发布 (P3)

### 4.1 引入 CI
- GitHub Actions:
  - `shellcheck -x xdpdrv-guard.sh`
  - `bats tests/` (csv 解析、端口压缩、范围合并、BLOCK_PUBLIC_TCP_PORTS 校验)
  - `clang -target bpf` 编译验证 (验证生成的 C 在多个内核 header 下可编译)
  - 集成测试 (netns + veth + scapy 注入各类报文)

### 4.2 预编译 `.o` 物料
- 配套发布 amd64/arm64/armv7 预编译对象，让没有 clang 的最小化镜像也可部署。

### 4.3 文档补强
- 增加 docs/runbook.md (出现 SYN 洪泛/合法用户被误伤/conntrack 满 等场景的处置)。
- 增加 docs/architecture.md (XDP 与 nft 兜底的边界、为何不回落 generic、fw-sync 的语义)。

---

## 5. 任务排期 (建议)

按 1 人 0.5 ~ 1 FTE 推进，预计 5 ~ 6 周。括号为预估工时 (人日)。

### Sprint 1 (W1, 5d) — P0 修复 / 止血
| # | 任务 | 工时 | 验收 |
|---|------|------|------|
| 1.1 | 修复 `firewall_fingerprint` 自激回环 | 0.5 | 30s timer 连续 24h 无非预期 reattach |
| 1.2 | IPv6 扩展头解析 (HBH/RTH/DESTOPT/FRAG) | 1.5 | scapy 6 类报文用例全通过 |
| 1.3 | 配置文件白名单解析 + 权限校验 | 1.0 | 注入测试拒载并告警 |
| 1.6 | systemd 单元能力裁剪 + flock | 0.5 | `systemd-analyze security` 评分提升 |
| 1.4 | fw-sync 单向累积修复 (双层模型) | 1.0 | 模拟外部 fw 增删，conf 不再单调膨胀 |
| — | 回归: doctor / value-report / up-down 全链路 | 0.5 | doctor PASS |

里程碑 M1: 现网可安心长期运行。

### Sprint 2 (W2-W3, 8d) — P1 架构升级 (核心)
| # | 任务 | 工时 | 验收 |
|---|------|------|------|
| 2.1a | eBPF 改 BPF_MAP 位图 + PERCPU 计数器 | 2.5 | 单测 + 真机 PPS 对比 ≥ 当前 |
| 2.1b | 引入 libbpf + bpftool skeleton；预编译 .o | 1.5 | 三架构 CI 出包 |
| 2.1c | 配置变更走 map update，不再 reattach | 1.0 | 改端口在线无丢包 (iperf+scapy 测) |
| 2.4 | fw-sync 与 XDP 解耦 | 0.5 | sync 不再触发 reattach |
| 2.3 | VLAN / IPv4 分片处理 + 计数 | 1.0 | scapy 用例 |
| — | 升级 README + 迁移指引 | 1.0 | 文档评审 |

里程碑 M2: 0 真空窗口的热更新与可观测计数。

### Sprint 3 (W4, 5d) — P1 输出层 + P2 质量
| # | 任务 | 工时 | 验收 |
|---|------|------|------|
| 2.5 | `--json` 全局输出 + textfile collector | 1.5 | Grafana 一张 dashboard |
| 2.2 | XDP 层 SYN 限速 (LRU hash + token) | 1.5 | 限速触发计数可见 |
| 3.3 | `is_tcp_port_effectively_public` 改 `nft -j` | 0.5 | 各种规则形态用例 |
| 3.4 | sshd 端口探测精确化 | 0.25 | 用例覆盖 |
| 3.5 | 去掉 `echo \| xargs` 模式 | 0.5 | shellcheck 干净 |
| 3.7 | install 顺序与回滚 | 0.5 | 故障注入测试 |
| 3.8 | MOTD 缓存化 | 0.25 | 登录耗时下降 |

里程碑 M3: 可对接监控与告警体系。

### Sprint 4 (W5, 5d) — P2 重构 + P3 测试
| # | 任务 | 工时 | 验收 |
|---|------|------|------|
| 2.6 | 拆分 lib/ 模块 | 2.0 | 行数下降 ≥40%，单文件 ≤500 行 |
| 4.1 | CI: shellcheck + bats + bpf 编译 | 1.0 | 主分支绿 |
| 4.1 | netns 集成测试用例 | 1.5 | 8 类典型报文用例 |
| 3.1 | BASE_DIR 自检测；README 改通用 | 0.25 | 任意目录可运行 |
| 3.2 | 语言统一 (建议中文为主, --lang en 切换) | 0.25 | 输出一致 |

里程碑 M4: 可作为公共项目稳定发布 v0.2.0。

### Sprint 5 (W6, 选做, 5d) — 长期增强
- conntrack 友好的 SYN 白名单 (允许端口下、已建立连接的 src 不计入限速)。
- 可选 GeoIP / ASN 黑白名单 (BPF map 加载 LPM_TRIE)。
- 一键迁移脚本: 旧版 → 新版 (保留 ALLOWED_TCP_PORTS、清理多余累积端口)。

---

## 6. 速查: 改动文件清单 (按优先级)

P0 必改:
- [xdpdrv-guard.sh:1192-1210](xdpdrv-guard.sh#L1192-L1210) — firewall_fingerprint
- [xdpdrv-guard.sh:1241-1294](xdpdrv-guard.sh#L1241-L1294) — fw-sync 写回逻辑
- [xdpdrv-guard.sh:199-202](xdpdrv-guard.sh#L199-L202) — load_config 安全
- [xdpdrv-guard.sh:1989-2016](xdpdrv-guard.sh#L1989-L2016) — systemd 单元加固
- [build/xdp_syn_guard.c:75-103](build/xdp_syn_guard.c#L75-L103) — IPv6 扩展头

P1 重构:
- [build/xdp_syn_guard.c](build/xdp_syn_guard.c) 全文 → libbpf skeleton + map
- [xdpdrv-guard.sh:744-918](xdpdrv-guard.sh#L744-L918) — generate_c_program / compile / attach
- [xdpdrv-guard.sh:1031-1088](xdpdrv-guard.sh#L1031-L1088) — fw-install 拆耦

P2 质量:
- [xdpdrv-guard.sh:996-1029](xdpdrv-guard.sh#L996-L1029) — is_tcp_port_effectively_public
- [xdpdrv-guard.sh:226-230](xdpdrv-guard.sh#L226-L230) — detect_sshd_ports
- [xdpdrv-guard.sh:1602-1611](xdpdrv-guard.sh#L1602-L1611) — MOTD 钩子
- 全文 trim 模式替换

---

## 7. 更长远的演进路线 (6 个月 → 2 年+)

§5 是按"修补 + 重构"维度的 5-6 周冲刺；下面补充 **战略级演进**，按时间地平线分层。每条都标注前置依赖，便于做选型与节奏控制。

### 7.1 H1 (3-6 个月): 从"加固脚本"到"可运维的安全组件"

#### 7.1.1 控制面与数据面分离
- **现状**: bash 脚本同时承担 CLI、配置管理、规则下发、报表。耦合重，故障域大。
- **演进**: 控制面用 Go (推荐) 或 Rust 重写为常驻进程 `xdpdrv-guardd`；bash 只作 bootstrap 与运维入口。
  - 进程内嵌 libbpf-go / aya-rs，直接管理 BPF map。
  - 暴露本地 unix socket gRPC/HTTP API，供 CLI / WebUI / 监控调用。
  - bash 时代的 `up/down/doctor` 改为 daemon 的 RPC 客户端，保持兼容。
- **附带收益**: 单元测试覆盖率上得来；libbpf skeleton 升级路径顺;从此 systemd 单元变成 `Type=notify`，可读取 watchdog/ready 状态。
- **前置**: §2.1 (BPF map 化) 必须先完成。

#### 7.1.2 配置版本化 + 灰度回滚
- **现状**: `/etc/xdpdrv-guard.conf` 单文件，覆盖即生效，错配影响面大。
- **演进**:
  - 配置目录化: `/etc/xdpdrv-guard/conf.d/*.yaml`，支持模块化 (ports.yaml / fw.yaml / telemetry.yaml)。
  - 写入采用"提交日志"模式 (git/sqlite)，每次 apply 生成 revision id，附带 diff。
  - `xdpdrv-guard rollback <rev>` 一键回到任意版本；`status` 显示当前 rev + 与上一 rev 的差异。
  - 灰度模式 (canary): 新策略先以 `XDP_PASS + count` 跑 N 分钟，统计差异后再切真 drop。
- **前置**: §7.1.1 控制面进程化。

#### 7.1.3 完整可观测性栈
- **指标 (Metrics)**: 直接暴露 `:9XXX/metrics` (Prometheus)，丢包按 (drop_reason × proto × stack × dport) 聚合。
- **追踪 (Tracing)**: 关键路径 (apply / sync / reattach) 接入 OpenTelemetry，追到调用链。
- **日志 (Logs)**: 结构化 JSON，字段稳定 (`event=apply revision=42 outcome=ok duration_ms=87`)，便于 ELK/Loki。
- **事件流**: BPF perf event / ring buffer 推送 drop 样本 (脱敏 src/dst) 到用户态，提供"近 N 秒丢包采样"接口。
- **价值**: surface-audit / value-report 不再是临时拼出来的脚本，而是 daemon 内置的视图。

### 7.2 H2 (6-12 个月): 从"单机加固"到"集群协同"

#### 7.2.1 中心化策略平面 (可选模块)
- **场景**: 一个团队 10~500 台 VPS，希望集中管理 ALLOWED_TCP_PORTS 与封禁名单。
- **演进**:
  - 引入 `xdpdrv-guard-controller`: 单点 (或 HA) 服务，agent 主动 pull (推荐) 或 push 模式。
  - 通信走 mTLS + 短期 token (SPIFFE/SVID 兼容更佳)。
  - 策略以 GitOps 形式管理: 仓库即真相，CI 校验后下发；配置 PR 评审天然形成审计轨迹。
  - Controller 聚合所有 agent 的 surface-audit / value-report，提供集群级仪表盘。
- **可选形态**: Kubernetes Operator + CRD `XDPGuardPolicy`，DaemonSet 部署 agent。
- **风险**: 中心化引入新故障域；必须保证 agent 在断连下用最后已知好策略 (LKG) 继续运行。

#### 7.2.2 自适应/在线学习的策略引擎
- **现状**: 阈值靠人填 (SYN rate)。
- **演进**:
  - daemon 内维护流量基线 (滑动 EWMA / sketch 结构如 CountMinSketch)；
  - 异常分检测: 单 src IP 突破 z-score 阈值 → 自动加入临时封禁 BPF map (TTL N 秒)。
  - 策略 A/B 切换: 同时挂两个 XDP program (主+影)，影模式只计数不丢包；A/B 对比误伤率，达标再切主。
  - 与 SRE 工作流融合: 自动产生"建议 PR" (新封禁列表) 推到 Git 配置仓，由人合并。
- **前置**: §7.1.3 (perf event 流) + §7.2.1 (Git 配置)。

#### 7.2.3 威胁情报双向流
- **入站**: 接 FireHOL / Spamhaus / AbuseIPDB / 运营商封禁列表 → 转换为 BPF LPM_TRIE 直接 drop。
- **出站**: agent 聚合丢包 top src IP，按 ASN 归并，生成 abuse 邮件模板 / RIR 报告 / 社区共享 (Threat Sharing 协议如 STIX)。
- **价值**: 从被动防护变成攻击成本提升 — 攻击者真实 ASN 被 ISP 关注。

### 7.3 H3 (12-24 个月): 数据面成为通用策略引擎

#### 7.3.1 多协议、多场景覆盖
- **DDoS 反射放大** (DNS/NTP/SSDP/Memcached/CLDAP): 在 XDP 层识别响应特征 → 直接 drop。
- **QUIC/HTTP3**: UDP 白名单不能简单等于"放行 443/UDP"，需理解 QUIC 初始包结构、对版本协商攻击丢弃。
- **GeoIP / ASN drop**: LPM_TRIE 加载 MaxMind / IPinfo 数据，按国家/ASN 维度黑白名单，热更新。
- **TCP 指纹 (类 ja3)**: 在 SYN 阶段提取 TCP options + window 形成指纹，针对扫描器/恶意工具 drop。
- **行为限速分层**: per-src-IP × per-dport × per-protocol，token bucket 多维 LRU。

#### 7.3.2 性能极限优化
- **AF_XDP zero-copy**: 把无法用 BPF 表达的复杂逻辑 (例如全报文深度解析) 卸载到用户态 worker，在 NUMA 本地处理。
- **多队列亲和性**: 自动调谐 RSS hash / RPS / XPS / IRQ affinity，确保 XDP 在每个 CPU 线性扩展。
- **大流量基准**: 在 10G/25G/100G NIC 上发布公开基准 (PPS / 延迟 / CPU%)，作为选型背书。
- **PERCPU 优化**: 计数器避开伪共享，map 设计避免跨 NUMA。

#### 7.3.3 可热升级与高可用
- **双 link 滚动替换**: 用 `bpf_link_update` 把新 program 原子替换旧 program，0 丢包升级 daemon 自身。
- **状态保留升级**: BPF map (尤其 LRU 限速、临时封禁) 在 daemon 重启时通过 pinned map 保留，不丢历史。
- **故障自愈**: verifier 拒绝新版本时自动回退到上一已知好的 .o；连续失败超阈值进入"安全模式" (仅装兜底 nft，不挂 XDP)。
- **HA 协同**: 双机热备场景下，封禁列表通过 raft/gossip 同步 (与 §7.2.1 集中管理形成两种部署形态)。

### 7.4 长期 (2 年+): 生态、合规、产品化

#### 7.4.1 生态融合
- 与 CrowdSec / fail2ban / Suricata / Falco 双向集成: 入侵检测告警 → 自动加入 XDP 封禁；XDP 丢包样本 → 反馈给 IDS 训练。
- 与 Cilium / Calico 共存矩阵: 明确 hook priority、tcx 接管时代的兼容路径 (Linux 6.6+ tcx)。
- 路由器形态: 适配 OpenWRT / VyOS，把 XDP 防护带到 SOHO 边界 (取决于 NIC 驱动支持度)。
- 与云厂商 LB / WAF 编排: 上游清洗 + 本机收敛的两段式防护参考架构。

#### 7.4.2 合规与审计
- 操作审计日志 (谁在何时做了什么 apply/rollback)，签名后落盘。
- 控制项映射: PCI-DSS Req 1 (firewall) / 等保 2.0 网络安全要求 / ISO 27001 A.13。
- 自动化合规报告: 季度产出 PDF (暴露面变化、攻击峰值、回滚记录)。
- 不变更生产规则的 dry-run 审计模式: `--audit-only`，把所有 drop 改为 count，对外披露策略而不影响业务。

#### 7.4.3 产品化路径 (若团队希望)
- WebUI: 实时流量热力 + 一键封禁 + 策略 diff review。
- 移动端推送: 异常峰值即时通知 (Telegram 已支持，可加企业微信/Slack/Lark)。
- SaaS 形态: 中心控制面托管化，agent 开源 + 控制面商业版 (经典开放核模型)。
- 教学/演示资产: examples/ 内含 5~10 类攻击 PoC (Vagrant/docker-compose 一键复现)，附原理图，便于布道与团队培训。

#### 7.4.4 跨平台扩展
- RHEL/Rocky/Alma/Arch/SUSE 矩阵化测试。
- 内核 ≤5.10 fallback: TC eBPF 替代 XDP (功能受限，但覆盖老内核)。
- 混合云场景: 同一策略文件可对应 Linux XDP / 云厂商安全组 / WAF 规则的多目标转译。

### 7.5 演进路线图 (一图速览)

```
H1 (3-6m)  ┃ daemon 化   配置版本化     可观测性栈
            ┃     │             │              │
            ┃     ▼             ▼              ▼
H2 (6-12m) ┃ 集群控制面   自适应学习    威胁情报双向流
            ┃     │             │              │
            ┃     ▼             ▼              ▼
H3 (12-24m)┃ 多协议引擎   AF_XDP 性能    热升级/HA
            ┃     │             │              │
            ┃     ▼             ▼              ▼
长期       ┃ 生态融合    合规审计       产品化与跨平台
```

### 7.6 选型决策点 (需团队提前对齐)

下列决策影响 H1 之后的所有路径，建议在 Sprint 2 完成前讨论清楚:

| 决策点 | 选项 A | 选项 B | 影响 |
|--------|--------|--------|------|
| 控制面语言 | Go (libbpf-go, 生态成熟) | Rust (aya, 安全/性能更强) | 决定 H1.1 起所有后续工程 |
| 部署形态 | 单机自治为主 (LKG) | 中心化优先 (controller-first) | 决定 H2.1 是否成立 |
| 策略来源 | conf 文件 → API | GitOps → API | 决定审计/回滚机制 |
| 与 K8s 关系 | 仅做主机 agent | 提供 Operator + CRD | 决定生态扩展边界 |
| 商业化意图 | 纯开源 | 开放核 + 控制面商业版 | 决定文档/许可证策略 |
| 内核基线 | 仅支持 ≥5.10 | 维护 4.x TC fallback | 决定数据面架构成本 |

---

## 8. 风险提示

- §2.1 重构涉及 libbpf 依赖，在最小化镜像 (无 `libbpf-dev`) 上需评估。建议保留旧路径作 fallback (`--legacy-static`)，预编译 `.o` 优先。
- §1.2 的 IPv6 扩展头解析在老内核 (≤4.x) 的 verifier 上可能受限制，需先在最低支持内核 (Debian 11 ~ 5.10) 上验证。
- §1.4 改为不写回 conf 后，老用户的 conf 已被污染，需配套 `xdpdrv-guard.sh prune-conf` 命令辅助清理。
- 任何涉及 attach/detach 的改动建议先在远程 KVM/IPMI 可达环境上线，避免 SSH 自断。
