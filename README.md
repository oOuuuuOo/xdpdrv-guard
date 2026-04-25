# xdpdrv-guard

> 一句话：把"打向你机器关闭端口的 TCP SYN 扫描和洪泛"在网卡驱动那一层就丢掉，
> 让 CPU 和防火墙不用浪费力气去处理。

版本 **0.1.1** · [CHANGELOG.md](CHANGELOG.md) · [AUDIT.md](AUDIT.md) (待办与架构方向)

---

## 这是什么 / 适不适合你

**这是什么**：一个 Bash 脚本，干两件事——
1. 在网卡驱动层挂一个小程序 (XDP)，把不该来的 TCP SYN 直接丢，根本不进内核栈。
2. 同时摆一份 nftables 兜底规则做"早期 + 备份"。

**为什么有用**：扫描器和小型 SYN 洪泛打过来的时候，普通防火墙也能丢，但每个包都要走
完整内核协议栈的一截才被丢；XDP 在网卡驱动那一层就丢，CPU 占用差好几倍。
对小机器 (1c2g 那种 VPS) 影响很明显。

**适合你**：
- 在 Debian / Ubuntu 上的 VPS / 独服 / 小型节点
- 网卡支持 `xdpdrv` 原生模式 (绝大多数云厂商提供的 virtio_net / mlx5 / ixgbe / e1000e 都行)
- 你能用 root 跑命令
- 你的服务端口数量不多 (几个到几十个)

**不适合你**：
- Kubernetes / Cilium 已经接管 XDP 的环境 → 会冲突
- 高速大型边界网关 (10G+ 大流量、几千端口) → 当前是 O(N) 端口表，不为这种量级设计
- 不是 Linux / 内核太老 (≤4.x 的特殊定制内核) → XDP 不一定可用

如果你看到这里还不确定要不要装，运一次 `doctor` 看看就知道:
```bash
sudo ./xdpdrv-guard.sh up --iface eth0 --no-persist --skip-self-test
sudo ./xdpdrv-guard.sh doctor --iface eth0
sudo ./xdpdrv-guard.sh down --iface eth0
```
不会写任何持久化，跑完原状还回去。

---

## 5 分钟跑起来

```bash
# 1) 把仓库放任意路径下，进去
cd /opt/xdpdrv-guard      # 或者 /home/xdpdrv-guard、~/xdpdrv-guard，都行

# 2) 上线 (会装依赖、生成模板配置、自检、挂 XDP、写 systemd)
sudo ./xdpdrv-guard.sh up --iface eth0 --with-deps --with-config

# 3) 检查
sudo ./xdpdrv-guard.sh doctor --iface eth0
```

`up` 跑完应该能看到大概这样的输出:

```
[xdpdrv-guard] [up] iface=eth0 with_deps=1 with_config=1 persist=1 self_test=1
[xdpdrv-guard] Installed in xdpdrv mode on eth0
3: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdpgeneric/id:0 xdpdrv/id:42 ...
```

关键字是 `xdpdrv/id:` 后面跟数字 — 表示 XDP 程序挂上了。如果是 `xdpgeneric/id:`
那就是降级模式，本项目不允许，会直接报错退出。

要把它彻底删掉:
```bash
sudo ./xdpdrv-guard.sh down --iface eth0
```

---

## 术语小词典 (按需查)

| 词 | 一句话解释 |
|---|---|
| **XDP** | eXpress Data Path。Linux 内核里给网卡驱动留的一个 hook，在内核协议栈之前就能跑你的小程序丢/改/转发包。 |
| **xdpdrv** | XDP 的 native 模式，由网卡驱动直接调用你的程序，CPU 占用最低。本项目只用这个。 |
| **xdpgeneric** | XDP 的兼容模式，跑在协议栈早期但已经过 sk_buff 分配。本项目**不用**它，太慢。 |
| **eBPF** | 内核里跑沙箱字节码的虚拟机。XDP 程序就是 eBPF 程序。 |
| **verifier** | eBPF 加载时的安全检查。所有循环必须有界、所有指针访问必须做边界检查。 |
| **nftables / nft** | Linux 现代防火墙 (iptables 的接班人)。本项目用它做 XDP 之外的兜底。 |
| **conntrack** | 内核维护的连接状态表。SYN 洪泛打满它会让正常连接连不上，所以要在更早层级丢掉异常 SYN。 |
| **VLAN** | 二层标签。带标签的包外面多 4 字节，旧版本不解开会让端口判断失效。 |
| **MOTD** | Message Of The Day，SSH 登录时显示的欢迎页。 |
| **systemd timer** | 类似 cron，但和 systemd 服务集成更好。本项目用它每 30 秒检查防火墙变更。 |

---

## 准备工作

### 系统 / 工具

| 工具 | 必装？ | 装法 (Debian/Ubuntu) | 不装会怎样 |
|---|---|---|---|
| `clang` | 是 | `apt install clang llvm` | 编不出 BPF 程序，启动失败 |
| `nft` | 是 | `apt install nftables` | 兜底规则装不上 |
| `iproute2` (`ip`/`ss`) | 是 | 一般已装 | 挂载和监听端口探测都靠它 |
| `coreutils` (`sha256sum`/`stat`) | 是 | 一般已装 | OBJ 缓存、权限校验失效 |
| `jq` | 推荐 | `apt install jq` | `surface-audit` 退化为 regex 推断，结果略糙 |
| `flock` (`util-linux`) | 推荐 | 一般已装 | 入口锁退化为 best-effort，并发可能撞 |
| `systemd` | 推荐 | 一般已装 | 没有持久化和 timer，只能手工跑 |

`up --with-deps` 帮你 `apt install` 关键的几个。

### 准备工作自检

```bash
# 网卡支持 xdpdrv 吗？
sudo ./xdpdrv-guard.sh doctor --iface eth0
```

`doctor` 报告里会显示一行 `result=self-test:PASS`/`FAIL`。FAIL 一般是网卡驱动不支持
`xdpdrv`，把 `--iface` 换成确实跑流量的那张。

---

## 配置文件 `/etc/xdpdrv-guard.conf`

`up --with-config` 会从模板复制一份。文件格式是 `KEY=VALUE`，注释以 `#` 开头。
v0.1.1 起脚本**不会 source 这个文件**——它用白名单解析器读，所以下面这些是**不行的**:

```ini
ALLOWED_TCP_PORTS=$(cat /etc/something)    # 拒绝：含 $()
PORTS_FROM_FILE=`cat /tmp/x`               # 拒绝：含反引号
DOUBLE_THING=22 ; rm -rf /                 # 拒绝：含 ;
```

文件本身也必须是 `root:root` 拥有，且 mode 不能 group/world 可写 (`chmod 0644` 或 `0600`)。
否则脚本启动时直接退出，不冒险加载。

### 全部可识别的 KEY

| KEY | 类型 / 例子 | 默认 | 说明 |
|---|---|---|---|
| `IFACE` | `eth0` | (空，自动检测) | 固定网卡名。空时按默认路由的出口推断。 |
| `ALLOWED_TCP_PORTS` | `22,80-81,443,10000-10100` | (空) | XDP 与 nft 兜底放行的 TCP 目标端口。**空 = 丢所有 TCP SYN**，慎用。 |
| `ALLOWED_UDP_PORTS` | `53,3478,51820` 或 `10000-10100` | (空) | 非空时启用 UDP 白名单；空时 XDP 不丢 UDP，保持原样。 |
| `AUTO_ALLOW_SSH_PORTS` | `0` 或 `1` | `0` | 1 = 运行时把当前 sshd 监听的端口自动并入 `ALLOWED_TCP_PORTS`。0 适合 tailscale-only SSH。 |
| `ALLOWED_TCP_SYN_RATE_PER_SEC` | `0` 或 `2000` | `0` | 0 关闭。>0 时在 nft 兜底链对放行端口加 rate limit (超阈值 drop)，可以挡掉打允许端口的小型 SYN flood。 |
| `BLOCK_PUBLIC_TCP_PORTS` | `22` | (空) | 对公网 iface 的指定 TCP 端口做**全量** drop (不只是 SYN)。`tailscale-only SSH` 场景的标准做法是把 22 放这里。 |
| `TELEGRAM_ENABLED` | `0` 或 `1` | `0` | 启用 TG 通知。 |
| `TELEGRAM_BOT_TOKEN` | `123:ABC...` | (空) | @BotFather 颁发的 token。 |
| `TELEGRAM_CHAT_ID` | `-1001234567890` | (空) | 用户 / 群 / 频道 id。 |

### 几种典型配置

**最保守 (新手默认)**:
```ini
ALLOWED_TCP_PORTS="22,80,443"
ALLOWED_UDP_PORTS=""
AUTO_ALLOW_SSH_PORTS=1
ALLOWED_TCP_SYN_RATE_PER_SEC=0
BLOCK_PUBLIC_TCP_PORTS=""
```

**Tailscale-only SSH (公网完全不开 22)**:
```ini
ALLOWED_TCP_PORTS="80,443"     # 不放 22
AUTO_ALLOW_SSH_PORTS=0
BLOCK_PUBLIC_TCP_PORTS="22"    # 对公网 22 全量丢，确保即便 nft 没拦也丢
```

**有较高 SYN 风险的 web 服务**:
```ini
ALLOWED_TCP_PORTS="22,80,443"
AUTO_ALLOW_SSH_PORTS=1
ALLOWED_TCP_SYN_RATE_PER_SEC=2000   # 单端口每秒最多 2000 SYN
```

改完文件之后:
```bash
sudo ./xdpdrv-guard.sh up --iface eth0       # 重新生效
```

---

## 子命令完整清单

每行有"做什么"和"什么时候用"。

| 命令 | 做什么 | 什么时候用 |
|---|---|---|
| `up [--iface I] [--with-deps] [--with-config] [--no-persist] [--skip-self-test]` | 业务上线全流程 | 第一次部署，或改完配置要生效时 |
| `down [--iface I] [--keep-service] [--keep-fw]` | 业务下线全流程 | 机器要交还 / 排查时彻底卸载 |
| `doctor [--iface I] [--quick]` | 综合体检 (status + fw-status + health-check + self-test) | 排错第一步永远是它 |
| `config-ui [--iface I]` | 交互向导：自动从 `ss` 抓监听端口，让你勾选并入配置 | 不想手写 conf，让脚本帮你配 |
| `rules-ui [--iface I]` | 终端菜单：看 / 加 / 删端口或范围，立即生效 | 临时调端口规则 |
| `value-report [--iface I] [--seconds N] [--tg]` | N 秒内的减负数据 (PPS、softirq、conntrack…) | 想给老板/同事/自己看效果 |
| `surface-audit [--iface I] [--tg]` | 公网暴露面只读审计，含风险评分 | 季度复查 / 上线后第一次自查 |
| `login-report [--iface I]` | 输出 MOTD 报表的内容 (调试用) | 怀疑 MOTD 显示不对时 |
| `motd-install [--iface I]` / `motd-remove` | 注册 / 卸载 SSH 登录欢迎页 (60s 缓存) | 想看登录时报告状态 |
| `fw-sync-install [--iface I]` / `-remove` / `-status` | 防火墙变更监听钩子的 timer | 你会在 ufw / iptables 里改放行端口，希望 XDP 自动跟上 |
| `fw-sync-now [--iface I]` | 立即触发一次同步 | 调试 fw-sync |
| `tg-test` | 发条 Telegram 测试消息 | 配完 TG 第一次验证 |
| `--version` / `-V` / `version` | 打印版本号 | 报 issue / 升级前确认 |
| `--help` / `-h` / `help` | 用法 | 忘了命令时 |

下划线开头的 (`_fw-apply` / `_runtime-install` / `_runtime-uninstall` / `_fw-sync-run` / `_health-check`)
是 systemd 内部入口，**不要人工调用**。

---

## 工作原理：包到了之后会发生什么

```
                ┌──────────────────────────────────────────────────────┐
                │           网卡驱动 (xdpdrv hook here)                │
                │           xdp_syn_guard.o                            │
                │  ┌───────────────────────────────────────────────┐   │
   incoming     │  │ 1. 解 ethhdr                                  │   │
   ───────────►│  │ 2. 剥最多 2 层 VLAN tag (802.1Q / Q-in-Q)     │   │
                │  │ 3. IPv4: 后片 → PASS；TCP+SYN+!ACK 且 dport   │   │
                │  │           不在 ALLOWED → DROP；其他 PASS      │   │
                │  │          UDP+ALLOWED_UDP_PORTS 非空 且 dport  │   │
                │  │           不在白名单 → DROP                   │   │
                │  │ 4. IPv6: 走 6 步扩展头链 (HBH/RTH/DESTOPT)；  │   │
                │  │          FRAG → PASS；同样的 TCP/UDP 规则     │   │
                │  └───────────────────────────────────────────────┘   │
                └────────────────────┬─────────────────────────────────┘
                                     │ XDP_PASS 才进入下面
                                     ▼
                ┌──────────────────────────────────────────────────────┐
                │           内核协议栈 (input hook, priority -300)     │
                │           nft table inet xdpdrv_guard                │
                │   - BLOCK_PUBLIC_TCP_PORTS 全量 drop (可选)          │
                │   - ALLOWED_TCP_SYN_RATE_PER_SEC limit drop (可选)   │
                │   - 兜底: tcp dport != { allow } counter drop        │
                └────────────────────┬─────────────────────────────────┘
                                     ▼
                              你已有的业务规则 / 应用
```

XDP 是第一道，命中 DROP 的包没花你 CPU。
nft 兜底是第二道，开机早期 XDP 还没挂上的极短窗口里它就在工作。
两层覆盖 + 解耦设计 (独立 nft table，不动你已有规则)。

---

## 子命令详解

### `up` — 上线

```bash
sudo ./xdpdrv-guard.sh up --iface eth0
sudo ./xdpdrv-guard.sh up --iface eth0 --with-deps --with-config   # 第一次推荐
sudo ./xdpdrv-guard.sh up --iface eth0 --no-persist                 # 临时跑跑，不写 systemd
```

参数:
- `--with-deps`: `apt install clang nftables jq …`
- `--with-config`: 从 `xdpdrv-guard.conf.example` 复制 `/etc/xdpdrv-guard.conf` (如果还没有)
- `--no-persist`: 只改运行时，不写 systemd unit (重启就消失)
- `--skip-self-test`: 跳过自检

执行顺序 (v0.1.1):
1. 编译 BPF 程序 (失败时整个流程停在这里，**不动 nft、不动 XDP**)
2. 备份当前 `inet xdpdrv_guard` table 快照
3. 装新 nft 兜底
4. detach 现有 XDP，attach 新的；attach 失败时**自动回滚** nft 到旧快照

### `down` — 下线

```bash
sudo ./xdpdrv-guard.sh down --iface eth0
sudo ./xdpdrv-guard.sh down --iface eth0 --keep-service   # 不动 systemd
sudo ./xdpdrv-guard.sh down --iface eth0 --keep-fw        # 不删 nft 兜底
```

### `doctor` — 排错入口

输出大概长这样：
```
=== Doctor Report ===
iface=eth0
mode=full

[Check] status
program=xdpdrv-guard
version=0.1.1
iface=eth0
allowed_tcp_ports=22,80,443
...
result=status:PASS

[Check] firewall
firewall_stack=nft+ufw
xdpdrv_guard_table=present
...
result=firewall:PASS

[Check] health
...
result=health:PASS

[Check] self-test
...
result=self-test:PASS

doctor_summary=PASS
```

任意一行 `result=xxx:FAIL` 就要点开看上下文。`--quick` 跳过 health 和 self-test
(那两个会临时 attach/detach 一次)。

### `value-report` — 量化效果

```bash
sudo ./xdpdrv-guard.sh value-report --iface eth0 --seconds 15
```

输出包括:
- 这 15 秒内 `rx_packets` / `rx_bytes` 增量
- NET_RX softirq 计数增量、CPU softirq 占比
- `SYN_RECV` / `ESTABLISHED` socket 数增量
- conntrack 表使用率 (有的话)
- 一段中文运维结论 ("当前 XDP 已减负 X%；conntrack 安全水位…")

`--tg` 同时把这段发到 Telegram。

### `surface-audit` — 公网暴露面审计

```bash
sudo ./xdpdrv-guard.sh surface-audit --iface eth0
```

只读，不动现网规则。输出:
- 公网监听 TCP / UDP 端点列表 (端点 + 进程名)
- 风险评分 (LOW / MEDIUM / HIGH)
- 减小暴露面的具体建议

v0.1.1 用 `nft -j` JSON 正向解析 dport / range / set，比之前 regex 推断准。

### `config-ui` 和 `rules-ui` — 交互式管理

不想手写 conf？跑 `config-ui` 让脚本扫监听端口，问你哪些放进白名单，
然后保存生效。`rules-ui` 提供 menu 让你随时加 / 删 / 改。

### `fw-sync` 系列 — 自动跟随 ufw / iptables 变更

详见下面"防火墙同步钩子"章节。

### `motd-*` 系列 — SSH 登录欢迎页

详见下面"SSH 登录报表"章节。

### `tg-test` — Telegram 测试

```bash
sudo ./xdpdrv-guard.sh tg-test
# 应该能在你的 chat 里收到一条带 hostname / iface / mode 的测试消息
```

---

## 防火墙同步钩子 (`fw-sync`)

很多人会在 ufw / iptables / nft 里手工放行新端口，希望 XDP 也跟着放行。

```bash
sudo ./xdpdrv-guard.sh fw-sync-install --iface eth0   # 注册一次，每 30s 自动跑
sudo ./xdpdrv-guard.sh fw-sync-status                  # 看状态
sudo ./xdpdrv-guard.sh fw-sync-now --iface eth0        # 手工触发一次
sudo ./xdpdrv-guard.sh fw-sync-remove                  # 卸载
```

它怎么工作 (v0.1.1)：
1. 抓一个**指纹** (`nft / iptables / ufw` 的规则文本，**剥掉 counter** 防止自激)
2. 跟上次比，没变就跳过
3. 变了就抽出"已被 accept 的 TCP 端口"
4. **运行时合并视图 = `ALLOWED_TCP_PORTS` ∪ 上面那些**
5. 把合并视图作为参数重新 install (重编译 + 重 attach)

> 关键变化：不再写回 `/etc/xdpdrv-guard.conf`。运维从 ufw 删了一个端口，
> 下一轮 fw-sync 自然会从合并视图里去掉它，不再有"配置只增不减"的问题。

> v0.1.1 之前的 bug：counter 字节数每个包都涨，指纹每 30 秒变一次，
> 导致 XDP 每 30 秒重 attach 一次。已修复 (剥 counter + 跳过自管 table)。

---

## SSH 登录报表 (MOTD)

```bash
sudo ./xdpdrv-guard.sh motd-install --iface eth0
sudo ./xdpdrv-guard.sh login-report --iface eth0    # 手工预览，不依赖 SSH
sudo ./xdpdrv-guard.sh motd-remove
```

下次 SSH 登录就会看到:
```
=== XDPDRV Guard Login Report ===
time=2026-04-25T10:30:00+00:00
iface=eth0
xdp_mode=xdpdrv
allowed_tcp_ports=22,80,443
allowed_udp_ports=
rx_packets_total=12345 rx_bytes_total=4567890 rx_dropped_total=...

PROTO  PORT    STACK  DROP_RATIO   SYN_RECV EST
-----  ----    -----  ----------   -------- ---
tcp    22      ipv4   0%           0        2
tcp    80      ipv4   0%           1        12
tcp    443     ipv4   0%           0        45
tcp    8443    ipv4   100%         0        0       # 监听了但没在 ALLOWED 里，会被丢
```

> v0.1.1 起 MOTD 走 60s TTL 缓存 (`/run/xdpdrv-guard/motd.txt`)。sftp / scp / 各种串联
> ssh 不会再每次都触发完整的 ss / sysfs 扫描。想强刷:
> ```bash
> sudo rm /run/xdpdrv-guard/motd.txt
> ```

---

## Telegram 通知 (可选)

```bash
# 1) 配
sudo ./xdpdrv-guard.sh config-ui   # 或者直接编辑 /etc/xdpdrv-guard.conf
# 把这三行设上：
# TELEGRAM_ENABLED=1
# TELEGRAM_BOT_TOKEN="123456789:ABCDEF..."
# TELEGRAM_CHAT_ID="-1001234567890"

# 2) 测
sudo ./xdpdrv-guard.sh tg-test

# 3) 用：value-report / surface-audit 加 --tg 即同发 TG
sudo ./xdpdrv-guard.sh value-report --iface eth0 --seconds 15 --tg
sudo ./xdpdrv-guard.sh surface-audit --iface eth0 --tg
```

不熟 Telegram bot？先和 [@BotFather](https://t.me/BotFather) 私聊
`/newbot` 生成 token；要拿 chat id，把 bot 拉进群 (或私聊给它发一条) 然后看
`https://api.telegram.org/bot<TOKEN>/getUpdates`。

---

## 排错指南 (按症状查)

### "我跑 `up` 报 `Failed to attach in xdpdrv mode`"

网卡不支持 native XDP。三种可能:
- 你 `--iface` 写错了 (写成了 lo / docker0 / 不存在的)
- 网卡驱动太老 (云厂商的 virtio_net 需要 host 端开启 XDP)
- 网卡当前 MTU 不被驱动支持挂 XDP (有的驱动不支持 MTU > 3520)

确认网卡:
```bash
ip -d link show              # 看 driver: 字段
ip route show default        # 看默认出口
```

### "改了 `/etc/xdpdrv-guard.conf` 但好像没生效"

要主动跑 `up` 让它生效:
```bash
sudo ./xdpdrv-guard.sh up --iface eth0
```
v0.1.1 起编译缓存按 SHA256，如果 OBJ 看起来卡住:
```bash
sudo rm -f /path/to/repo/build/xdp_syn_guard.o*
sudo ./xdpdrv-guard.sh up --iface eth0
```

### "`fw-sync` 时间戳一直在变 / journalctl 满屏 reattach"

升级到 v0.1.1。如果已经在 v0.1.1 还出问题，先解钩子看看:
```bash
sudo ./xdpdrv-guard.sh fw-sync-remove
journalctl -u xdpdrv-guard.service -n 100 --no-pager
```

### "MOTD 显示的内容是好几分钟前的"

缓存 60 秒。强刷:
```bash
sudo rm /run/xdpdrv-guard/motd.txt
ssh user@host    # 重新登一下，会同步重生成
```

### "`up` 卡在 `another xdpdrv-guard operation is in progress`"

入口锁，30 秒超时。说明有别的实例 (多半是 systemd timer) 正在跑。等会儿再来；
或者:
```bash
ps -ef | grep xdpdrv-guard
sudo systemctl status xdpdrv-guard-fw-sync.timer
```

### "`Refusing to load /etc/xdpdrv-guard.conf: mode=...` / `owner uid=...`"

权限不对。修一下:
```bash
sudo chown root:root /etc/xdpdrv-guard.conf
sudo chmod 0644 /etc/xdpdrv-guard.conf
```

### "完全要回到没装 xdpdrv-guard 的状态"

```bash
sudo ./xdpdrv-guard.sh down --iface eth0
sudo ./xdpdrv-guard.sh motd-remove
sudo ./xdpdrv-guard.sh fw-sync-remove
sudo rm -rf /etc/xdpdrv-guard.conf /etc/default/xdpdrv-guard* \
            /var/lib/xdpdrv-guard /run/xdpdrv-guard
```

---

## 安全模型 (v0.1.1)

简单说: **被 root 跑的脚本**该有的防御都加了。

| 风险 | 防御 |
|---|---|
| 配置文件被低权限改写 → root 任意命令执行 | 解析器只读 KEY=VALUE，拒绝 `$()`、反引号、`;`、管道；强制 owner=root + mode≤0644 |
| 多入口 (timer / 手工 / config-ui) 并发撞配置和 OBJ | `flock /var/lock/xdpdrv-guard.lock` 串行 |
| systemd 服务以 root 跑、无沙箱 | `NoNewPrivileges` / `ProtectSystem=strict` / `ProtectHome=read-only` / `ProtectKernel*` / `PrivateTmp` / `RestrictAddressFamilies` / `CapabilityBoundingSet=CAP_NET_ADMIN CAP_BPF CAP_SYS_ADMIN ...` |
| 安装失败留下半应用状态 | 先 compile，再换 nft (备份旧快照)，最后 attach；attach 失败自动回滚 nft |
| 自激回环 (counter 抖动 → reattach) | 指纹剥 counter + 跳过自管 table |
| 配置只增不减 | fw-sync 不再写回 conf，运行时每轮重算 |
| 注入构造的 IPv6 / VLAN 包绕过 | 解 IPv6 扩展头链；解 802.1Q / Q-in-Q；丢 IPv4 后片 |

---

## 文件 / 目录全景

```
仓库 (放任意路径都行)
├── xdpdrv-guard.sh                  ← 主脚本 (CLI 入口)
├── xdpdrv-guard.conf.example         ← 配置模板
├── build/
│   ├── xdp_syn_guard.c              ← 数据面源码 (脚本会按配置覆盖)
│   ├── xdp_syn_guard.o              ← 编译产物
│   └── xdp_syn_guard.o.srchash      ← 编译缓存 (sha256 对比源码)
├── README.md / AUDIT.md / CHANGELOG.md

系统侧持久化
├── /etc/xdpdrv-guard.conf            ← 你编辑的运行配置
├── /etc/default/xdpdrv-guard         ← systemd 主服务的 IFACE 等环境
├── /etc/default/xdpdrv-guard-sync    ← fw-sync 的 IFACE 等环境
├── /etc/systemd/system/
│   ├── xdpdrv-guard.service          ← 主服务
│   ├── xdpdrv-guard-fw-sync.service  ← fw-sync 一次性服务
│   └── xdpdrv-guard-fw-sync.timer    ← fw-sync 定时器 (每 30s)
├── /etc/update-motd.d/99-xdpdrv-guard ← MOTD 入口 (60s 缓存壳)

运行状态
├── /var/lib/xdpdrv-guard/
│   ├── runtime.env                   ← 上次 install 的 iface / 端口快照
│   ├── firewall.env                  ← 上次 fw-install 的 nft 状态
│   └── firewall_sync.hash            ← fw-sync 上轮的指纹
├── /var/lock/xdpdrv-guard.lock       ← 入口 flock
└── /run/xdpdrv-guard/motd.txt        ← MOTD 60s TTL 缓存
```

---

## FAQ

**Q: 装上之后我的 SSH 还能进吗？**
A: 默认配置下 (`AUTO_ALLOW_SSH_PORTS=0` 且不在 `ALLOWED_TCP_PORTS`) **不能**——
因为你"应该"用 tailscale。所以 `--with-config` 第一次跑务必检查 conf。
最稳的姿势: 用 KVM 控制台 (云厂商一般有) 跑第一次，验证完再退出。

**Q: 跟 ufw / iptables / docker / podman 共存吗？**
A: ufw / iptables 共存没问题，因为 xdpdrv-guard 用独立 nft table，不动你的链。
docker / podman 创建的 nat 表也不冲突。和 Cilium / Calico (它们也用 XDP) 会冲突，
**不要同时用**。

**Q: 重启之后还在生效吗？**
A: `up` 不带 `--no-persist` 默认装 systemd unit，会开机自启。`down` 默认会反过来移除。

**Q: 性能开销有多大？**
A: 大部分 VPS 上单核 xdpdrv 处理几 Mpps 不是问题。具体数据用 `value-report` 看。

**Q: IPv6 也能保护吗？**
A: 能。v0.1.1 起会解 IPv6 扩展头链 (HBH/RTH/DESTOPT/FRAGMENT)，端口判断和 IPv4 同等。

**Q: 我的网卡有 VLAN trunk，能用吗？**
A: 能。v0.1.1 起最多解 2 层 VLAN tag (单层 802.1Q + 双层 802.1ad / Q-in-Q)。

**Q: 配置改了多少次都不卡顿吗？**
A: 当前每次配置变更要重编译 + 重 attach，attach 之间存在亚秒级"防护真空"。
这是已知问题 (AUDIT §1.5 / §2.1)，下一阶段重构 BPF map 化。频繁改 conf 的场景请知悉。

**Q: 怎么 uninstall 干净？**
A: 见上面"完全要回到没装 xdpdrv-guard 的状态"。

**Q: 报 issue / 提需求？**
A: 把以下贴上:
```bash
sudo ./xdpdrv-guard.sh --version
sudo ./xdpdrv-guard.sh doctor --iface eth0 2>&1 | head -200
journalctl -u xdpdrv-guard.service -n 50 --no-pager
ip -d link show dev eth0
```

---

## 设计边界 — 不会做的事

- 不替代上游清洗。已经到达你网卡的带宽是计费上的事，本机没法退回去。
- 不与你已有 nft 业务链合并写规则。永远是独立 table。
- 不会把 XDP 程序回落到 generic 模式。不支持就直接退出。
- 不自动放行公网 SSH 端口 (`AUTO_ALLOW_SSH_PORTS` 默认 0)。
- 不存元数据 / 不上报云端 (除非你显式开 Telegram)。
- 不为 10G+ 边界网关 / 几千端口的策略规模做优化 (静态 .o 范围表线性扫)。

---

## 路线图

- 5–6 周冲刺 (修补 + 重构) → [AUDIT.md §5](AUDIT.md)
- 6 个月 / 2 年长期 (daemon 化 / GitOps / 自适应学习 / AF_XDP / 合规) → [AUDIT.md §7](AUDIT.md)
- 已合入修复列表 → [CHANGELOG.md](CHANGELOG.md)
