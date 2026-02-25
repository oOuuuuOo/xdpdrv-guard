# xdpdrv-guard

通用 VPS/独服加固脚本（首版）：
- 仅使用 `xdpdrv`（native）模式。
- 不回落到 `xdpgeneric`。
- 通过 XDP 直接丢弃“打向未开放端口的 TCP SYN”，降低内核与防火墙负载。
- 可选 UDP 白名单防护：配置 `ALLOWED_UDP_PORTS` 后，XDP 会丢弃目标端口不在白名单内的 UDP 报文。
- 通过解耦 `nft` 静态规则做开机早期兜底，规则与 `ALLOWED_TCP_PORTS` 自动同步。
- 支持 `systemd` 自启动与开机自动恢复。
- 提供一键下线命令。
- 提供解耦防火墙框架（独立 table/chain，不改你原有规则链定义）。
- 提供 XDP 价值报告（减负与可操作性指标）。

## 支持范围

- 发行版：Debian / Ubuntu
- CPU 架构：amd64(x86_64) / arm64(aarch64) / armv7(armhf)
- 模式：仅 `xdpdrv`，不回落 `xdpgeneric`

## 目录

- 脚本: `/home/xdpdrv-guard/xdpdrv-guard.sh`
- 示例配置: `/home/xdpdrv-guard/xdpdrv-guard.conf.example`
- 运行配置: `/etc/xdpdrv-guard.conf`

## 快速开始

```bash
sudo /home/xdpdrv-guard/xdpdrv-guard.sh up --iface eth0 --with-deps --with-config
sudo /home/xdpdrv-guard/xdpdrv-guard.sh doctor --iface eth0
```

说明：`up` 会按业务顺序执行：可选依赖/配置 -> 自检 -> 防护生效（XDP+解耦nft）-> 可选开机持久化。

默认安全行为：
- 默认不会自动放行公网 `eth0` 的 SSH 端口（更适合 tailscale-only SSH）
- 若你确实需要公网 SSH 连续性，可在配置中设 `AUTO_ALLOW_SSH_PORTS=1`

## 业务流程命令（推荐）

```bash
# 一键上线（默认会持久化到 systemd）
sudo /home/xdpdrv-guard/xdpdrv-guard.sh up --iface eth0

# 首次机器建议（含依赖和配置初始化）
sudo /home/xdpdrv-guard/xdpdrv-guard.sh up --iface eth0 --with-deps --with-config

# 只做即时防护，不写入开机持久化
sudo /home/xdpdrv-guard/xdpdrv-guard.sh up --iface eth0 --no-persist

# 统一巡检（完整）
sudo /home/xdpdrv-guard/xdpdrv-guard.sh doctor --iface eth0

# 统一巡检（快速）
sudo /home/xdpdrv-guard/xdpdrv-guard.sh doctor --iface eth0 --quick

# 一键下线（默认会移除开机持久化、卸载XDP、移除解耦nft）
sudo /home/xdpdrv-guard/xdpdrv-guard.sh down --iface eth0

# 下线时保留某些组件
sudo /home/xdpdrv-guard/xdpdrv-guard.sh down --iface eth0 --keep-service
sudo /home/xdpdrv-guard/xdpdrv-guard.sh down --iface eth0 --keep-fw
```

`up` 会自动安装并重启 `xdpdrv-guard.service`（写入 `/etc/default/xdpdrv-guard`），并确保服务按 `network-pre` 时序提前启动，尽量缩短开机早期防护真空期。

## 观测命令

```bash
sudo /home/xdpdrv-guard/xdpdrv-guard.sh doctor --iface eth0
sudo /home/xdpdrv-guard/xdpdrv-guard.sh doctor --iface eth0 --quick
sudo /home/xdpdrv-guard/xdpdrv-guard.sh value-report --iface eth0 --seconds 15
sudo /home/xdpdrv-guard/xdpdrv-guard.sh surface-audit --iface eth0
sudo /home/xdpdrv-guard/xdpdrv-guard.sh tg-test
sudo nft -a list table inet xdpdrv_guard
```

## 解耦防火墙框架

- 创建独立的 `nft` 表：`inet xdpdrv_guard`
- 创建独立 hook 链：`xdpdrv_guard_input`（`input` hook，priority `-300`，policy `accept`）
- 对目标网卡的 TCP `SYN` 新连接执行“非允许端口丢弃”，允许端口来自 `ALLOWED_TCP_PORTS`
- 不将规则写入你已有业务链，便于与其他脚本/手工规则解耦
- `up` 执行时会自动同步这套规则，`down` 默认会移除

## 开机即生效：静态 nftables 兜底（由脚本管理）

当你担心“XDP 还没挂上前”的早期窗口时，不需要再手工维护大规则集。
脚本会在开机早期先加载一套**解耦静态 SYN 兜底规则**，并按 `ALLOWED_TCP_PORTS` 自动同步。

检查当前兜底规则：

```bash
sudo /home/xdpdrv-guard/xdpdrv-guard.sh doctor --iface eth0 --quick
sudo nft -a list table inet xdpdrv_guard
```

说明：
- 若需要新增允许端口，只改 `/etc/xdpdrv-guard.conf` 的 `ALLOWED_TCP_PORTS`，然后重新执行 `up --iface <网卡>`
- 若允许端口本身遭遇高强度 SYN 洪泛，可设置 `ALLOWED_TCP_SYN_RATE_PER_SEC`（例如 `2000`）后再执行 `up`
- 若是 tailscale-only SSH，建议设置 `BLOCK_PUBLIC_TCP_PORTS="22"`，对公网网卡上的 22 端口做全量 TCP 硬丢弃
- 若配置 `ALLOWED_UDP_PORTS`，UDP 也可在 XDP 层做端口白名单收敛；若保持为空则延续原行为（不做 UDP XDP 丢弃）
- 此兜底专注于 TCP SYN 攻击面收敛，XDP 继续承担更前置减负

## XDP 价值报告

```bash
sudo /home/xdpdrv-guard/xdpdrv-guard.sh value-report --iface eth0 --seconds 15
```

报告输出示例指标：
- 网卡 RX 速率 / PPS
- NET_RX softirq 速率
- CPU softirq 占比
- SYN_RECV / ESTABLISHED 变化
- conntrack 使用率（若可用）
- “Operator-Focused Value” 文本结论（强调减负与可操作性）

支持可选 TG 推送：

```bash
sudo /home/xdpdrv-guard/xdpdrv-guard.sh value-report --iface eth0 --seconds 15 --tg
```

## 预防面审计（只读）

```bash
sudo /home/xdpdrv-guard/xdpdrv-guard.sh surface-audit --iface eth0
```

审计内容（不修改现网规则）：
- 公网暴露详情（具体 TCP/UDP 端点 + 对应进程）
- 风险评分与等级（LOW/MEDIUM/HIGH）
- 面向非专业用户的“为什么这会影响运维流畅度”说明
- 可执行的最小化暴露建议（不改你的现网规则）

支持可选 TG 推送：

```bash
sudo /home/xdpdrv-guard/xdpdrv-guard.sh surface-audit --iface eth0 --tg
```

## Telegram 通知（可选）

在 `/etc/xdpdrv-guard.conf` 配置：

```bash
TELEGRAM_ENABLED=1
TELEGRAM_BOT_TOKEN="<your-bot-token>"
TELEGRAM_CHAT_ID="<your-chat-id>"
```

发送测试消息：

```bash
sudo /home/xdpdrv-guard/xdpdrv-guard.sh tg-test
```

`doctor` 已包含健康检查与自检链路（`--quick` 会跳过重型检查）。

## 多端口与端口范围

`/etc/xdpdrv-guard.conf` 中 `ALLOWED_TCP_PORTS` 支持：

- 单端口：`22,80,443`
- 端口范围：`10000-10100`
- 混合写法：`22,80-81,443,10000-10100`

相关开关：
- `AUTO_ALLOW_SSH_PORTS=0`：运行时是否自动并入当前 SSH 监听端口（默认关闭）
- `ALLOWED_TCP_SYN_RATE_PER_SEC=0`：允许端口的 SYN 限速阈值（0 表示关闭）
- `BLOCK_PUBLIC_TCP_PORTS=""`：对公网 IFACE 的指定 TCP 端口做全量硬丢弃（例如 `22`）

修改后执行：

```bash
sudo /home/xdpdrv-guard/xdpdrv-guard.sh up --iface eth0
```

可选 UDP 配置示例：

```bash
ALLOWED_UDP_PORTS="53,3478,51820"
```

## 设计说明

- `probe` 会临时挂载最小程序测试 `xdpdrv` 能力，然后立即卸载。
- `up` 在生效阶段会先清理已有 XDP 挂载，再强制尝试 `xdpdrv`。
- 如果 `xdpdrv` 不支持则直接失败退出（符合“不回落 generic”的要求）。

## 注意事项

- 此脚本主要抑制 TCP SYN 扫描/洪泛对主机栈的影响。
- 对于已到达网卡的带宽计量，本机侧仍无法替代上游清洗。
- 变更 `ALLOWED_TCP_PORTS` 后重新执行 `up` 生效。
