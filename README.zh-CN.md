# ssh-brute-alert

[English](README.md) | **简体中文**

一个轻量、零依赖的 SSH 爆破检测脚本，专为 [青龙面板（Qinglong）](https://github.com/whyour/qinglong) 设计，也适用于任何 Linux 主机。

它通过监控**本机 SSH 端口的并发连接数**来工作：正常情况下只有 1~3 个连接，而公网字典爆破会在几秒内把并发数冲到几十个。一旦超过阈值，脚本就会通过你配置的通知渠道推送告警；连接回落后，还会再发一条「已恢复」的通知。

## 最适合：通过内网穿透暴露的设备（FRP / 端口转发）

本工具**特别适合那些通过内网穿透隧道访问的设备**——比如各种廉价开发板、迷你盒子、随身 WiFi / 4G 路由、家用 NAS 等，它们的 SSH 往往通过 **FRP、ngrok 或类似的端口转发**映射到公网端口。

为什么这类设备最合适：

- 它们的 SSH 被暴露在公网端口上，扫描器会不停地找到并爆破它们。
- 因为隧道把流量转发到 `127.0.0.1:22`，攻击者的真实 IP 会被**改写成 `127.0.0.1`**——导致基于 `auth.log` 的工具和 `fail2ban` 要么失明，要么误伤本机。
- 这类设备通常是低功耗小板子（内存/CPU 有限），一波爆破就能把负载打飞、甚至把机器卡死。及早发现能让你在它扛不住之前就采取措施（换穿透端口、加密钥）。
- 脚本只读 `/proc/net/tcp`，**无需安装任何额外软件包、无需读取日志、无需改动任何系统级配置**——对于安装重型工具很麻烦的受限/嵌入式系统来说非常理想。

如果你在这类设备上跑青龙（或任何 host 网络模式的 Docker 容器），把它作为定时任务加进去，就能免费获得基于连接表的爆破告警。

## 工作原理

- 读取 `/proc/net/tcp` 和 `/proc/net/tcp6`，统计打到被监控 SSH 端口的连接数。
- 在 **host 网络模式的 Docker 容器**（例如青龙）中，`/proc/net/tcp` 反映的是**宿主机的真实连接表**，所以在容器内也能正常工作。
- **不读取 `auth.log`**（容器看不到宿主机日志），**也不改动任何系统配置**——它只读 `/proc`。
- 能识别经隧道（如 FRP）转发的攻击的特征：攻击者打公网穿透端口 → 穿透转发到本地 `127.0.0.1:22` → 源 IP 被改写成 `127.0.0.1`，在连接表里表现为一堆到本地 SSH 端口的并发连接——正是本脚本所统计的。

## ⚠️ 前提要求：Docker 必须用 host 网络模式

本脚本靠读 `/proc/net/tcp` 数连接。**只有 host 网络模式下**，容器看到的才是**宿主机的真实连接表**。在 `bridge`（Docker 默认）或其他网络模式下，容器只能看到它自己的连接，**无法检测到针对宿主机 SSH 的爆破**——脚本会正常运行但永远报 0、永远不告警。

- **青龙官方镜像默认就是 host 网络模式**，一般无需改动。
- **如果你的容器不是 host 网络**，二选一：
  - 用 `--network host` 重建容器（仅限 Linux 宿主机），或
  - 直接在宿主机上（Docker 之外）用 cron 跑脚本——见 [独立运行](#独立运行)。
- **不是 Linux，或用不了 host 网络？** 直接在宿主机操作系统上用系统 cron 跑即可；走 Docker/青龙这条路只是可选项。

快速确认是否在 host 网络：

```bash
docker inspect -f '{{.HostConfig.NetworkMode}}' qinglong   # 应输出：host
```

## 配置

所有配置都由环境变量驱动，**没有任何硬编码的敏感信息**。想用哪个通知渠道就配哪个，可以同时配置多个。

### 参数调节（可选）

| 环境变量 | 默认值 | 含义 |
| --- | --- | --- |
| `SSH_MON_PORT` | `22` | 被监控的本地 SSH 端口 |
| `SSH_MON_THRESHOLD` | `8` | 并发连接超过此值即判为疑似爆破（正常为 1~3） |
| `SSH_MON_SILENCE` | `30` | 告警静默期（分钟，防止刷屏） |

### 通知渠道（至少配置一个）

**填在哪里：** 所有渠道都**集中列在脚本 `ssh_brute_alert.py` 的顶部**（「通知通道集中配置区」），每个都带行内注释标注了**填在哪 / 格式 / 示例**——和常见的青龙开机脚本一个风格。你可以二选一：

- **推荐（青龙）：** 不改脚本，到面板的 **环境变量** 页面填变量（升级不会洗掉配置），或
- **独立运行：** 直接把配置区里的默认值改成你自己的，或运行前 `export` 这些变量。

想配几个渠道都行——配了的每个都会发。下面再把每个渠道的确切格式和示例列一遍（示例值均为占位，请替换成你自己的）。

#### 企业微信应用 —— `QYWX_AM`

格式：**`corpid,secret,touser,agentid`**（逗号分隔，**顺序固定**，共 4 段）。

```
QYWX_AM=ww1a2b3c4d5e6f7g,abcDEF-xxxxxxxxxxxxxxxxxxxxxxxxxx,@all,1000002
```

- `corpid` —— 企业 ID
- `secret` —— 该应用的 Secret
- `touser` —— 接收人；`@all` = 所有人
- `agentid` —— 该应用的 AgentId（一个数字）

> 注意：这个字段顺序和青龙自身用的一致。**不要**把 `touser` 和 `agentid` 调换。

#### 企业微信机器人 —— `QYWX_KEY`

格式：群机器人 webhook 的 **key**（webhook URL 里 `key=` 后面那串）。

```
QYWX_KEY=693a91f6-7xxx-4bc4-97a0-0ec2sifa5aaa
```

#### Telegram —— `TG_BOT_TOKEN` + `TG_USER_ID`

```
TG_BOT_TOKEN=123456789:AAExxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
TG_USER_ID=87654321
```

- `TG_BOT_TOKEN` —— 找 @BotFather 拿
- `TG_USER_ID` —— 你的数字 chat id（找 @userinfobot 拿）
- 可选 `TG_API_HOST` —— 你自建的反代，如 `https://tg.example.com`（默认 `https://api.telegram.org`）

#### Bark（iOS） —— `BARK_PUSH`

格式：完整 URL，**或**只填 device key。

```
BARK_PUSH=https://api.day.app/AbCdEf123456
# 或只填 key：
BARK_PUSH=AbCdEf123456
```

#### Server酱 —— `PUSH_KEY`

格式：SendKey（Turbo 版以 `SCT` 开头，旧版以 `SC` 开头）。

```
PUSH_KEY=SCT12345TxxxxxxxxxxxxxxxxxxxxDEF
```

#### 钉钉机器人 —— `DD_BOT_TOKEN`（+ 可选 `DD_BOT_SECRET`）

```
DD_BOT_TOKEN=a1b2c3d4e5f6xxxxxxxxxxxxxxxxxxxxxxxxxxxx
DD_BOT_SECRET=SECxxxxxxxxxxxxxxxxxxxxxxxx
```

- `DD_BOT_TOKEN` —— 机器人 webhook URL 里 `access_token=` 后面那串
- `DD_BOT_SECRET` —— 仅当你开启了「加签」安全设置时才需要

#### PushPlus —— `PUSH_PLUS_TOKEN`

```
PUSH_PLUS_TOKEN=a1b2c3d4e5f6g7h8xxxxxxxxxxxxxxxx
```

#### Gotify —— `GOTIFY_URL` + `GOTIFY_TOKEN`

```
GOTIFY_URL=https://gotify.example.com
GOTIFY_TOKEN=AbCdxxxxxxxxxxx
```

#### 通用 Webhook —— `WEBHOOK_URL`

格式：任意能接收 `POST`、body 为 JSON `{"title": ..., "content": ...}` 的 URL。

```
WEBHOOK_URL=https://your-endpoint.example.com/hook
```

#### 青龙 `notify`（自动兜底）

无需设置任何变量。如果上面的渠道**一个都没配**，脚本会回退到青龙自带的 `notify` 模块，复用你在青龙里已经配好的所有渠道。

## 在青龙上部署

1. **先确认是 host 网络**（见上面的前提要求）：`docker inspect -f '{{.HostConfig.NetworkMode}}' qinglong` 应输出 `host`。
2. 把脚本放进青龙的脚本目录（通过面板的脚本管理，或 `task` 仓库拉取）。
3. 在青龙的 **环境变量** 页面配置通知变量（格式见上文）。
4. 新建一个定时任务：
   - **命令：** `task ssh_brute_alert.py`
   - **Cron：** `*/3 * * * *`（每 3 分钟一次）

## 独立运行

先 export 你需要的环境变量，再用宿主机的 cron 跑。示例：

```bash
SSH_MON_THRESHOLD=8 \
TG_BOT_TOKEN=123456789:AAExxxx TG_USER_ID=87654321 \
python3 ssh_brute_alert.py
```

加进 crontab 每 3 分钟检查一次：

```bash
*/3 * * * * TG_BOT_TOKEN=... TG_USER_ID=... /usr/bin/python3 /path/to/ssh_brute_alert.py >> /var/log/ssh_brute_alert.log 2>&1
```

## 处置建议

收到告警时，针对「经隧道转发的爆破」，真正有效的处置手段是：

- **更换公网穿透端口**（攻击者扫的是固定端口，一换就把攻击降到零）。
- **添加 SSH 密钥并禁用密码登录。**
- **在穿透服务端做 IP 白名单。**

注意：`fail2ban` 在这种场景下无效——攻击源已被隧道改写成 `127.0.0.1`，封它反而会把本机锁在外面。

## 许可证

MIT
