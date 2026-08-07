# ssh-brute-alert

**English** | [简体中文](README.zh-CN.md)

A lightweight, zero-dependency SSH brute-force detector for [Qinglong (青龙面板)](https://github.com/whyour/qinglong) — or any Linux host.

It watches the **number of concurrent connections to your local SSH port**. Normal usage sits at 1–3 connections; a public-facing dictionary attack spikes it to dozens within seconds. When the count crosses a threshold, it pushes an alert through whichever notification channels you've configured, and sends a "recovered" notice once things calm down.

## Best fit: devices exposed through a tunnel (FRP / port forwarding)

This tool is **especially useful for devices reached over an intranet-penetration tunnel** — cheap SBCs, mini boxes, portable Wi-Fi/4G routers, home NAS, etc. whose SSH is forwarded to a public port via **FRP, ngrok, or similar port forwarding**.

Why these devices are the sweet spot:

- Their SSH becomes reachable on a public port, so scanners find and brute-force them constantly.
- Because the tunnel forwards to `127.0.0.1:22`, the attacker's real IP is **rewritten to `127.0.0.1`** — so `auth.log`-based tools and `fail2ban` are blind or counterproductive.
- These devices are often low-power (limited RAM/CPU), and a brute-force storm can spike load and even hang the box. Early detection lets you react (change the tunnel port, add a key) before it falls over.
- The script reads only `/proc/net/tcp` and needs **no extra packages, no log access, no root-level config changes** — ideal for constrained/embedded systems where installing heavier tooling is painful.

If you run Qinglong (or any host-network Docker container) on such a device, drop this in as a scheduled task and you get connection-table-based brute-force alerts for free.

## How it works

- Reads `/proc/net/tcp` and `/proc/net/tcp6` to count connections to the monitored SSH port.
- In a **host-network Docker container** (e.g. Qinglong), `/proc/net/tcp` reflects the **host's real connection table**, so it works from inside the container.
- **Does not read `auth.log`** (a container can't see host logs) and **does not touch any system config** — it only reads `/proc`.
- Detects the specific fingerprint of an attack forwarded through a tunnel (e.g. FRP): the attacker hits a public tunnel port, the tunnel forwards to local `127.0.0.1:22`, and the source IP gets rewritten to `127.0.0.1`. That shows up as a burst of concurrent connections to the local SSH port — exactly what this script counts.

## ⚠️ Requirement: Docker must use host network mode

This script counts connections by reading `/proc/net/tcp`. **Only in host network mode** does a container see the **host's real connection table**. In `bridge` (the Docker default) or any other network mode, the container only sees its own connections and **cannot detect brute force against the host's SSH** — the script runs without error but always reports 0 and never alerts.

- **Qinglong's official image runs in host network by default**, so you usually don't need to change anything.
- **If your container is NOT on host network**, either:
  - recreate it with `--network host` (Linux hosts only), or
  - run the script directly on the host (outside Docker) via cron — see [Run standalone](#run-standalone).
- **Not on Linux, or can't use host network?** Run it on the host OS directly with a system cron job; the Docker/Qinglong path is optional.

Quick check that you're on host network:

```bash
docker inspect -f '{{.HostConfig.NetworkMode}}' qinglong   # should print: host
```

## Configuration

Everything is driven by environment variables. **No secrets are hardcoded.** Configure whichever notification channels you want; multiple can be active at once.

### Tuning (optional)

| Env var | Default | Meaning |
| --- | --- | --- |
| `SSH_MON_PORT` | `22` | Local SSH port to watch |
| `SSH_MON_THRESHOLD` | `8` | Concurrent connections above this = suspected brute force (normal is 1–3) |
| `SSH_MON_SILENCE` | `30` | Alert silence window in minutes (avoids spam) |

### Notification channels (configure at least one)

**Where to set these:** in Qinglong, open the panel's **Environment Variables (环境变量)** page and add each variable there. Running standalone, `export` them (or prefix them on the command line) before launching the script. Configure as many channels as you like — every configured one fires.

Each section below shows the **exact value format** and an example (example values are placeholders — replace with your own).

#### WeCom App / 企业微信应用 — `QYWX_AM`

Format: **`corpid,secret,touser,agentid`** (comma-separated, **order matters**, 4 fields).

```
QYWX_AM=ww1a2b3c4d5e6f7g,abcDEF-xxxxxxxxxxxxxxxxxxxxxxxxxx,@all,1000002
```

- `corpid` — enterprise ID
- `secret` — the app's Secret
- `touser` — who receives it; `@all` = everyone
- `agentid` — the app's AgentId (a number)

> Note: this is the same field order Qinglong itself uses. Do **not** swap `touser` and `agentid`.

#### WeCom Bot / 企业微信机器人 — `QYWX_KEY`

Format: the group-bot webhook **key** (the `key=` value from the webhook URL).

```
QYWX_KEY=693a91f6-7xxx-4bc4-97a0-0ec2sifa5aaa
```

#### Telegram — `TG_BOT_TOKEN` + `TG_USER_ID`

```
TG_BOT_TOKEN=123456789:AAExxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
TG_USER_ID=87654321
```

- `TG_BOT_TOKEN` — from @BotFather
- `TG_USER_ID` — your numeric chat id (from @userinfobot)
- Optional `TG_API_HOST` — your own reverse proxy, e.g. `https://tg.example.com` (default `https://api.telegram.org`)

#### Bark (iOS) — `BARK_PUSH`

Format: full URL, **or** just the device key.

```
BARK_PUSH=https://api.day.app/AbCdEf123456
# or just the key:
BARK_PUSH=AbCdEf123456
```

#### Server酱 — `PUSH_KEY`

Format: the SendKey (`SCT...` for Turbo, or the old `SC...`).

```
PUSH_KEY=SCT12345TxxxxxxxxxxxxxxxxxxxxDEF
```

#### DingTalk / 钉钉 — `DD_BOT_TOKEN` (+ optional `DD_BOT_SECRET`)

```
DD_BOT_TOKEN=a1b2c3d4e5f6xxxxxxxxxxxxxxxxxxxxxxxxxxxx
DD_BOT_SECRET=SECxxxxxxxxxxxxxxxxxxxxxxxx
```

- `DD_BOT_TOKEN` — the `access_token=` value from the robot webhook URL
- `DD_BOT_SECRET` — only needed if you enabled the "sign (加签)" security option

#### PushPlus — `PUSH_PLUS_TOKEN`

```
PUSH_PLUS_TOKEN=a1b2c3d4e5f6g7h8xxxxxxxxxxxxxxxx
```

#### Gotify — `GOTIFY_URL` + `GOTIFY_TOKEN`

```
GOTIFY_URL=https://gotify.example.com
GOTIFY_TOKEN=AbCdxxxxxxxxxxx
```

#### Generic Webhook — `WEBHOOK_URL`

Format: any URL that accepts a `POST` with JSON body `{"title": ..., "content": ...}`.

```
WEBHOOK_URL=https://your-endpoint.example.com/hook
```

#### Qinglong `notify` (automatic fallback)

No variable to set. If **none** of the channels above are configured, the script falls back to Qinglong's built-in `notify` module, reusing whatever channels you've already set up in Qinglong.

## Deploy on Qinglong

1. **Confirm host network** (see the requirement section above): `docker inspect -f '{{.HostConfig.NetworkMode}}' qinglong` should print `host`.
2. Add the script to your Qinglong scripts directory (via the panel's script manager or a `task` repo pull).
3. Set your notification env vars on the **Environment Variables (环境变量)** page (see formats above).
4. Create a scheduled task:
   - **Command:** `task ssh_brute_alert.py`
   - **Cron:** `*/3 * * * *` (every 3 minutes)

## Run standalone

Export the env vars you need, then run it from cron on the host. Example:

```bash
SSH_MON_THRESHOLD=8 \
TG_BOT_TOKEN=123456789:AAExxxx TG_USER_ID=87654321 \
python3 ssh_brute_alert.py
```

Add to crontab for every-3-minutes checks:

```bash
*/3 * * * * TG_BOT_TOKEN=... TG_USER_ID=... /usr/bin/python3 /path/to/ssh_brute_alert.py >> /var/log/ssh_brute_alert.log 2>&1
```

## Mitigation reminders

When you get an alert, the real fixes for tunnel-forwarded brute force are:

- **Change the public tunnel port** (attackers scan fixed ports; moving it drops the attack to zero).
- **Add an SSH key and disable password login.**
- **IP allowlist on the tunnel server side.**

Note: `fail2ban` is ineffective here — the attack source is rewritten to `127.0.0.1` by the tunnel, so banning it would lock out the local host.

## License

MIT
