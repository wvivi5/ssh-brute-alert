# ssh-brute-alert

A lightweight, zero-dependency SSH brute-force detector for [Qinglong (青龙面板)](https://github.com/whyour/qinglong) — or any Linux host.

It watches the **number of concurrent connections to your local SSH port**. Normal usage sits at 1–3 connections; a public-facing dictionary attack spikes it to dozens within seconds. When the count crosses a threshold, it pushes an alert through whichever notification channels you've configured, and sends a "recovered" notice once things calm down.

## How it works

- Reads `/proc/net/tcp` and `/proc/net/tcp6` to count connections to the monitored SSH port.
- In a **host-network Docker container** (e.g. Qinglong), `/proc/net/tcp` reflects the **host's real connection table**, so it works from inside the container.
- **Does not read `auth.log`** (a container can't see host logs) and **does not touch any system config** — it only reads `/proc`.
- Detects the specific fingerprint of an attack forwarded through a tunnel (e.g. FRP): the attacker hits a public tunnel port, the tunnel forwards to local `127.0.0.1:22`, and the source IP gets rewritten to `127.0.0.1`. That shows up as a burst of concurrent connections to the local SSH port — exactly what this script counts.

## Configuration

Everything is driven by environment variables. **No secrets are hardcoded.** Configure whichever notification channels you want; multiple can be active at once.

### Tuning (optional)

| Env var | Default | Meaning |
| --- | --- | --- |
| `SSH_MON_PORT` | `22` | Local SSH port to watch |
| `SSH_MON_THRESHOLD` | `8` | Concurrent connections above this = suspected brute force (normal is 1–3) |
| `SSH_MON_SILENCE` | `30` | Alert silence window in minutes (avoids spam) |

### Notification channels (configure at least one)

| Channel | Env var(s) |
| --- | --- |
| WeCom App (企业微信应用) | `QYWX_AM` = `corpid,secret,touser,agentid` |
| WeCom Bot (企业微信机器人) | `QYWX_KEY` |
| Telegram | `TG_BOT_TOKEN` + `TG_USER_ID` (optional `TG_API_HOST`) |
| Bark (iOS) | `BARK_PUSH` (full URL or device key) |
| Server酱 | `PUSH_KEY` |
| DingTalk (钉钉) | `DD_BOT_TOKEN` (+ optional `DD_BOT_SECRET`) |
| PushPlus | `PUSH_PLUS_TOKEN` |
| Gotify | `GOTIFY_URL` + `GOTIFY_TOKEN` |
| Generic Webhook | `WEBHOOK_URL` (POST JSON `{title, content}`) |
| Qinglong `notify` | auto fallback — reuses all channels already configured in Qinglong |

If none of the above are set, it falls back to Qinglong's built-in `notify` module.

## Deploy on Qinglong

1. Add the script to your Qinglong scripts directory (e.g. via the panel's script manager or `task` repo).
2. Create a scheduled task:
   - **Command:** `task ssh_brute_alert.py`
   - **Cron:** `*/3 * * * *` (every 3 minutes)
3. Set your notification env vars in Qinglong's environment variables page.

## Run standalone

```bash
SSH_MON_THRESHOLD=8 TG_BOT_TOKEN=xxx TG_USER_ID=yyy python3 ssh_brute_alert.py
```

## Mitigation reminders

When you get an alert, the real fixes for tunnel-forwarded brute force are:

- **Change the public tunnel port** (attackers scan fixed ports; moving it drops the attack to zero).
- **Add an SSH key and disable password login.**
- **IP allowlist on the tunnel server side.**

Note: `fail2ban` is ineffective here — the attack source is rewritten to `127.0.0.1` by the tunnel, so banning it would lock out the local host.

## License

MIT
