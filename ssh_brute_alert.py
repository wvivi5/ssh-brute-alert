#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSH 爆破监控告警脚本 (青龙面板 / 通用)
====================================================
监控本机 SSH 端口的并发连接数, 突增即判定疑似字典爆破, 多渠道推送告警。

【原理】
容器 host 网络模式下 /proc/net/tcp[6] 反映宿主机真实连接表。统计打到本地
SSH 端口的并发连接数: 正常 1~3 个, 被公网扫描器字典爆破时会瞬间冲到几十个。
超过阈值即推送告警, 且不读 auth.log (容器读不到宿主日志)、不动任何系统配置。

【重要: 青龙容器必须用 host 网络模式】
本脚本靠读 /proc/net/tcp 数连接。只有 host 网络模式下, 容器内看到的
才是宿主机真实连接表; bridge/默认网络模式下只能看到容器自己的连接,
检测不到宿主机 SSH 爆破。青龙官方镜像默认就是 host 网络, 一般无需改动。

【多渠道通知 —— 全部走环境变量, 零硬编码, 配了哪个就发哪个 (可同时多个)】
  企业微信应用   QYWX_AM            corpid,secret,touser,agentid  (逗号分隔, 顺序固定)
  企业微信机器人 QYWX_KEY           群机器人 webhook 的 key
  Telegram       TG_BOT_TOKEN + TG_USER_ID   (可选 TG_API_HOST 自建反代)
  Bark(iOS)      BARK_PUSH          完整URL 或 device key
  Server酱       PUSH_KEY           sctapi.ftqq.com
  钉钉机器人     DD_BOT_TOKEN + DD_BOT_SECRET
  PushPlus       PUSH_PLUS_TOKEN
  Gotify         GOTIFY_URL + GOTIFY_TOKEN
  通用Webhook    WEBHOOK_URL        POST JSON {title, content}
  青龙 notify    (自动兜底, 复用青龙已配的全部渠道)

【部署】青龙定时任务, 命令 `task ssh_brute_alert.py`, 建议 */3 * * * *
"""

import os
import json
import time
import socket
import hmac
import base64
import hashlib
import urllib.parse
import urllib.request

# ==================== 可调参数 ====================
SSH_PORT    = int(os.environ.get("SSH_MON_PORT", "22"))   # 被监控的本地 SSH 端口
THRESHOLD   = int(os.environ.get("SSH_MON_THRESHOLD", "8"))  # 并发超此值判爆破 (正常1~3)
SILENCE_MIN = int(os.environ.get("SSH_MON_SILENCE", "30"))  # 告警静默期(分钟)
STATE_FILE  = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".ssh_brute_state.json")
HOSTNAME    = socket.gethostname()
# =================================================


# ============ 通知通道集中配置区 (优先读环境变量, 为空取右侧默认值) ============
#   • 青龙用户: 建议在【环境变量】页面填, 不要直接改本文件 (升级不丢配置)。
#   • 独立运行: 可直接把下面引号里的默认值改成你自己的, 或用环境变量覆盖。
#   • 配了哪个就发哪个, 可同时配多个; 全为空则回退青龙自带 notify。
# ---------------------------------------------------------------------------

# 1. 企业微信应用   格式: corpid,secret,touser,agentid  (逗号分隔, 顺序固定, 共4段)
#    示例: ww1a2b3c4d5e6f7g,abcDEF-xxxxxxxxxxxxxxxxxxxxxxxx,@all,1000002
#    corpid=企业ID  secret=应用Secret  touser=接收人(@all=所有人)  agentid=应用AgentId(数字)
#    ⚠️ 顺序别搞错! touser 在前、agentid 在后 (与青龙一致)。
QYWX_AM         = os.environ.get("QYWX_AM",         "").strip()   # 例: ww1a2b...,SECRET,@all,1000002

# 2. 企业微信机器人  填: 群机器人 webhook URL 里 key= 后面那串
QYWX_KEY        = os.environ.get("QYWX_KEY",        "").strip()   # 例: 693a91f6-xxxx-xxxx-xxxx-xxxxxxxx5aaa

# 3. Telegram       填: BotFather 给的 Token + 你的数字 chat_id (@userinfobot 查)
TG_BOT_TOKEN    = os.environ.get("TG_BOT_TOKEN",    "").strip()   # 例: 123456789:AAExxxxxxxxxxxxxxxxxxxxxxxx
TG_USER_ID      = os.environ.get("TG_USER_ID",      "").strip()   # 例: 87654321
TG_API_HOST     = os.environ.get("TG_API_HOST",     "").strip()   # 可选, 自建反代, 例: https://tg.example.com

# 4. Bark(iOS)      填: 完整推送URL 或 仅 device key
BARK_PUSH       = os.environ.get("BARK_PUSH",       "").strip()   # 例: https://api.day.app/AbCdEf123456  或  AbCdEf123456

# 5. Server酱       填: SendKey (Turbo版以 SCT 开头, 旧版以 SC 开头)
PUSH_KEY        = os.environ.get("PUSH_KEY",        "").strip()   # 例: SCT123456TxxxxxxxxxxxxxxxxxxDEF

# 6. 钉钉机器人     填: webhook URL 里 access_token= 后那串; 若开了"加签"再填 secret
DD_BOT_TOKEN    = os.environ.get("DD_BOT_TOKEN",    "").strip()   # 例: a1b2c3d4e5f6xxxxxxxxxxxxxxxxxxxx
DD_BOT_SECRET   = os.environ.get("DD_BOT_SECRET",   "").strip()   # 例: SECxxxxxxxxxxxxxxxxxxxxxxxx (未开加签留空)

# 7. PushPlus       填: pushplus.plus 的 token
PUSH_PLUS_TOKEN = os.environ.get("PUSH_PLUS_TOKEN", "").strip()   # 例: a1b2c3d4e5f6g7h8xxxxxxxxxxxxxxxx

# 8. Gotify         填: 服务器URL + 应用Token
GOTIFY_URL      = os.environ.get("GOTIFY_URL",      "").strip()   # 例: https://gotify.example.com
GOTIFY_TOKEN    = os.environ.get("GOTIFY_TOKEN",    "").strip()   # 例: AbCdxxxxxxxxxxx

# 9. 通用Webhook    填: 任意接收 POST JSON {title, content} 的URL
WEBHOOK_URL     = os.environ.get("WEBHOOK_URL",     "").strip()   # 例: https://your-endpoint.example.com/hook

# 10. 青龙 notify   无需填, 上面全空时自动兜底, 复用青龙已配的全部渠道。
# ===========================================================================


# ---------- 连接统计 ----------
def count_ssh_conns(port):
    port_hex = f"{port:04X}"
    established = other = 0
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path) as f:
                next(f)
                for line in f:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    if parts[1].split(":")[-1].upper() == port_hex:
                        if parts[3] == "01":
                            established += 1
                        else:
                            other += 1
        except Exception:
            continue
    return established, other


# ---------- 状态持久化 ----------
def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {"last_alert_ts": 0, "alerting": False}


def save_state(state):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(state, f)
    except Exception:
        pass


# ---------- HTTP 小工具 ----------
def _get(url, timeout=15):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode())


def _post(url, payload, timeout=15, is_json=True):
    if is_json:
        data = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json"}
    else:
        data = urllib.parse.urlencode(payload).encode()
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
    req = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read().decode()
        try:
            return json.loads(body)
        except Exception:
            return {"raw": body}


def _env(name):
    return os.environ.get(name, "").strip()


# ---------- 各推送渠道 (返回 True=成功, 抛异常=失败, 返回 None=未配置跳过) ----------
#            (读取顶部"通知通道集中配置区"的变量, 别在这里各自读环境变量)
def ch_qywx_app(title, content):
    am = QYWX_AM
    if not am:
        return None
    # QYWX_AM 格式 (逗号分隔): corpid,secret,touser,agentid  (与青龙/甲骨文脚本一致)
    parts = [p.strip() for p in am.split(",") if p.strip()]
    if len(parts) < 4:
        raise RuntimeError(f"QYWX_AM 段数不足 (需≥4: corpid,secret,touser,agentid; 实为 {len(parts)})")
    corpid, corpsecret, touser, agentid = parts[0], parts[1], parts[2], parts[3]
    origin = os.environ.get("QYWX_ORIGIN", "").strip() or "https://qyapi.weixin.qq.com"
    tok = _get(f"{origin}/cgi-bin/gettoken?corpid={corpid}&corpsecret={corpsecret}")
    at = tok["access_token"]
    res = _post(f"{origin}/cgi-bin/message/send?access_token={at}",
                {"touser": touser, "msgtype": "text", "agentid": agentid,
                 "text": {"content": f"{title}\n\n{content}"}})
    if res.get("errcode") != 0:
        raise RuntimeError(f"企业微信应用: {res}")
    return True


def ch_qywx_bot(title, content):
    key = QYWX_KEY
    if not key:
        return None
    res = _post(f"https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key={key}",
                {"msgtype": "text", "text": {"content": f"{title}\n\n{content}"}})
    if res.get("errcode") != 0:
        raise RuntimeError(f"企业微信机器人: {res}")
    return True


def ch_telegram(title, content):
    token = TG_BOT_TOKEN
    uid = TG_USER_ID
    if not (token and uid):
        return None
    host = TG_API_HOST or "https://api.telegram.org"
    res = _post(f"{host}/bot{token}/sendMessage",
                {"chat_id": uid, "text": f"{title}\n\n{content}"}, is_json=False)
    if not res.get("ok"):
        raise RuntimeError(f"Telegram: {res}")
    return True


def ch_bark(title, content):
    bark = BARK_PUSH
    if not bark:
        return None
    if not bark.startswith("http"):
        bark = f"https://api.day.app/{bark}"
    url = f"{bark.rstrip('/')}/{urllib.parse.quote(title)}/{urllib.parse.quote(content)}"
    _get(url)
    return True


def ch_serverchan(title, content):
    key = PUSH_KEY
    if not key:
        return None
    url = f"https://sctapi.ftqq.com/{key}.send" if key.startswith("SCT") \
        else f"https://sc.ftqq.com/{key}.send"
    res = _post(url, {"title": title, "desp": content}, is_json=False)
    if res.get("code") not in (0, None) and res.get("errno") not in (0, None):
        raise RuntimeError(f"Server酱: {res}")
    return True


def ch_dingtalk(title, content):
    token = DD_BOT_TOKEN
    secret = DD_BOT_SECRET
    if not token:
        return None
    url = f"https://oapi.dingtalk.com/robot/send?access_token={token}"
    if secret:
        ts = str(round(time.time() * 1000))
        sign = urllib.parse.quote_plus(base64.b64encode(hmac.new(
            secret.encode(), f"{ts}\n{secret}".encode(), hashlib.sha256).digest()))
        url += f"&timestamp={ts}&sign={sign}"
    res = _post(url, {"msgtype": "text", "text": {"content": f"{title}\n{content}"}})
    if res.get("errcode") != 0:
        raise RuntimeError(f"钉钉: {res}")
    return True


def ch_pushplus(title, content):
    token = PUSH_PLUS_TOKEN
    if not token:
        return None
    res = _post("http://www.pushplus.plus/send",
                {"token": token, "title": title, "content": content})
    if str(res.get("code")) != "200":
        raise RuntimeError(f"PushPlus: {res}")
    return True


def ch_gotify(title, content):
    url = GOTIFY_URL
    token = GOTIFY_TOKEN
    if not (url and token):
        return None
    res = _post(f"{url.rstrip('/')}/message?token={token}",
                {"title": title, "message": content, "priority": 5})
    if "id" not in res:
        raise RuntimeError(f"Gotify: {res}")
    return True


def ch_webhook(title, content):
    url = WEBHOOK_URL
    if not url:
        return None
    _post(url, {"title": title, "content": content})
    return True


def ch_ql_notify(title, content):
    """青龙自带 notify, 复用青龙已配的全部渠道 (最终兜底)"""
    try:
        import notify
    except Exception:
        return None
    notify.send(title, content)
    return True


CHANNELS = [
    ("企业微信应用", ch_qywx_app),
    ("企业微信机器人", ch_qywx_bot),
    ("Telegram", ch_telegram),
    ("Bark", ch_bark),
    ("Server酱", ch_serverchan),
    ("钉钉", ch_dingtalk),
    ("PushPlus", ch_pushplus),
    ("Gotify", ch_gotify),
    ("Webhook", ch_webhook),
]


def send_alert(title, content):
    """遍历所有渠道: 配置了就发, 统计成功数; 一个都没成功则调青龙 notify 兜底"""
    ok = 0
    for name, fn in CHANNELS:
        try:
            r = fn(title, content)
            if r is True:
                ok += 1
                print(f"[push] ✅ {name} 成功")
            # r is None => 未配置, 静默跳过
        except Exception as e:
            print(f"[push] ⚠️ {name} 失败: {e}")
    if ok == 0:
        try:
            if ch_ql_notify(title, content):
                ok += 1
                print("[push] ✅ 青龙 notify 兜底成功")
        except Exception as e:
            print(f"[push] ⚠️ 青龙 notify 兜底失败: {e}")
    if ok == 0:
        print(f"[push] ❌ 无任何可用推送渠道! 请配置至少一个通知环境变量。\n{title}\n{content}")
    return ok > 0


# ---------- 主逻辑 ----------
def main():
    est, other = count_ssh_conns(SSH_PORT)
    total = est + other
    now = time.time()
    state = load_state()

    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {HOSTNAME} SSH({SSH_PORT}) "
          f"并发: ESTABLISHED={est} 半连接={other} 合计={total} (阈值 {THRESHOLD})")

    if total > THRESHOLD:
        left = SILENCE_MIN * 60 - (now - state.get("last_alert_ts", 0))
        if left > 0:
            print(f"[skip] 疑似爆破但静默期, 剩 {int(left/60)} 分钟, 不重复告警")
        else:
            title = f"⚠️ {HOSTNAME} 疑似 SSH 爆破!"
            content = (f"SSH({SSH_PORT}) 并发连接暴增!\n"
                       f"• 当前: {total} 个 (ESTABLISHED {est} + 半连接 {other})\n"
                       f"• 阈值: {THRESHOLD}  主机: {HOSTNAME}\n"
                       f"• 时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                       f"疑似公网字典爆破。建议: 换穿透端口 / 加 SSH 密钥 / 禁密码登录。\n"
                       f"(静默 {SILENCE_MIN} 分钟, 回落后自动通知恢复)")
            if send_alert(title, content):
                state["last_alert_ts"] = now
                state["alerting"] = True
                save_state(state)
    else:
        if state.get("alerting"):
            send_alert(f"✅ {HOSTNAME} SSH 连接已恢复正常",
                       f"SSH({SSH_PORT}) 并发回落到 {total} 个 (阈值 {THRESHOLD}), 爆破疑似平息。\n"
                       f"时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        state["alerting"] = False
        save_state(state)


if __name__ == "__main__":
    main()
