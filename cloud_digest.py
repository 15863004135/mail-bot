#!/usr/bin/env python3
"""163 邮箱 -> 中文摘要 + 待办 -> 飞书。跑在 GitHub Actions 上，不依赖本地电脑。

用法:
    python cloud_digest.py fetch    取新邮件、分析、推飞书
    python cloud_digest.py daily    推一条今日待办
    python cloud_digest.py test     只发一条测试消息
"""
import base64, hashlib, hmac, imaplib, io, json, os, re, sys, time, urllib.request
from datetime import datetime, timedelta, timezone
from email import message_from_bytes
from email.header import decode_header, make_header

ROOT = os.path.dirname(os.path.abspath(__file__))
STATE = os.path.join(ROOT, "state.json")
PENDING = os.path.join(ROOT, "pending.json")
TZ = timezone(timedelta(hours=8))

USER = os.environ.get("MAIL163_USER", "").strip()
PASS = os.environ.get("MAIL163_PASS", "").strip()
KEY = os.environ.get("DEEPSEEK_KEY", "").strip()
HOOK = os.environ.get("FEISHU_WEBHOOK", "").strip()
MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-flash").strip()
DATA_KEY = os.environ.get("DATA_KEY", "").strip()
IMAP_HOST = os.environ.get("MAIL_IMAP_HOST", "imap.163.com").strip()

SCHOOL = ["exeter.ac.uk", "exeterguild.com", "exeterguild.org",
          "universityofexeteruk.onmicrosoft.com"]
AD_WORDS = ["促销", "优惠", "限时", "特惠", "折扣", "立减", "大促", "秒杀", "会员日",
            "领券", "退订", "满减", "抽奖", "unsubscribe", "coupon", "voucher",
            "% off", "promotion", "newsletter", "marketing"]
MAX_PER_RUN = 15


def log(*a):
    print(datetime.now(TZ).strftime("%H:%M:%S"), *a, flush=True)



# ---------- 数据文件加密（密钥放 GitHub Secrets，公开仓库里只看到乱码）----------
def _key():
    """优先用 DATA_KEY；如果 workflow 还没把它传进来，就用 DEEPSEEK_KEY 派生一个，
    这样不需要改 workflow 也能加密。"""
    seed = DATA_KEY or (("derive:" + (KEY or "")) if KEY else "")
    if not seed:
        return None
    return hashlib.sha256(seed.encode("utf-8")).digest()


def _key_source():
    return "DATA_KEY" if DATA_KEY else ("DEEPSEEK_KEY(派生)" if KEY else "无")


def _keystream(key, nonce, n):
    out, i = b"", 0
    while len(out) < n:
        out += hmac.new(key, nonce + i.to_bytes(8, "big"), hashlib.sha256).digest()
        i += 1
    return out[:n]


def enc(obj):
    """没有配钥匙就存明文（本地用）；配了就存加密串。"""
    data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    key = _key()
    if not key:
        return data.decode("utf-8")
    nonce = os.urandom(16)
    ct = bytes(a ^ b for a, b in zip(data, _keystream(key, nonce, len(data))))
    tag = hmac.new(key, nonce + ct, hashlib.sha256).digest()
    return "ENC1:" + base64.b64encode(nonce + tag + ct).decode()


def dec(raw):
    raw = (raw or "").strip()
    if not raw.startswith("ENC1:"):
        return json.loads(raw) if raw else None
    key = _key()
    if not key:
        raise RuntimeError("pending.json 是加密的，但仓库里没有配置 DATA_KEY 这个 Secret")
    blob = base64.b64decode(raw[5:])
    nonce, tag, ct = blob[:16], blob[16:48], blob[48:]
    if not hmac.compare_digest(tag, hmac.new(key, nonce + ct, hashlib.sha256).digest()):
        raise RuntimeError("数据校验失败：DATA_KEY 换过了吗？")
    return json.loads(bytes(a ^ b for a, b in zip(ct, _keystream(key, nonce, len(ct)))).decode("utf-8"))


def load_data(path, default):
    try:
        v = dec(io.open(path, encoding="utf-8").read())
        return default if v is None else v
    except Exception as e:
        log("读取", os.path.basename(path), "失败:", e)
        return default


def save_data(path, obj):
    io.open(path, "w", encoding="utf-8", newline="\n").write(enc(obj) + "\n")


def load(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)


def feishu(payload):
    if not HOOK:
        log("没有配置飞书 Webhook")
        return False
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(HOOK, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            out = json.loads(r.read().decode("utf-8"))
        ok = out.get("code", 0) == 0 or out.get("StatusCode", 0) == 0
        log("飞书:", out.get("msg") or out.get("StatusMessage"), "OK" if ok else "FAIL")
        return ok
    except Exception as e:
        log("飞书发送失败:", e)
        return False


def card(title, elements):
    return {"msg_type": "interactive",
            "card": {"config": {"wide_screen_mode": True},
                     "header": {"template": "blue",
                                "title": {"tag": "plain_text", "content": title}},
                     "elements": elements}}


def md(t):
    return {"tag": "div", "text": {"tag": "lark_md", "content": t}}


def text_of(msg):
    body = ""
    try:
        if msg.is_multipart():
            for part in msg.walk():
                if "attachment" in str(part.get("Content-Disposition") or ""):
                    continue
                if part.get_content_type() == "text/plain":
                    body = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", "ignore")
                    break
            if not body:
                for part in msg.walk():
                    if part.get_content_type() == "text/html":
                        body = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", "ignore")
                        break
        else:
            body = msg.get_payload(decode=True).decode(msg.get_content_charset() or "utf-8", "ignore")
    except Exception:
        pass
    body = re.sub(r"<script.*?</script>", " ", body, flags=re.S | re.I)
    body = re.sub(r"<style.*?</style>", " ", body, flags=re.S | re.I)
    body = re.sub(r"<[^>]+>", " ", body)
    for a, b in (("&nbsp;", " "), ("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">")):
        body = body.replace(a, b)
    body = re.sub(r"[ \t\xa0]+", " ", body)
    body = re.sub(r"\n\s*\n+", "\n", body)
    return body.strip()


def imap_connect():
    M = imaplib.IMAP4_SSL(IMAP_HOST, 993, timeout=60)
    try:
        M.xatom("ID", '("name" "MailDigest" "version" "1.0" "vendor" "personal")')
    except Exception:
        pass
    M.login(USER, PASS)
    return M


def fetch_new(state):
    M = imap_connect()
    typ, dat = M.select("INBOX", readonly=True)
    if typ != "OK":
        raise RuntimeError("cannot open INBOX")
    uidv = M.untagged_responses.get("UIDVALIDITY", [b"0"])[0].decode()
    last = int(state.get("last_uid") or 0) if state.get("uidvalidity") == uidv else 0
    typ, dat = M.uid("SEARCH", None, "UID %d:*" % (last + 1))
    uids = [int(u) for u in (dat[0].split() if dat and dat[0] else [])]
    uids = [u for u in uids if u > last][-MAX_PER_RUN:]
    mails = []
    for uid in uids:
        typ, dat = M.uid("FETCH", str(uid), "(BODY.PEEK[])")
        if typ == "OK" and dat and isinstance(dat[0], tuple):
            mails.append((uid, dat[0][1]))
    state["uidvalidity"] = uidv
    if uids:
        state["last_uid"] = max(uids)
    M.logout()
    return mails


PROMPT = """You help a Chinese student triage university email. Read the email and reply with JSON only:
{"category":"action|important|fyi",
 "summary":"centre idea in Simplified Chinese, under 80 characters",
 "actions":[{"text":"what to do, in Chinese, start with a verb","url":"official URL from the email, else empty"}],
 "deadlines":[{"date":"YYYY-MM-DD","text":"Chinese note"}],
 "events":[{"date":"YYYY-MM-DD","time":"HH:MM or empty","text":"Chinese note"}]}
Rules: actions = only things the recipient must actually do, max 5, else empty list.
Never invent URLs; a URL must appear in the email. Only include dates you can see."""


def ask_ai(subject, sender, body):
    if not KEY:
        return None
    payload = {"model": MODEL,
               "messages": [{"role": "system", "content": PROMPT},
                            {"role": "user", "content": "From: %s\nSubject: %s\n\nBody:\n%s"
                             % (sender, subject, body[:6000])}],
               "response_format": {"type": "json_object"},
               "temperature": 0.2}
    req = urllib.request.Request("https://api.deepseek.com/chat/completions",
                                 data=json.dumps(payload).encode("utf-8"),
                                 headers={"Content-Type": "application/json",
                                          "Authorization": "Bearer " + KEY})
    with urllib.request.urlopen(req, timeout=90) as r:
        out = json.loads(r.read().decode("utf-8"))
    return json.loads(out["choices"][0]["message"]["content"])


def is_school(sender):
    s = (sender or "").lower()
    return any(d in s for d in SCHOOL)


def is_ad(subject, sender):
    t = ((subject or "") + " " + (sender or "")).lower()
    return any(w.lower() in t for w in AD_WORDS)


def mail_card(subject, sender, when, a, forced=False):
    cat = {"action": "需要行动", "important": "重要", "fyi": "知会"}.get(a.get("category"), "")
    els = [md("**%s**\n%s ｜ %s%s" % (subject, cat, sender, " ｜ 学校邮件" if forced else ""))]
    if a.get("summary"):
        els.append(md("**【这封在讲什么】**\n" + a["summary"]))
    acts = []
    for x in (a.get("actions") or [])[:6]:
        if isinstance(x, dict) and x.get("text"):
            u = (x.get("url") or "").strip()
            # 有办理网址就给「去办理」；没有就不再挂"看原文"（那个链接已经废弃）
            acts.append("• %s%s" % (x["text"], ("　[去办理 ↗](%s)" % u) if u.startswith("http") else ""))
    if acts:
        els.append(md("**【要做什么】**\n" + "\n".join(acts)))
    dls = [(x.get("date") or "", x.get("text") or "") for x in (a.get("deadlines") or []) if isinstance(x, dict)]
    dls = [d for d in dls if d[1]]
    if dls:
        els.append(md("**【截止】**\n" + "\n".join("• %s%s" % (d + " " if d else "", t) for d, t in dls[:5])))
    evs = [(x.get("date") or "", x.get("time") or "", x.get("text") or "")
           for x in (a.get("events") or []) if isinstance(x, dict)]
    evs = [e for e in evs if e[2]]
    if evs:
        els.append(md("**【活动】**\n" + "\n".join("• %s %s%s" % (d, (t + " ") if t else "", x) for d, t, x in evs[:5])))
    els.append(md("[打开 163 邮箱去处理 ↗](https://mail.163.com)"))
    els.append({"tag": "note", "elements": [{"tag": "plain_text",
                "content": "邮件时间 %s ｜ 云端自动整理" % when}]})
    return card("📩 新邮件", els)


def daily_card(pending):
    now = datetime.now(TZ)
    today = now.strftime("%Y-%m-%d")
    floor = (now - timedelta(days=14)).strftime("%Y-%m-%d")
    items = sorted([p for p in pending if (p.get("date") or "9999") >= floor or not p.get("date")],
                   key=lambda p: (p.get("date") or "9999-99-99", p.get("added") or ""))
    els = [md("**📊 未完成待办 %d 件**" % len(items))]
    if items:
        lines = []
        for i, p in enumerate(items[:30], 1):
            d = p.get("date") or ""
            tag = ("（⚠️已过期 %s）" % d) if (d and d < today) else (("（截止 %s）" % d) if d else "")
            link = ("　[去办理 ↗](%s)" % p["url"]) if (p.get("url") or "").startswith("http") else ""
            lines.append("%d. %s%s%s\n　　来自：%s" % (i, p.get("text", ""), tag, link, (p.get("mail") or "")[:34]))
        els.append(md("**🔴 要你处理的事（按紧急度排）**\n" + "\n".join(lines)))
    else:
        els.append(md("**🔴 要你处理的事**\n没有未完成的待办。"))
    els.append(md("[打开 163 邮箱去处理 ↗](https://mail.163.com)"))
    els.append({"tag": "note", "elements": [{"tag": "plain_text",
                "content": "云端自动整理 ｜ %s" % now.strftime("%m-%d %H:%M")}]})
    return card("📋 今日待办", els)


def add_pending(pending, subject, a):
    if not isinstance(a, dict):
        return
    day = ""
    for x in (a.get("deadlines") or []):
        if isinstance(x, dict) and x.get("date"):
            day = x["date"]
            break
    for x in (a.get("actions") or []):
        if isinstance(x, dict) and x.get("text"):
            pending.append({"text": x["text"], "url": (x.get("url") or ""), "date": day,
                            "mail": subject, "added": datetime.now(TZ).isoformat()})
    seen, uniq = set(), []
    for p in reversed(pending):
        k = re.sub(r"\W+", "", p.get("text", ""))[:24]
        if k and k not in seen:
            seen.add(k)
            uniq.append(p)
    uniq.reverse()
    del pending[:]
    pending.extend(uniq[-120:])


def do_fetch():
    state = load(STATE, {})
    pending = load_data(PENDING, [])
    mails = fetch_new(state)
    log("取到新邮件 %d 封" % len(mails))
    pushed = 0
    for uid, raw in mails:
        msg = message_from_bytes(raw)
        subj = str(make_header(decode_header(msg.get("Subject", "(no subject)"))))
        frm = str(make_header(decode_header(msg.get("From", ""))))
        when = (msg.get("Date") or "")[:31]
        body = text_of(msg)
        school = is_school(frm)
        try:
            a = ask_ai(subj, frm, body) or {}
        except Exception as e:
            log("AI 失败:", subj[:30], e)
            a = {}
        a["category"] = a.get("category") or "fyi"
        add_pending(pending, subj, a)
        send = school or (a["category"] in ("action", "important") and not is_ad(subj, frm))
        if send:
            if feishu(mail_card(subj, frm, when, a, forced=school)):
                pushed += 1
            time.sleep(1)
        else:
            log("按规则跳过:", subj[:36])
    save(STATE, state)
    save_data(PENDING, pending)
    log("推送 %d 封，待办池 %d 条" % (pushed, len(pending)))
    return 0


def do_daily():
    feishu(daily_card(load_data(PENDING, [])))
    return 0


def do_test():
    feishu(card("✅ 云端邮件助手已接通",
                [md("这是来自 **GitHub 云端** 的测试消息。以后新邮件会自动整理成中文摘要发到这里。")]))
    return 0


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "fetch"
    if mode == "test":
        return do_test()
    missing = [k for k, v in (("MAIL163_USER", USER), ("MAIL163_PASS", PASS),
                              ("DEEPSEEK_KEY", KEY), ("FEISHU_WEBHOOK", HOOK)) if not v]
    if missing:
        log("缺少环境变量:", ", ".join(missing))
        return 1
    if mode == "fetch":
        log("加密钥匙来源:", _key_source())
        return do_fetch()
    if mode == "daily":
        return do_daily()
    log("未知模式:", mode)
    return 1


if __name__ == "__main__":
    sys.exit(main())
