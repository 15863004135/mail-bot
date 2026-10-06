#!/usr/bin/env python3
"""163 邮箱 -> 中文摘要 + 待办 -> 飞书。跑在 GitHub Actions 上，不依赖本地电脑。

用法:
    python cloud_digest.py fetch    取新邮件、分析、推飞书
    python cloud_digest.py daily    推一条今日待办
    python cloud_digest.py test     只发一条测试消息
"""
import base64, hashlib, hmac, imaplib, io, json, os, re, sys, time, urllib.request
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from email import message_from_bytes
from email.header import decode_header, make_header
from email.utils import parsedate_to_datetime

ROOT = os.path.dirname(os.path.abspath(__file__))
STATE = os.path.join(ROOT, "state.json")
PENDING = os.path.join(ROOT, "pending.json")
TZ = timezone(timedelta(hours=8))
UK = ZoneInfo("Europe/London")

USER = os.environ.get("MAIL163_USER", "").strip()
PASS = os.environ.get("MAIL163_PASS", "").strip()
KEY = os.environ.get("DEEPSEEK_KEY", "").strip()
HOOK = os.environ.get("FEISHU_WEBHOOK", "").strip()
MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-flash").strip()
DATA_KEY = os.environ.get("DATA_KEY", "").strip()
APP_FILE = os.path.join(ROOT, "app.json")          # 飞书应用凭据（加密存放）
FEISHU_BASE = "https://open.feishu.cn/open-apis"
IMAP_HOST = os.environ.get("MAIL_IMAP_HOST", "imap.163.com").strip()
# 163 会把邮件自动分到多个文件夹，所以要一起看（跳过 已发送/草稿/垃圾/验证码 这些）
FOLDERS = [f.strip() for f in os.environ.get("MAIL_FOLDERS", "").split(",") if f.strip()] or [
    "INBOX", "其他邮件", "留学申请", "住宿", "账单与财务", "广告邮件"]

SCHOOL = ["exeter.ac.uk", "exeterguild.com", "exeterguild.org",
          "universityofexeteruk.onmicrosoft.com",
          # 下面这些不是学校域名，但和你的学业/生活直接相关，不能漏
          "glide.co.uk",            # 宿舍水电账单
          "cas-shield.com",         # 签证 CAS Shield
          "gov.uk",                 # 英国政府通知（eVisa 等）
          "panopto.com",            # 课程录播
          "teams.mail.microsoft",   # 学校 Teams 通知
          "padlet.com",             # 课程公告板
          ]
AD_WORDS = ["促销", "优惠", "限时", "特惠", "折扣", "立减", "大促", "秒杀", "会员日",
            "领券", "退订", "满减", "抽奖", "unsubscribe", "coupon", "voucher",
            "% off", "promotion", "newsletter", "marketing"]
MAX_PER_RUN = 25


def b64_utf7(s):
    """把中文文件夹名编码成 IMAP 的 modified UTF-7。"""
    out, i = "", 0
    while i < len(s):
        ch = s[i]
        if 0x20 <= ord(ch) <= 0x7e:
            out += "&-" if ch == "&" else ch
            i += 1
        else:
            j = i
            while j < len(s) and not (0x20 <= ord(s[j]) <= 0x7e):
                j += 1
            enc = base64.b64encode(s[i:j].encode("utf-16-be")).decode().rstrip("=").replace("/", ",")
            out += "&" + enc + "-"
            i = j
    return out


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



def hdr(msg, name, default=""):
    """解码邮件头；遇到坏编码也不崩。"""
    raw = msg.get(name, default)
    try:
        return str(make_header(decode_header(raw)))
    except Exception:
        try:
            return str(raw)
        except Exception:
            return default

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
    """扫多个文件夹，返回 [(folder, uid, raw), ...]。state 按文件夹分别记进度。"""
    M = imap_connect()
    folders = state.setdefault("folders", {})
    out = []
    for name in FOLDERS:
        raw_name = b64_utf7(name)
        try:
            typ, dat = M.select(raw_name, readonly=True)
        except Exception as e:
            log("打开文件夹失败:", name, e)
            continue
        if typ != "OK":
            log("跳过文件夹:", name)
            continue
        total = dat[0].decode() if dat and dat[0] else "?"
        uidv = M.untagged_responses.get("UIDVALIDITY", [b"0"])[0].decode()
        st = folders.get(name) or {}
        last = int(st.get("last_uid") or 0) if st.get("uidvalidity") == uidv else 0
        typ, dat = M.uid("SEARCH", None, "UID %d:*" % (last + 1))
        uids = [int(u) for u in (dat[0].split() if dat and dat[0] else [])]
        uids = [u for u in uids if u > last]
        folders[name] = {"uidvalidity": uidv, "last_uid": max(uids) if uids else last}
        if uids:
            log("  %s: 共 %s 封，新 %d 封" % (name, total, len(uids)))
        out.extend((name, u, None) for u in uids)
    out = out[:MAX_PER_RUN]
    mails = []
    for name, uid, _ in out:
        M.select(b64_utf7(name), readonly=True)
        typ, dat = M.uid("FETCH", str(uid), "(BODY.PEEK[])")
        if typ == "OK" and dat and isinstance(dat[0], tuple):
            mails.append((name, uid, dat[0][1]))
    state["folders"] = folders
    # 兼容旧字段
    state.pop("uidvalidity", None)
    state.pop("last_uid", None)
    M.logout()
    return mails


PROMPT = """You help a Chinese student triage university email. Read the email and reply with JSON only:
{"category":"action|important|fyi",
 "summary":"用简体中文概括这封邮件讲什么，不超过 60 字",
 "translation":"把邮件正文完整准确地翻译成简体中文，保留段落和全部关键信息（时间、金额、机构名、网址、要求），最多 1200 字",
 "actions":[{"text":"what to do, in Chinese, start with a verb","evidence":"the exact original sentence from the email that supports this (keep its original language)","url":"official URL from the email, else empty"}],
 "deadlines":[{"date":"YYYY-MM-DD","text":"Chinese note"}],
 "events":[{"date":"YYYY-MM-DD","time":"HH:MM or empty","text":"Chinese note"}]}
Rules: actions = only things the recipient must actually do, max 5, else empty list.
Never invent URLs; a URL must appear in the email. Only include dates you can see.\nCopy evidence EXACTLY from the email, do not translate it."""


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


def mail_card(subject, sender, when, a, forced=False, body_text="", maxlen=1600):
    """一封邮件一张卡片：①概要 ②中文翻译 ③英文原文 ④要做什么 ⑤链接"""
    cat = {"action": "需要行动", "important": "重要", "fyi": "知会"}.get(a.get("category"), "")
    els = [md("**%s**\n%s ｜ %s%s" % (subject, cat, sender, " ｜ 学校邮件" if forced else ""))]
    if a.get("summary"):
        els.append(md("**【概要】**\n" + a["summary"]))
    tr = (a.get("translation") or "").strip()
    if tr:
        cut = "\n……（翻译过长，已截取）" if len(tr) > maxlen else ""
        els.append(md("**【中文翻译】**\n" + tr[:maxlen] + cut))
    orig = (body_text or "").strip()
    if orig:
        cut = "\n……（原文过长，已截取）" if len(orig) > maxlen else ""
        els.append(md("**【英文原文】**\n" + orig[:maxlen] + cut))
    acts = []
    for x in (a.get("actions") or [])[:5]:
        if isinstance(x, dict) and x.get("text"):
            u = (x.get("url") or "").strip()
            ev = (x.get("evidence") or "").strip()
            line = "• %s%s" % (x["text"], ("　[去办理 ↗](%s)" % u) if u.startswith("http") else "")
            if ev:
                line += "\n　　*原文：%s*" % ev[:140]
            acts.append(line)
    els.append(md("**【要做什么】**\n" + ("\n".join(acts) if acts else "（这封没有需要你动手的事）")))
    for x in (a.get("deadlines") or [])[:4]:
        if isinstance(x, dict) and x.get("text"):
            els.append(md("**⏰ 截止** %s %s" % (x.get("date") or "", x["text"])))
    lks = mail_links(body_text)
    if lks:
        els.append(md("**【邮件里的链接】**\n" + "\n".join(
            "• [%s ↗](%s)" % (u.split("/")[2][:30], u) for u in lks)))
    els.append(md("[打开 163 邮箱 ↗](https://mail.163.com)"))
    els.append({"tag": "note", "elements": [{"tag": "plain_text",
                "content": "邮件时间 %s ｜ 云端自动整理" % when}]})
    return card("📩 新邮件", els)


def daily_card(pending):
    now = datetime.now(TZ)
    today = now.strftime("%Y-%m-%d")
    items = sorted_pending(pending)
    els = [md("**📊 未完成待办 %d 件**" % len(items))]
    if items:
        lines = []
        for i, p in enumerate(items[:30], 1):
            d = p.get("date") or ""
            tag = ("（⚠️已过期 %s）" % d) if (d and d < today) else (("（截止 %s）" % d) if d else "")
            link = ("　[去办理 ↗](%s)" % p["url"]) if (p.get("url") or "").startswith("http") else ""
            ev = (p.get("ev") or "").strip()
            lines.append("%d. %s%s%s\n　　%s\n　　来自：%s" % (
                i, p.get("text", ""), tag, link,
                ("*原文：%s*" % ev) if ev else "*原文：见邮件*", (p.get("mail") or "")[:34]))
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
                            "ev": (x.get("evidence") or "")[:160],
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



# ---------- 飞书应用：读群里的命令 ----------
def load_app():
    """优先用环境变量；没有就读取 app.json（加密）。"""
    aid = os.environ.get("FEISHU_APP_ID", "").strip()
    sec = os.environ.get("FEISHU_APP_SECRET", "").strip()
    if not (aid and sec) and os.path.exists(APP_FILE):
        try:
            cfg = dec(io.open(APP_FILE, encoding="utf-8").read().strip()) or {}
            aid = aid or cfg.get("app_id", "")
            sec = sec or cfg.get("app_secret", "")
        except Exception as e:
            log("读取 app.json 失败:", e)
    return aid, sec


def fs_api(method, path, token=None, data=None):
    req = urllib.request.Request(
        FEISHU_BASE + path,
        data=(json.dumps(data, ensure_ascii=False).encode("utf-8") if data is not None else None),
        headers=dict({"Content-Type": "application/json; charset=utf-8"},
                     **({"Authorization": "Bearer " + token} if token else {})),
        method=method)
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.loads(r.read().decode("utf-8"))


def tenant_token(aid, sec):
    try:
        return fs_api("POST", "/auth/v3/tenant_access_token/internal",
                      data={"app_id": aid, "app_secret": sec}).get("tenant_access_token")
    except Exception as e:
        log("取飞书应用 token 失败:", e)
        return None


def sorted_pending(pending):
    """唯一的排序规则：卡片上的序号就是这里的序号（不过滤，避免两边编号对不上）。"""
    return sorted(pending, key=lambda p: (p.get("date") or "9999-99-99", p.get("added") or ""))



# ---------- 找活动：先问一句，再给链接 ----------
ACT = {
    "hike":  ("徒步/户外", [
        ("Meetup：Exeter 徒步活动", "https://www.meetup.com/find/?keywords=hiking&location=Exeter"),
        ("学生会社团总表（找 Hiking / Walking Society）", "https://www.exeterguild.com/societies/main/societies"),
        ("Exeter 官方旅游（周边去哪玩）", "https://www.visitexeter.com/"),
    ]),
    "sport": ("运动/健身", [
        ("Sport Exeter（校队/健身房/课程）", "https://sport.exeter.ac.uk/"),
        ("学生会活动中心", "https://www.exeterguild.com/whats-on/main-pages/events-hub"),
    ]),
    "social": ("社交/认识人", [
        ("学生会活动中心（社交活动都在这）", "https://www.exeterguild.com/whats-on/main-pages/events-hub"),
        ("Meetup：Exeter 社交活动", "https://www.meetup.com/find/?keywords=social&location=Exeter"),
        ("国际学生活动（含 Intercultural Café）", "https://www.exeter.ac.uk/international-students/events-and-support/"),
    ]),
    "culture": ("文化/博物馆/剧院", [
        ("RAMM 博物馆（免费）", "https://rammuseum.org.uk/"),
        ("Northcott 剧院", "https://www.exeternorthcott.co.uk/"),
        ("学校活动日历", "https://www.exeter.ac.uk/events/"),
    ]),
    "trip": ("出去玩/一日游", [
        ("学生会活动中心（社团出游）", "https://www.exeterguild.com/whats-on/main-pages/events-hub"),
        ("Exeter 官方旅游", "https://www.visitexeter.com/"),
        ("火车票 Trainline", "https://www.thetrainline.com/"),
    ]),
}


def act_kind(text):
    t = (text or "").lower()
    if any(k in t for k in ["徒步", "爬山", "hike", "hiking", "walk", "户外", "dartmoor"]):
        return "hike"
    if any(k in t for k in ["运动", "健身", "sport", "gym", "跑步", "球"]):
        return "sport"
    if any(k in t for k in ["社交", "认识", "交友", "social", "朋友", "party"]):
        return "social"
    if any(k in t for k in ["文化", "博物馆", "剧院", "展览", "museum", "theatre", "theater", "concert"]):
        return "culture"
    if any(k in t for k in ["出去玩", "一日游", "旅行", "trip", "travel", "周边", "周末去哪"]):
        return "trip"
    return None


def act_reply(text):
    k = act_kind(text) or "social"
    label, links = ACT[k]
    lines = ["**%s 的入口（点一下就能看/报名）：**" % label]
    for name, u in links:
        lines.append("• [%s ↗](%s)" % (name, u))
    lines.append("\n想换一类就说：徒步 / 运动 / 社交 / 文化 / 出去玩")
    return "\n".join(lines)


def apply_cmd(text, pending, done_log=None):
    """把「3 完成」「EDI 完成」「清单」变成动作，返回要回复的话。"""
    t = (text or "").strip()
    low = t.lower()
    if low in ("清单", "list", "待办", "全部", "查看"):
        return ["__LIST__"]
    # 一次勾掉多条：1-30完成 / 1到30完成 / 1,2,5完成 / 全部完成
    if re.search(r"(全部|所有|都).*(完成|done|已办|删)", t, re.I) or re.search(r"(完成|done|删).*(全部|所有)", t, re.I):
        items = sorted_pending(pending)
        if not items:
            return ["待办清单已经是空的。"]
        n_removed = len(items)
        for x in items:
            if done_log is not None:
                done_log.append({"text": x.get("text", ""), "at": datetime.now(TZ).isoformat()})
        pending[:] = []
        return ["✅ 已把全部 %d 件标记完成，清单清空了。" % n_removed, "__LIST__"]
    m = re.match(r"^(\d+)\s*[-~～至到]\s*(\d+).{0,6}?(完成|done|已完成|好了|ok|删|删除)$", t, re.I) or \
        re.match(r"^(?:完成|done|删|删除)\s*(\d+)\s*[-~～至到]\s*(\d+)$", t, re.I)
    if m:
        nums_all = [int(x) for x in re.findall(r"\d+", t)]
        a, b = nums_all[0], nums_all[-1]
        if a > b:
            a, b = b, a
        nums = list(range(a, b + 1))          # 1-30 -> 1..30，一条一条展开
        items = sorted_pending(pending)
        picked = [items[i - 1] for i in sorted(set(nums)) if 1 <= i <= len(items)]
        if not picked:
            return ["这个范围里没有可勾掉的待办（现在共 %d 条）。" % len(items)]
        for x in picked:
            try:
                pending.remove(x)
            except ValueError:
                pass
            if done_log is not None:
                done_log.append({"text": x.get("text", ""), "at": datetime.now(TZ).isoformat()})
        return ["✅ 已勾掉 %d 件（%d-%d），还剩 %d 件。\n下面是更新后的清单。"
                % (len(picked), min(nums), max(nums), len(sorted_pending(pending))), "__LIST__"]
    m = re.match(r"^[\d,，、\s]+?(完成|done|删|删除)$", t, re.I)
    if m:
        nums = [int(x) for x in re.findall(r"\d+", t)]
        items = sorted_pending(pending)
        picked = [items[i - 1] for i in sorted(set(nums)) if 1 <= i <= len(items)]
        if not picked:
            return ["这些序号里没有可勾掉的待办（现在共 %d 条）。" % len(items)]
        for x in picked:
            try:
                pending.remove(x)
            except ValueError:
                pass
            if done_log is not None:
                done_log.append({"text": x.get("text", ""), "at": datetime.now(TZ).isoformat()})
        return ["✅ 已勾掉 %d 件，还剩 %d 件。\n下面是更新后的清单。"
                % (len(picked), len(sorted_pending(pending))), "__LIST__"]
    m = re.match(r"^(\d+)\s*(?:条)?\s*(完成|done|已完成|好了|ok|删|删除)$", t, re.I) or \
        re.match(r"^(?:完成|done|已完成|删|删除)\s*(\d+)$", t, re.I)
    if m:
        n = int([g for g in m.groups() if g and g.isdigit()][0])
    else:
        m2 = re.match(r"^(.{1,30}?)\s*(?:完成|done|已完成|删|删除)$", t, re.I)
        if not m2:
            return []
        kw = m2.group(1).strip()
        items = sorted_pending(pending)
        hit = [i for i, p in enumerate(items, 1) if kw and kw.lower() in (p.get("text") or "").lower()]
        if not hit:
            return ["没找到包含「%s」的待办。" % kw]
        n = hit[0]
    items = sorted_pending(pending)
    if n < 1 or n > len(items):
        return ["序号 %d 超出范围（现在共 %d 条）。发「清单」可以看当前列表。" % (n, len(items))]
    p = items[n - 1]
    pending.remove(p)
    if done_log is not None:
        done_log.append({"text": p.get("text", ""), "at": datetime.now(TZ).isoformat()})
        del done_log[:-300]
    left = len(sorted_pending(pending))
    return ["✅ 已勾掉「%s」\n还剩 %d 件，下面是更新后的清单。" % ((p.get("text") or "")[:40], left),
            "__LIST__"]


def send_text(chat_id, text, token):
    try:
        fs_api("POST", "/im/v1/messages?receive_id_type=chat_id", token,
               {"receive_id": chat_id, "msg_type": "text",
                "content": json.dumps({"text": text}, ensure_ascii=False)})
        return True
    except Exception as e:
        log("发消息失败:", e)
        return False


def handle_commands(state, pending):
    aid, sec = load_app()
    if not (aid and sec):
        log("没有飞书应用凭据，跳过命令处理")
        return False
    tok = tenant_token(aid, sec)
    if not tok:
        return False
    cid = state.get("cmd_chat")
    if not cid:
        try:
            r = fs_api("GET", "/im/v1/chats?page_size=50", tok)
        except Exception as e:
            log("列群失败:", e); return False
        items = (r.get("data") or {}).get("items") or []
        if not items:
            log("机器人还没被拉进任何群"); return False
        cid = items[0]["chat_id"]
        state["cmd_chat"] = cid
    since = int(state.get("last_cmd_ts") or 0) or (int(time.time()) - 3600)
    try:
        r = fs_api("GET", "/im/v1/messages?container_id_type=chat&container_id=%s"
                          "&start_time=%s&page_size=20&sort_type=ByCreateTimeAsc" % (cid, since), tok)
    except Exception as e:
        log("读群消息失败:", e); return False
    items = (r.get("data") or {}).get("items") or []
    newest, changed, replies = int(since), False, []
    for m in items:
        ct = int(m.get("create_time") or 0) // 1000      # 飞书给的是毫秒，转成秒
        if ct > newest:
            newest = ct
        if m.get("msg_type") != "text":
            continue
        snd = m.get("sender") or {}
        if snd.get("id_type") != "user" and snd.get("sender_type") != "user":
            continue                      # 只认真人发的，忽略机器人自己
        try:
            text = json.loads(m["body"]["content"]).get("text", "")
        except Exception:
            continue
        if not text.strip():
            continue
        log("收到命令:", text.strip()[:40])
        low = text.strip().lower()
        # 1) 他之前问了"找活动"，这条就是回答
        if state.get("pending_q") == "activity":
            state["pending_q"] = ""
            replies.append(act_reply(text))
            changed = True
            send_text(cid, replies[-1], tok)
            continue
        # 2) 他让我找活动 -> 先问一句要哪种
        if re.search(r"(找|推荐|有什么|有啥).{0,6}(活动|玩的|去处)", text) or "周末活动" in text or "活动推荐" in text:
            state["pending_q"] = "activity"
            replies.append("你想找哪一类？回我一个词就行：\n"
                           "① 徒步/户外　② 运动　③ 社交认识人　④ 文化（博物馆/剧院）　⑤ 出去玩/一日游")
            changed = True
            send_text(cid, replies[-1], tok)
            continue
        rng = parse_range(text)
        if rng:
            try:
                n = range_report(rng[0], rng[1], tok, cid, pending)
                changed = True
                log("按需整理了 %d 封" % n)
            except Exception as e:
                log("按需整理失败:", e)
                send_text(cid, "整理失败了：" + str(e)[:80], tok)
            continue
        res = apply_cmd(text, pending, state.setdefault("done_log", []))
        if "__LIST__" in res:
            changed = True
            feishu(daily_card(pending))
            res = [x for x in res if x != "__LIST__"]
        if res:
            changed = True
            replies.extend(res)
    state["last_cmd_ts"] = newest
    for t in replies:
        send_text(cid, t, tok)
    return changed



# ---------- 按日期范围整理邮件 ----------
MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()
RANGE_CAP = 40          # 一次最多整理几封（越大越全，花钱越多）



def mail_links(body, limit=3):
    """从邮件正文里挑几个真实可点的链接（去掉退订之类）。"""
    urls = re.findall(r"https?://[^\s<>\"')]+", body or "")
    out, seen = [], set()
    for u in urls:
        u = u.rstrip(".,;)]>")
        low = u.lower()
        if "unsubscribe" in low or "退订" in u or "mail.163.com" in low:
            continue
        if u in seen:
            continue
        seen.add(u)
        out.append(u)
        if len(out) >= limit:
            break
    return out

def parse_range(text):
    """识别「9月26日之后」「9/26以后」「最近3天」「9月20日到9月26日」。"""
    t = (text or "").strip()
    if not t:
        return None
    today = datetime.now(TZ).date()
    m = re.search(r"最近\s*(\d+)\s*天", t)
    if m:
        return (today - timedelta(days=int(m.group(1))), today)
    if re.search(r"最近\s*(一周|7天|一星期)", t):
        return (today - timedelta(days=7), today)
    d1 = d2 = None
    m = re.search(r"(\d{1,2})\s*月\s*(\d{1,2})\s*日?", t)
    if m:
        d1 = datetime(today.year, int(m.group(1)), int(m.group(2))).date()
        rest = t[m.end():]
        m2 = re.search(r"(\d{1,2})\s*月\s*(\d{1,2})\s*日?", rest)
        if m2:
            d2 = datetime(today.year, int(m2.group(1)), int(m2.group(2))).date()
    if not d1:
        ms = re.findall(r"(\d{1,2})\s*[./／\-－]\s*(\d{1,2})", t)
        if ms:
            def mk(a, b):
                a, b = int(a), int(b)
                mo, dy = (a, b) if a <= 12 else (b, a)
                return datetime(today.year, mo, dy).date()
            d1 = mk(*ms[0])
            if len(ms) > 1:
                d2 = mk(*ms[1])
    if not d1:
        return None
    if d2 and d2 < d1:
        d1, d2 = d2, d1
    return (d1, d2 or today)


def imap_range(start_date, end_date):
    """按日期把邮件正文取回来（最多 RANGE_CAP 封，取最新的）。"""
    M = imap_connect()
    out = []
    for name in FOLDERS:
        try:
            typ, _ = M.select(b64_utf7(name), readonly=True)
            if typ != "OK":
                continue
            crit = "SINCE %02d-%s-%d BEFORE %02d-%s-%d" % (
                start_date.day, MONTHS[start_date.month - 1], start_date.year,
                (end_date + timedelta(days=1)).day, MONTHS[(end_date + timedelta(days=1)).month - 1],
                (end_date + timedelta(days=1)).year)
            typ, dat = M.uid("SEARCH", None, crit)
            uids = [int(u) for u in (dat[0].split() if dat and dat[0] else [])]
            for u in uids:
                typ, dat = M.uid("FETCH", str(u), "(BODY.PEEK[])")
                if typ == "OK" and dat and isinstance(dat[0], tuple):
                    raw = dat[0][1]
                    try:
                        hdr = message_from_bytes(raw)
                        ts = parsedate_to_datetime(hdr.get("Date")).timestamp()
                    except Exception:
                        ts = 0
                    out.append((ts, name, u, raw))
        except Exception as e:
            log("搜索", name, "失败:", e)
    M.logout()
    out.sort(key=lambda x: x[0], reverse=True)   # 按邮件日期从新到旧
    return [(name, u, raw) for _ts, name, u, raw in out[:RANGE_CAP]]


def range_report(start_date, end_date, token, chat_id, pending, skip=None):
    mails = imap_range(start_date, end_date)
    send_text(chat_id, "✅ 正在整理 %s 到 %s 的邮件（共 %d 封），稍后发结果。"
              % (start_date, end_date, len(mails)), token)
    els, n_new, skipped, done = [], 0, 0, []
    for name, uid, raw in mails:
        msg = message_from_bytes(raw)
        mid = str(msg.get("Message-ID") or "")
        if skip and mid and hashlib.sha256(mid.encode()).hexdigest()[:16] in skip:
            continue
        subj = hdr(msg, "Subject", "(no subject)")[:70]
        frm = hdr(msg, "From", "")[:50]
        if os.environ.get("ONLY_SCHOOL", "1") == "1" and not is_school(frm):
            skipped += 1
            continue
        when = (msg.get("Date") or "")[:22]
        body = text_of(msg)
        try:
            a = ask_ai(subj, frm, body) or {}
        except Exception as e:
            log("AI 失败:", subj[:24], e)
            a = {}
        if n_new:
            time.sleep(1)
        feishu(mail_card(subj, frm, when, a, forced=True, body_text=body))
        add_pending(pending, subj, a)
        if mid:
            done.append(hashlib.sha256(mid.encode()).hexdigest()[:16])
        n_new += 1
    els.append(md("[打开 163 邮箱去处理 ↗](https://mail.163.com)"))
    els.append({"tag": "note", "elements": [{"tag": "plain_text",
                "content": "只看学校邮件 ｜ %s 到 %s ｜ 学校邮件 %d 封（其余 %d 封非学校邮件已跳过，不花 token）"
                % (start_date, end_date, n_new, skipped)}]})
    feishu(card("📚 %s 到 %s 的邮件" % (start_date, end_date), els))
    return n_new, done


def weekly_card(pending, state):
    """每周结束时：本周完成了什么、还剩什么。"""
    uk = datetime.now(UK)
    logs = state.get("done_log") or []
    week_ago = (uk - timedelta(days=7)).isoformat()
    recent = [x for x in logs if (x.get("at") or "") >= week_ago]
    items = sorted_pending(pending)
    els = [md("**✅ 本周完成 %d 件**" % len(recent))]
    els.append(md("\n".join("• %s" % (x.get("text") or "")[:60] for x in recent[-20:]) if recent
                  else "（这周还没有标记完成的待办）"))
    els.append(md("**⏳ 还没完成 %d 件**" % len(items)))
    if items:
        lines = []
        for i, x in enumerate(items[:15], 1):
            d = x.get("date") or ""
            link = ("　[去办理 ↗](%s)" % x["url"]) if (x.get("url") or "").startswith("http") else ""
            lines.append("%d. %s%s%s" % (i, x.get("text", "")[:50], ("（截止 %s）" % d) if d else "", link))
        els.append(md("\n".join(lines)))
    els.append(md("[打开 163 邮箱 ↗](https://mail.163.com)"))
    els.append({"tag": "note", "elements": [{"tag": "plain_text",
                "content": "周报 ｜ %s（英国时间）" % uk.strftime("%Y-%m-%d %H:%M")}]})
    return card("📊 本周回顾", els)


def do_fetch():
    state = load(STATE, {})
    pending = load_data(PENDING, [])
    mails = fetch_new(state)
    log("取到新邮件 %d 封" % len(mails))
    pushed = 0
    for uid, raw in mails:
        msg = message_from_bytes(raw)
        subj = hdr(msg, "Subject", "(no subject)")
        frm = hdr(msg, "From", "")
        when = (msg.get("Date") or "")[:31]
        body = text_of(msg)
        school = is_school(frm)
        if not school and os.environ.get("ONLY_SCHOOL", "1") == "1":
            log("不是学校邮件，直接跳过（不花 token）：", (frm or "")[:40], "|", subj[:30])
            continue
        try:
            a = ask_ai(subj, frm, body) or {}
        except Exception as e:
            log("AI 失败:", subj[:30], e)
            a = {}
        a["category"] = a.get("category") or "fyi"
        if school or os.environ.get("ONLY_SCHOOL", "1") != "1":
            add_pending(pending, subj, a)
        send = school or (a["category"] in ("action", "important") and not is_ad(subj, frm))
        if send:
            if feishu(mail_card(subj, frm, when, a, forced=school, body_text=body)):
                pushed += 1
            time.sleep(1)
        else:
            log("按规则跳过:", subj[:36])
    # 处理群里的命令（完成/清单/按日期整理）
    try:
        if handle_commands(state, pending):
            log("已按群里的命令更新待办池")
    except Exception as e:
        log("处理命令出错:", e)
    # 每天 08:00（英国时间）推今日待办；周日 20:00 推周报
    try:
        uk = datetime.now(UK)
        if uk.strftime("%H:%M") >= "08:00" and state.get("last_daily_uk") != uk.strftime("%Y-%m-%d"):
            if feishu(daily_card(pending)):
                state["last_daily_uk"] = uk.strftime("%Y-%m-%d")
                log("已推送今日待办（英国时间 %s）" % uk.strftime("%H:%M"))
        if uk.weekday() == 6 and uk.strftime("%H:%M") >= "20:00" and state.get("last_weekly") != uk.strftime("%Y-%m-%d"):
            if feishu(weekly_card(pending, state)):
                state["last_weekly"] = uk.strftime("%Y-%m-%d")
                log("已推送本周回顾")
    except Exception as e:
        log("日报/周报出错:", e)
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
