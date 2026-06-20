#!/usr/bin/env python3
import base64, hashlib, hmac, io, json, os, secrets, subprocess, urllib.parse, yaml
import qrcode
from http.server import BaseHTTPRequestHandler, HTTPServer
from dotenv import load_dotenv

load_dotenv("/opt/vpnserver/.env")

# ── config ────────────────────────────────────────────────────────────────────
SERVER_IP   = os.getenv("SERVER_IP", "")
UUID        = os.getenv("STATIC_UUID", "")
PUBLIC_KEY  = os.getenv("XRAY_PUBLIC_KEY", "")
SHORT_ID    = os.getenv("XRAY_SHORT_ID", "")
PORT_VLESS  = int(os.getenv("XRAY_PORT", "443"))
SNI         = os.getenv("XRAY_SNI", "www.microsoft.com")
REMARK      = "MyVPN"
WEB_PORT    = 80
XRAY_API    = "127.0.0.1:10085"
USERS_FILE  = "/opt/vpnbot/users.json"
TOTAL_LIMIT = 3 * 1024 ** 4

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
SESSION_SECRET = secrets.token_hex(32)

PROXMOX_HOST        = os.getenv("PROXMOX_HOST", "")
PROXMOX_SSH_PORT    = int(os.getenv("PROXMOX_SSH_PORT", "22"))
PROXMOX_SSH_USER    = os.getenv("PROXMOX_SSH_USER", "root")
PROXMOX_SSH_KEY     = os.getenv("PROXMOX_SSH_KEY", "/root/.ssh/id_ed25519")
PROXMOX_SHUTDOWN_CMD = "shutdown -h now"

STATIC_USER = {
    "email": os.getenv("STATIC_TOKEN", "user1"),
    "label": os.getenv("STATIC_LABEL", "Администратор"),
    "token": os.getenv("STATIC_TOKEN", "user1"),
    "uuid":  UUID,
    "username": os.getenv("ADMIN_USERNAME", ""),
    "approved": True,
}

DL_CLASH = {"win": "#", "mac": "#", "linux": "#"}
DL_HAPP  = {"android": "#", "ios": "#"}

# ── auth ──────────────────────────────────────────────────────────────────────
def make_session_token():
    return hmac.new(SESSION_SECRET.encode(), b"admin", hashlib.sha256).hexdigest()

SESSION_TOKEN = make_session_token()

def is_authenticated(cookie_header: str) -> bool:
    if not cookie_header:
        return False
    for part in cookie_header.split(";"):
        k, _, v = part.strip().partition("=")
        if k.strip() == "session" and v.strip() == SESSION_TOKEN:
            return True
    return False

LOGIN_HTML = """<!DOCTYPE html>
<html lang="ru"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MyVPN — Вход</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d0d12;color:#e2e8f0;font-family:-apple-system,'Segoe UI',sans-serif;
  min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.box{background:#16161f;border:1px solid rgba(255,255,255,0.07);border-radius:20px;
  padding:40px;width:100%;max-width:360px}
h2{font-size:1.5rem;font-weight:700;margin-bottom:6px;
  background:linear-gradient(135deg,#e2e8f0,#a78bfa);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent}
.sub{color:#64748b;font-size:.85rem;margin-bottom:28px}
label{display:block;font-size:.75rem;color:#64748b;text-transform:uppercase;
  letter-spacing:.06em;margin-bottom:6px}
input{width:100%;background:#1e1e2a;border:1px solid rgba(255,255,255,0.08);
  border-radius:9px;padding:11px 14px;color:#e2e8f0;font-size:.95rem;outline:none;
  transition:border-color .15s}
input:focus{border-color:#a78bfa}
.err{color:#f87171;font-size:.8rem;margin-top:8px;display:none}
.err.show{display:block}
button{width:100%;margin-top:20px;background:linear-gradient(135deg,#7c3aed,#4f46e5);
  border:none;border-radius:9px;color:#fff;padding:13px;font-size:.95rem;font-weight:600;
  cursor:pointer;transition:opacity .15s}
button:hover{opacity:.88}
</style></head>
<body>
<div class="box">
  <h2>MyVPN Admin</h2>
  <p class="sub">Введите пароль для доступа</p>
  <form method="POST" action="/login">
    <label>Пароль</label>
    <input type="password" name="password" autofocus placeholder="••••••••">
    <div class="err" id="err">WRONG_MSG</div>
    <button type="submit">Войти</button>
  </form>
</div>
</body></html>"""

# ── users ─────────────────────────────────────────────────────────────────────
def load_db() -> dict:
    try:
        return json.loads(open(USERS_FILE).read())
    except Exception:
        return {"admin_id": 0, "users": {}}

def save_db(db: dict):
    open(USERS_FILE, "w").write(json.dumps(db, ensure_ascii=False, indent=2))

def get_routing_mode() -> str:
    return load_db().get("routing_mode", "full")

def set_routing_mode(mode: str):
    db = load_db()
    db["routing_mode"] = mode
    save_db(db)

def active_users() -> list:
    """Approved users for subscriptions."""
    db = load_db()
    out = []
    for tuid, u in db.get("users", {}).items():
        if u.get("approved") and u.get("token"):
            out.append({
                "email":    u.get("email", f"tg_{tuid}"),
                "label":    u.get("name", f"User {tuid}"),
                "username": u.get("username", ""),
                "token":    u["token"],
                "uuid":     u.get("uuid", UUID),
                "approved": True,
            })
    return out

def all_users_for_stats() -> list:
    """All users that ever had an email — for traffic accounting."""
    db = load_db()
    out = [STATIC_USER]
    for tuid, u in db.get("users", {}).items():
        email = u.get("email")
        if not email:
            continue
        out.append({
            "email":    email,
            "label":    u.get("name", f"User {tuid}"),
            "approved": u.get("approved", False),
        })
    return out

def find_user(token: str):
    import time
    if token == STATIC_USER["token"]:
        return STATIC_USER
    for u in active_users():
        if u["token"] == token:
            return u
    # Trial keys
    db = load_db()
    t  = db.get("trial_keys", {}).get(token)
    if t and t.get("expires_at", 0) > time.time():
        return {
            "email":    t["email"],
            "label":    t.get("label", "Тестовый"),
            "token":    token,
            "uuid":     t["uuid"],
            "approved": True,
        }
    return None

# ── xray stats (persistent across restarts) ───────────────────────────────────
STATS_FILE = "/opt/vpnbot/stats_persistent.json"

def _load_persistent() -> dict:
    try:
        return json.loads(open(STATS_FILE).read())
    except Exception:
        return {}

def _save_persistent(data: dict):
    try:
        open(STATS_FILE, "w").write(json.dumps(data))
    except Exception:
        pass

def _query_live() -> dict:
    try:
        r = subprocess.run(
            ["/opt/xray/xray", "api", "statsquery", f"--server={XRAY_API}"],
            capture_output=True, text=True, timeout=3
        )
        data = json.loads(r.stdout)
        out = {}
        for item in data.get("stat", []):
            n, v = item["name"], int(item.get("value", 0))
            if "user>>>" in n:
                parts = n.split(">>>")
                email, direction = parts[1], parts[3]
                if email not in out:
                    out[email] = {"uplink": 0, "downlink": 0}
                out[email][direction] = v
        return out
    except Exception:
        return {}

def snapshot_stats():
    """Call before xray restart to persist current counters."""
    live  = _merge_aliases(_query_live())
    saved = _merge_aliases(_load_persistent())
    for email, vals in live.items():
        if email not in saved:
            saved[email] = {"uplink": 0, "downlink": 0}
        saved[email]["uplink"]   += vals.get("uplink", 0)
        saved[email]["downlink"] += vals.get("downlink", 0)
    _save_persistent(saved)

EMAIL_ALIASES = {
    "user1_admin":      "user1",
    "user1_admin_happ": "user1_happ",
}

def _merge_aliases(d: dict) -> dict:
    out = {}
    for email, vals in d.items():
        key = EMAIL_ALIASES.get(email, email)
        if key not in out:
            out[key] = {"uplink": 0, "downlink": 0}
        out[key]["uplink"]   += vals.get("uplink", 0)
        out[key]["downlink"] += vals.get("downlink", 0)
    return out

def get_stats() -> dict:
    saved = _merge_aliases(_load_persistent())
    live  = _merge_aliases(_query_live())
    out   = {}
    for email in set(saved) | set(live):
        s = saved.get(email, {})
        l = live.get(email, {})
        out[email] = {
            "uplink":   s.get("uplink", 0)   + l.get("uplink", 0),
            "downlink": s.get("downlink", 0) + l.get("downlink", 0),
        }
    return out

def _autosave_stats():
    import threading
    def loop():
        import time
        while True:
            time.sleep(300)  # every 5 minutes
            snapshot_stats()
    t = threading.Thread(target=loop, daemon=True)
    t.start()

def fmt(b):
    b = int(b)
    if b < 1024:      return f"{b} B"
    if b < 1024**2:   return f"{b/1024:.1f} KB"
    if b < 1024**3:   return f"{b/1024**2:.1f} MB"
    return f"{b/1024**3:.2f} GB"

def make_qr_b64(text: str) -> str:
    img = qrcode.make(text)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()

# ── vless / subs ──────────────────────────────────────────────────────────────
PORT_HAPP = 2053  # fallback port without flow

def vless_link(uid=None, flow=True, port=None):
    uid  = uid or UUID
    port = port or PORT_VLESS
    params = {
        "security": "reality", "sni": SNI, "fp": "firefox",
        "pbk": PUBLIC_KEY, "sid": SHORT_ID,
        "type": "tcp", "headerType": "none", "encryption": "none",
    }
    if flow:
        params["flow"] = "xtls-rprx-vision"
    p = urllib.parse.urlencode(params)
    return f"vless://{uid}@{SERVER_IP}:{port}?{p}#{urllib.parse.quote(REMARK)}"

def _build_clash(uid, port, flow=None):
    mode = get_routing_mode()
    G_PROXY = "🌍 Весь трафик" if mode == "full" else "🌍 Иностранные сайты"
    G_RU = "🇷🇺 Русские сайты"
    proxy = {
        "name": REMARK, "type": "vless",
        "server": SERVER_IP, "port": port, "uuid": uid,
        "network": "tcp", "tls": True, "udp": True,
        "reality-opts": {"public-key": PUBLIC_KEY, "short-id": SHORT_ID},
        "servername": SNI, "client-fingerprint": "firefox",
    }
    if flow:
        proxy["flow"] = flow
    local = [f"IP-CIDR,{SERVER_IP}/32,DIRECT,no-resolve",
             "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
             "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
             "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
             "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve"]
    if mode == "full":
        rules = local + [f"DOMAIN-SUFFIX,{d},{G_RU}" for d in RU_DOMAINS] + [f"MATCH,{G_PROXY}"]
        groups = [
            {"name": G_PROXY, "type": "select", "proxies": [REMARK, "DIRECT"]},
            {"name": G_RU,    "type": "select", "proxies": ["DIRECT", REMARK]},
        ]
    else:
        rules = local + [f"DOMAIN-SUFFIX,{d},{G_RU}" for d in RU_DOMAINS] + [f"MATCH,{G_PROXY}"]
        groups = [
            {"name": G_PROXY, "type": "select", "proxies": [REMARK, "DIRECT"]},
            {"name": G_RU,    "type": "select", "proxies": ["DIRECT", REMARK]},
        ]
    return yaml.dump({
        "port": 7890, "socks-port": 7891, "allow-lan": True,
        "mode": "rule", "log-level": "info",
        "proxies": [proxy], "proxy-groups": groups, "rules": rules,
    }, allow_unicode=True, default_flow_style=False)

def clash_yaml_happ(uid=None):
    return _build_clash(uid or UUID, PORT_HAPP, flow=None)

def v2ray_sub(uid=None):
    # port 2053, no Vision flow — HAPP doesn't support xtls-rprx-vision
    return base64.b64encode(vless_link(uid, flow=False, port=PORT_HAPP).encode()).decode()

RU_DOMAINS = [
    "vk.com","vk.ru","vkontakte.ru","userapi.com","vkuseraudio.net",
    "ok.ru","odnoklassniki.ru",
    "yandex.ru","yandex.net","yandex.com","yandex.st","yandex-team.ru",
    "ya.ru","yastatic.net","yandexcloud.net","yandex.kz",
    "mail.ru","my.mail.ru","imgsmail.ru","mradx.net",
    "sber.ru","sberbank.ru","sberpay.ru","sbermarket.ru","domclick.ru",
    "gosuslugi.ru","mos.ru","nalog.gov.ru","nalog.ru","pfr.gov.ru",
    "kremlin.ru","government.ru","cbr.ru","rkn.gov.ru",
    "ozon.ru","wildberries.ru","avito.ru","youla.ru","cian.ru",
    "lamoda.ru","dns-shop.ru","mvideo.ru","eldorado.ru",
    "kinopoisk.ru","ivi.ru","okko.tv","more.tv","premier.one",
    "rbc.ru","ria.ru","tass.ru","lenta.ru","kommersant.ru",
    "interfax.ru","rt.com","1tv.ru","russia.tv","ntv.ru",
    "rambler.ru","gazeta.ru","iz.ru","mk.ru","aif.ru",
    "mts.ru","beeline.ru","megafon.ru","tele2.ru","rostelecom.ru",
    "2gis.ru","pochta.ru","russianpost.ru","hh.ru","superjob.ru",
    "tinkoff.ru","vtb.ru","alfabank.ru","raiffeisen.ru","gazprombank.ru",
    "habr.com","pikabu.ru","dzen.ru","zen.yandex.ru",
    "2ip.ru","reg.ru","beget.ru","timeweb.ru",
]

def clash_yaml(uid=None):
    return _build_clash(uid or UUID, PORT_VLESS, flow="xtls-rprx-vision")

# ── CSS / JS (shared) ─────────────────────────────────────────────────────────
CSS = """
:root{--bg:#0d0d12;--s:#16161f;--s2:#1e1e2a;--br:rgba(255,255,255,0.07);
  --p:#a78bfa;--g:#34d399;--r:#f87171;--t:#e2e8f0;--m:#64748b}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--t);font-family:-apple-system,'Segoe UI',sans-serif;
  min-height:100vh;padding:32px 16px 60px}
.wrap{max-width:680px;margin:0 auto;display:flex;flex-direction:column;gap:16px}
h1{font-size:1.9rem;font-weight:700;
  background:linear-gradient(135deg,#e2e8f0,var(--p));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:4px}
.sub{color:var(--m);font-size:.9rem}
.badge{display:inline-flex;align-items:center;gap:6px;background:rgba(167,139,250,.1);
  border:1px solid rgba(167,139,250,.25);border-radius:100px;padding:5px 12px;
  font-size:.72rem;color:var(--p);text-transform:uppercase;letter-spacing:.05em;margin-bottom:16px}
.dot{width:6px;height:6px;border-radius:50%;background:var(--g);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.card{background:var(--s);border:1px solid var(--br);border-radius:16px;overflow:hidden}
.card:hover{border-color:rgba(167,139,250,.25)}
.card-head{display:flex;align-items:center;gap:14px;padding:20px;border-bottom:1px solid var(--br)}
.icon{width:46px;height:46px;border-radius:12px;display:flex;align-items:center;
  justify-content:center;font-size:1.4rem;flex-shrink:0}
.icon-stat{background:rgba(167,139,250,.12);border:1px solid rgba(167,139,250,.2)}
.icon-clash{background:linear-gradient(135deg,#f59e0b,#dc2626)}
.icon-happ{background:linear-gradient(135deg,#06b6d4,#10b981)}
.card-title{font-size:1rem;font-weight:700}
.card-sub{font-size:.75rem;color:var(--m);margin-top:2px}
.card-body{padding:16px 20px;display:flex;flex-direction:column;gap:10px}
.ptag{display:inline-block;background:var(--s2);border:1px solid var(--br);
  border-radius:6px;padding:2px 8px;font-size:.68rem;color:var(--m);margin:2px 2px 0 0}
.tblock{padding:16px 20px;border-bottom:1px solid var(--br)}
.trow{display:flex;align-items:baseline;justify-content:space-between;margin-bottom:8px;flex-wrap:wrap;gap:8px}
.tlabel{font-size:.72rem;color:var(--m);text-transform:uppercase;letter-spacing:.05em}
.tval{font-size:.9rem}
.track{height:6px;background:rgba(255,255,255,.07);border-radius:100px;overflow:hidden;margin-bottom:6px}
.fill{height:100%;border-radius:100px;transition:width .6s}
.tmeta{display:flex;justify-content:space-between;font-size:.73rem}
.urow{display:flex;align-items:center;gap:12px;padding:12px 20px;border-bottom:1px solid var(--br)}
.urow:last-child{border-bottom:none}
.avatar{width:34px;height:34px;border-radius:50%;background:linear-gradient(135deg,#7c3aed,#4f46e5);
  display:flex;align-items:center;justify-content:center;font-weight:700;font-size:.78rem;color:#fff;flex-shrink:0}
.avatar.rev{background:linear-gradient(135deg,#4b5563,#374151)}
.uinfo{flex:1}.uname{font-weight:600;font-size:.88rem}.uemail{font-size:.7rem;color:var(--m);font-family:monospace}
.urev{font-size:.68rem;color:var(--r);background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.2);
  border-radius:5px;padding:1px 6px;margin-left:6px}
.tstats{display:flex;gap:14px;align-items:center}
.si{text-align:center}.sv{font-size:.9rem;font-weight:700;font-family:monospace}
.sv.up{color:var(--g)}.sv.dn{color:#60a5fa}
.sl{font-size:.62rem;color:var(--m);text-transform:uppercase;margin-top:1px}
.stotal{font-size:.76rem;font-weight:600;color:var(--p);background:rgba(167,139,250,.08);
  border:1px solid rgba(167,139,250,.15);border-radius:7px;padding:5px 9px;white-space:nowrap}
.crow{display:flex;align-items:center;gap:8px;background:var(--s2);
  border:1px solid var(--br);border-radius:9px;padding:9px 12px;transition:border-color .15s}
.crow.flash{border-color:var(--g)!important}
.cv{flex:1;font-family:'Courier New',monospace;font-size:.75rem;color:#c4b5fd;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;user-select:all}
.cb{background:none;border:1px solid rgba(167,139,250,.3);border-radius:6px;
  color:var(--p);padding:5px 10px;font-size:.72rem;font-weight:600;cursor:pointer;
  white-space:nowrap;flex-shrink:0;transition:all .15s}
.cb:hover{background:rgba(167,139,250,.12);border-color:var(--p)}
.cb.ok{background:rgba(52,211,153,.12);border-color:var(--g);color:var(--g)}
.flabel{font-size:.68rem;color:var(--m);text-transform:uppercase;letter-spacing:.05em;margin-bottom:5px}
.divider{border:none;border-top:1px solid var(--br);margin:2px 0}
.qr-wrap{display:flex;flex-direction:column;align-items:center;gap:10px;padding:14px 0 4px}
.qr-wrap canvas,.qr-wrap img{border-radius:12px;border:3px solid rgba(255,255,255,.08);
  background:#fff;padding:10px;width:180px;height:180px}
.qr-hint{font-size:.72rem;color:var(--m);text-align:center}
.dlrow{display:flex;flex-wrap:wrap;gap:7px;padding:14px 20px;border-top:1px solid var(--br)}
.dllabel{font-size:.68rem;color:var(--m);text-transform:uppercase;letter-spacing:.05em;padding:10px 20px 0}
.dlbtn{display:inline-flex;align-items:center;gap:6px;background:rgba(255,255,255,.04);
  border:1px solid var(--br);border-radius:7px;padding:7px 13px;text-decoration:none;
  color:var(--m);font-size:.78rem;transition:all .15s}
.dlbtn:hover{border-color:var(--p);color:var(--p);background:rgba(167,139,250,.06)}
.strip{background:var(--s);border:1px solid var(--br);border-radius:12px;
  display:flex;flex-wrap:wrap;overflow:hidden}
.si2{padding:12px 24px;text-align:center;border-right:1px solid var(--br);flex:1;min-width:120px}
.si2:last-child{border-right:none}
.sl2{font-size:.68rem;color:var(--m);text-transform:uppercase;letter-spacing:.06em;margin-bottom:3px}
.sv2{font-size:.9rem;font-weight:600;color:var(--p);font-family:monospace}
.pxbtn{display:flex;align-items:center;gap:14px;
  background:linear-gradient(135deg,rgba(229,112,0,.1),rgba(229,112,0,.04));
  border:1px solid rgba(229,112,0,.3);border-radius:16px;padding:18px 20px;
  text-decoration:none;color:var(--t);transition:all .2s}
.pxbtn:hover{border-color:rgba(229,112,0,.65);transform:translateY(-1px)}
.pxtxt{flex:1;display:flex;flex-direction:column;gap:2px}
.pxname{font-size:1.05rem;font-weight:700;color:#fb923c}
.pxsub{font-size:.78rem;color:var(--m)}
.pxport{font-family:monospace;font-size:.82rem;font-weight:700;color:#fb923c;
  background:rgba(229,112,0,.13);border:1px solid rgba(229,112,0,.22);
  border-radius:7px;padding:5px 11px;flex-shrink:0}
.refresh-area{padding:10px 20px;font-size:.72rem;color:var(--m);
  display:flex;justify-content:space-between;border-top:1px solid var(--br)}
.rbtn{background:none;border:1px solid var(--br);border-radius:6px;color:var(--m);
  padding:4px 10px;cursor:pointer;font-size:.72rem;transition:all .15s}
.rbtn:hover{border-color:var(--p);color:var(--p)}

/* system controls */
.sys-row{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
.sys-info{flex:1}
.sys-name{font-weight:600;font-size:.92rem;margin-bottom:4px}
.sys-status{font-size:.78rem;display:flex;align-items:center;gap:6px}
.st-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0;display:inline-block}
.st-on{background:#34d399;box-shadow:0 0 6px #34d399}
.st-off{background:#f87171;box-shadow:0 0 6px #f87171}
.st-unknown{background:#64748b}
.sys-btns{display:flex;gap:8px;flex-shrink:0}
.sys-btn{border:none;border-radius:8px;padding:8px 16px;font-size:.8rem;font-weight:600;
  cursor:pointer;transition:all .15s;white-space:nowrap}
.sys-btn:disabled{opacity:.45;cursor:not-allowed}
.sys-btn-on{background:rgba(52,211,153,.15);border:1px solid rgba(52,211,153,.35);color:#34d399}
.sys-btn-on:hover:not(:disabled){background:rgba(52,211,153,.25)}
.sys-btn-off{background:rgba(248,113,113,.12);border:1px solid rgba(248,113,113,.3);color:#f87171}
.sys-btn-off:hover:not(:disabled){background:rgba(248,113,113,.22)}
.sys-btn-danger{background:rgba(239,68,68,.15);border:1px solid rgba(239,68,68,.4);color:#ef4444}
.sys-btn-danger:hover:not(:disabled){background:rgba(239,68,68,.25)}
@media(max-width:480px){h1{font-size:1.5rem}.tstats{gap:8px}.stotal{display:none}}
"""

JS = """
function fmt(b){b=parseInt(b)||0;
  if(b<1024)return b+' B';if(b<1048576)return(b/1024).toFixed(1)+' KB';
  if(b<1073741824)return(b/1048576).toFixed(1)+' MB';return(b/1073741824).toFixed(2)+' GB'}
function renderStats(data){
  const LIMIT=3*1024*1024*1024*1024;
  let tot=0;
  (data.users||[]).forEach(u=>{tot+=(parseInt(u.uplink)||0)+(parseInt(u.downlink)||0)});
  const pct=Math.min(100,tot/LIMIT*100),pctS=pct.toFixed(1);
  const col=pct>85?'#f87171':pct>60?'#fb923c':'#34d399';
  const srv=document.getElementById('srv-stats');
  if(srv) srv.innerHTML=`
    <div class="trow"><span class="tlabel">Всего на сервере (3 ТБ)</span>
      <span class="tval"><b style="color:var(--t)">${fmt(tot)}</b> <span style="color:var(--m)">из 3 ТБ</span></span></div>
    <div class="track"><div class="fill" style="width:${pctS}%;background:${col}"></div></div>
    <div class="tmeta"><span style="color:${col}">${pctS}% использовано</span>
      <span style="color:var(--m)">Осталось: ${fmt(LIMIT-tot)}</span></div>`;
  // personal
  const uid=document.getElementById('user-email')?.value;
  if(uid){
    const u=(data.users||[]).find(x=>x.email===uid);
    const el=document.getElementById('user-stats');
    if(el&&u){
      const up=parseInt(u.uplink)||0,dn=parseInt(u.downlink)||0,t=up+dn;
      const up2=Math.min(100,t/LIMIT*100),uc=up2>85?'#f87171':up2>60?'#fb923c':'#34d399';
      el.innerHTML=`
        <div class="trow"><span class="tlabel">Твой расход</span>
          <span class="tval"><b style="color:var(--t)">${fmt(t)}</b> <span style="color:var(--m)">из 3 ТБ</span></span></div>
        <div class="track"><div class="fill" style="width:${up2.toFixed(1)}%;background:${uc}"></div></div>
        <div class="tmeta">
          <span>↑ <b style="color:#34d399">${fmt(up)}</b> &nbsp; ↓ <b style="color:#60a5fa">${fmt(dn)}</b></span>
          <span style="color:var(--m)">${up2.toFixed(1)}%</span></div>`;
    }
  }
  // admin table
  const tbl=document.getElementById('all-users');
  if(tbl&&data.users) tbl.innerHTML=data.users.map(u=>{
    const up=parseInt(u.uplink)||0,dn=parseInt(u.downlink)||0,tot2=up+dn;
    const init=(u.label||'?').split(' ').map(w=>w[0]).join('').toUpperCase().slice(0,2);
    const revBadge=u.approved?'':'<span class="urev">отозван</span>';
    return `<div class="urow">
      <div class="avatar${u.approved?'':' rev'}">${init}</div>
      <div class="uinfo"><div class="uname">${u.label}${revBadge}</div>
        <div class="uemail">${u.email}</div></div>
      <div class="tstats">
        <div class="si"><div class="sv up">↑ ${fmt(up)}</div><div class="sl">Отправлено</div></div>
        <div class="si"><div class="sv dn">↓ ${fmt(dn)}</div><div class="sl">Получено</div></div>
        <div class="stotal">Всего: ${fmt(tot2)}</div>
      </div></div>`;
  }).join('');
  document.getElementById('last-upd').textContent='Обновлено: '+new Date().toLocaleTimeString('ru-RU');
}
function loadStats(){fetch('/api/stats').then(r=>r.json()).then(renderStats).catch(()=>{})}
function doCopy(t){
  if(navigator.clipboard&&window.isSecureContext)return navigator.clipboard.writeText(t);
  return new Promise((res,rej)=>{const e=document.createElement('textarea');
    e.value=t;e.style.cssText='position:fixed;top:-9999px;opacity:0';
    document.body.appendChild(e);e.focus();e.select();
    try{document.execCommand('copy')?res():rej()}catch(ex){rej(ex)}
    document.body.removeChild(e)});
}
function copy(id,txt,btn){
  doCopy((txt||document.querySelector('#'+id+' .cv').textContent).trim())
    .then(()=>flash(id,btn)).catch(()=>flash(id,btn));
}
function flash(id,btn){
  document.getElementById(id)?.classList.add('flash');
  const o=btn.textContent;btn.textContent='✓ Скопировано';btn.classList.add('ok');
  setTimeout(()=>{document.getElementById(id)?.classList.remove('flash');
    btn.textContent=o;btn.classList.remove('ok');},2000);
}
loadStats();setInterval(loadStats,30000);

function loadSystem(){
  fetch('/api/system').then(r=>r.json()).then(d=>{
    const bs=document.getElementById('bot-status');
    const ps=document.getElementById('px-status');
    const rs=document.getElementById('routing-status');
    const ron=document.getElementById('routing-on');
    const rof=document.getElementById('routing-off');
    if(bs){
      bs.innerHTML=d.bot
        ? '<span class="st-dot st-on"></span> Работает'
        : '<span class="st-dot st-off"></span> Остановлен';
      document.getElementById('bot-start').disabled=d.bot;
      document.getElementById('bot-stop').disabled=!d.bot;
    }
    if(ps){
      if(!d.proxmox_host){
        ps.innerHTML='<span class="st-dot st-unknown"></span> IP не настроен';
      } else {
        ps.innerHTML=d.proxmox
          ? '<span class="st-dot st-on"></span> Онлайн'
          : '<span class="st-dot st-off"></span> Недоступен';
      }
    }
    if(rs){
      rs.innerHTML=d.routing==='split'
        ? '<span class="st-dot st-on"></span> Включены'
        : '<span class="st-dot st-off"></span> Выключены';
      if(ron) ron.disabled=d.routing==='split';
      if(rof) rof.disabled=d.routing==='full';
    }
  }).catch(()=>{});
}

function setRouting(mode){
  fetch('/api/routing/set',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({mode:mode})})
    .then(r=>r.json()).then(()=>loadSystem()).catch(()=>loadSystem());
}

function botAction(action){
  const btn=document.getElementById(action==='start'?'bot-start':'bot-stop');
  btn.disabled=true;
  fetch('/api/bot/'+action,{method:'POST'})
    .then(r=>r.json()).then(()=>setTimeout(loadSystem,1000))
    .catch(()=>setTimeout(loadSystem,1000));
}

function pxShutdown(){
  if(!confirm('Выключить домашний Proxmox сервер?')) return;
  const btn=document.querySelector('.sys-btn-danger');
  btn.disabled=true; btn.textContent='Выключение...';
  fetch('/api/proxmox/shutdown',{method:'POST'})
    .then(r=>r.json())
    .then(d=>{
      if(d.result==='ok'){btn.textContent='✓ Команда отправлена';}
      else{btn.disabled=false;btn.textContent='⏻ Выключить';alert('Ошибка: '+d.result);}
      setTimeout(loadSystem,3000);
    }).catch(()=>{btn.disabled=false;btn.textContent='⏻ Выключить'});
}

if(document.getElementById('sys-card')){loadSystem();setInterval(loadSystem,10000);}
"""

# ── user personal page ────────────────────────────────────────────────────────
def user_page(user: dict) -> str:
    token = user["token"]
    uid   = user["uuid"]
    email = user["email"]
    label = user["label"]
    sub_url = f"http://{SERVER_IP}/sub/{token}"
    return f"""<!DOCTYPE html>
<html lang="ru"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MyVPN</title><style>{CSS}</style></head>
<body>
<input type="hidden" id="user-email" value="{email}">
<div class="wrap">
  <div>
    <div class="badge"><span class="dot"></span> Сервер активен</div>
    <h1>MyVPN</h1>
    <p class="sub">Привет, {label}!</p>
  </div>

  <div class="card">
    <div class="card-head">
      <div class="icon icon-stat">📊</div>
      <div><div class="card-title">Твой трафик</div></div>
    </div>
    <div class="tblock" id="user-stats"><div style="color:var(--m);font-size:.85rem">Загрузка...</div></div>
    <div class="tblock" id="srv-stats" style="border-top:1px solid var(--br)"><div style="color:var(--m);font-size:.85rem">Загрузка...</div></div>
    <div class="refresh-area"><span id="last-upd">—</span><button class="rbtn" onclick="loadStats()">↻ Обновить</button></div>
  </div>

  <div class="card">
    <div class="card-head">
      <div class="icon icon-happ">📱</div>
      <div><div class="card-title">HAPP</div>
        <div><span class="ptag">Android</span><span class="ptag">iOS</span></div></div>
    </div>
    <div class="card-body">
      <div>
        <div class="flabel">Ссылка подписки</div>
        <div class="crow" id="r-happ">
          <span class="cv">{sub_url}</span>
          <button class="cb" onclick="copy('r-happ','{sub_url}',this)">Копировать</button>
        </div>
      </div>
      <hr class="divider">
      <div>
        <div class="flabel">VLESS ссылка (ручная, порт 2053)</div>
        <div class="crow" id="r-vless-happ">
          <span class="cv">{vless_link(uid, flow=False, port=PORT_HAPP)}</span>
          <button class="cb" onclick="copy('r-vless-happ',null,this)">Копировать</button>
        </div>
      </div>
    </div>
      <hr class="divider">
      <div>
        <div class="flabel">QR-код для HAPP</div>
        <div class="qr-wrap">
          <img src="data:image/png;base64,{make_qr_b64(sub_url)}" alt="QR" width="180" height="180">
          <p class="qr-hint">Открой HAPP → Добавить сервер → Сканировать QR</p>
        </div>
      </div>
    </div>
    <div class="dllabel">Скачать HAPP</div>
    <div class="dlrow">
      <a class="dlbtn" href="{DL_HAPP['android']}" target="_blank">🤖 Android</a>
      <a class="dlbtn" href="{DL_HAPP['ios']}" target="_blank">🍎 iOS</a>
    </div>
  </div>

  <div class="card">
    <div class="card-head">
      <div class="icon icon-clash">⚡</div>
      <div><div class="card-title">Koala Clash</div>
        <div><span class="ptag">Windows</span><span class="ptag">macOS</span><span class="ptag">Linux</span></div></div>
    </div>
    <div class="card-body">
      <div>
        <div class="flabel">Ссылка подписки (Clash YAML)</div>
        <div class="crow" id="r-clash">
          <span class="cv">http://{SERVER_IP}/sub/clash/{token}</span>
          <button class="cb" onclick="copy('r-clash','http://{SERVER_IP}/sub/clash/{token}',this)">Копировать</button>
        </div>
      </div>
      <hr class="divider">
      <div>
        <div class="flabel">VLESS ссылка (ручная, порт 443)</div>
        <div class="crow" id="r-vless-clash">
          <span class="cv">{vless_link(uid, flow=True, port=PORT_VLESS)}</span>
          <button class="cb" onclick="copy('r-vless-clash',null,this)">Копировать</button>
        </div>
      </div>
    </div>
    <div class="dllabel">Скачать Koala Clash</div>
    <div class="dlrow">
      <a class="dlbtn" href="{DL_CLASH['win']}" target="_blank">🪟 Windows</a>
      <a class="dlbtn" href="{DL_CLASH['mac']}" target="_blank">🍎 macOS</a>
      <a class="dlbtn" href="{DL_CLASH['linux']}" target="_blank">🐧 Linux</a>
    </div>
  </div>
</div>
<script>{JS}
// Override loadStats for user page — use public endpoint
(function(){{
  const TOKEN="{token}";
  loadStats=function(){{
    fetch('/api/user-stats/'+TOKEN).then(r=>r.json()).then(function(d){{
      const LIMIT=d.limit||3*1024*1024*1024*1024;
      const up=parseInt(d.uplink)||0,dn=parseInt(d.downlink)||0,t=up+dn;
      const tot=parseInt(d.total_server)||0;
      // user block
      const el=document.getElementById('user-stats');
      if(el){{
        const pct=Math.min(100,t/LIMIT*100);
        const col=pct>85?'#f87171':pct>60?'#fb923c':'#34d399';
        el.innerHTML=`<div class="trow"><span class="tlabel">Твой расход</span>
          <span class="tval"><b style="color:var(--t)">${{fmt(t)}}</b> <span style="color:var(--m)">из 3 ТБ</span></span></div>
          <div class="track"><div class="fill" style="width:${{pct.toFixed(1)}}%;background:${{col}}"></div></div>
          <div class="tmeta"><span>↑ <b style="color:#34d399">${{fmt(up)}}</b> &nbsp; ↓ <b style="color:#60a5fa">${{fmt(dn)}}</b></span>
          <span style="color:var(--m)">${{pct.toFixed(1)}}%</span></div>`;
      }}
      // server block
      const srv=document.getElementById('srv-stats');
      if(srv){{
        const p2=Math.min(100,tot/LIMIT*100);
        const c2=p2>85?'#f87171':p2>60?'#fb923c':'#34d399';
        srv.innerHTML=`<div class="trow"><span class="tlabel">Всего на сервере</span>
          <span class="tval"><b style="color:var(--t)">${{fmt(tot)}}</b> <span style="color:var(--m)">из 3 ТБ</span></span></div>
          <div class="track"><div class="fill" style="width:${{p2.toFixed(1)}}%;background:${{c2}}"></div></div>
          <div class="tmeta"><span style="color:${{c2}}">${{p2.toFixed(1)}}% использовано</span>
          <span style="color:var(--m)">Осталось: ${{fmt(LIMIT-tot)}}</span></div>`;
      }}
      document.getElementById('last-upd').textContent='Обновлено: '+new Date().toLocaleTimeString('ru-RU');
    }}).catch(()=>{{}});
  }};
  loadStats();setInterval(loadStats,30000);
}})();
</script>
</body></html>"""

# ── admin page ────────────────────────────────────────────────────────────────
def admin_page() -> str:
    return f"""<!DOCTYPE html>
<html lang="ru"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MyVPN — Admin</title><style>{CSS}
.logout{{font-size:.75rem;color:var(--m);text-decoration:none;border:1px solid var(--br);
  border-radius:6px;padding:4px 10px;transition:all .15s}}
.logout:hover{{border-color:var(--r);color:var(--r)}}
</style></head>
<body>
<div class="wrap">
  <div style="display:flex;align-items:flex-start;justify-content:space-between">
    <div>
      <div class="badge"><span class="dot"></span> Сервер активен</div>
      <h1>MyVPN Admin</h1>
      <p class="sub">Дмитрий Орлов</p>
    </div>
    <a href="/logout" class="logout">Выйти</a>
  </div>

  <div class="strip">
    <div class="si2"><div class="sl2">IP сервера</div><div class="sv2">{SERVER_IP}</div></div>
    <div class="si2"><div class="sl2">Протокол</div><div class="sv2">VLESS+Reality</div></div>
    <div class="si2"><div class="sl2">Порт</div><div class="sv2">{PORT_VLESS}</div></div>
  </div>

  <!-- System controls -->
  <div class="card" id="sys-card">
    <div class="card-head">
      <div class="icon icon-stat">⚙️</div>
      <div><div class="card-title">Управление системой</div>
        <div class="card-sub">Бот и домашний сервер</div></div>
    </div>
    <div class="card-body" style="gap:14px">

      <!-- Bot -->
      <div class="sys-row">
        <div class="sys-info">
          <div class="sys-name">🤖 Telegram Бот</div>
          <div class="sys-status" id="bot-status"><span class="st-dot st-unknown"></span> Загрузка...</div>
        </div>
        <div class="sys-btns">
          <button class="sys-btn sys-btn-on"  id="bot-start" onclick="botAction('start')">▶ Вкл</button>
          <button class="sys-btn sys-btn-off" id="bot-stop"  onclick="botAction('stop')">■ Выкл</button>
        </div>
      </div>

      <hr class="divider">

      <!-- Routing mode -->
      <div class="sys-row">
        <div class="sys-info">
          <div class="sys-name">🌐 Белые списки</div>
          <div class="sys-status" id="routing-status"><span class="st-dot st-unknown"></span> Загрузка...</div>
        </div>
        <div class="sys-btns">
          <button class="sys-btn sys-btn-on"  id="routing-on"  onclick="setRouting('split')">▶ Вкл</button>
          <button class="sys-btn sys-btn-off" id="routing-off" onclick="setRouting('full')">■ Выкл</button>
        </div>
      </div>

      <hr class="divider">

      <!-- Proxmox -->
      <div class="sys-row">
        <div class="sys-info">
          <div class="sys-name">🖥 Proxmox (домашний)</div>
          <div class="sys-status" id="px-status"><span class="st-dot st-unknown"></span> Загрузка...</div>
        </div>
        <div class="sys-btns">
          <button class="sys-btn sys-btn-danger" onclick="pxShutdown()">⏻ Выключить</button>
        </div>
      </div>

    </div>
  </div>

  <div class="card">
    <div class="card-head">
      <div class="icon icon-stat">📊</div>
      <div><div class="card-title">Трафик пользователей</div>
        <div class="card-sub">3 ТБ в месяц · включая отозванных</div></div>
      <button class="rbtn" style="margin-left:auto" onclick="loadStats()">↻</button>
    </div>
    <div class="tblock" id="srv-stats"><div style="color:var(--m);font-size:.85rem">Загрузка...</div></div>
    <div id="all-users"></div>
    <div class="refresh-area"><span id="last-upd">—</span></div>
  </div>

  <div class="card">
    <div class="card-head">
      <div class="icon icon-clash">⚡</div>
      <div><div class="card-title">Koala Clash</div>
        <div><span class="ptag">Windows</span><span class="ptag">macOS</span><span class="ptag">Linux</span></div></div>
    </div>
    <div class="card-body">
      <div>
        <div class="flabel">Clash YAML</div>
        <div class="crow" id="r-clash">
          <span class="cv">http://{SERVER_IP}/sub/clash/user1</span>
          <button class="cb" onclick="copy('r-clash','http://{SERVER_IP}/sub/clash/user1',this)">Копировать</button>
        </div>
      </div>
      <hr class="divider">
      <div>
        <div class="flabel">VLESS ссылка</div>
        <div class="crow" id="r-vless">
          <span class="cv">{vless_link()}</span>
          <button class="cb" onclick="copy('r-vless',null,this)">Копировать</button>
        </div>
      </div>
    </div>
    <div class="dllabel">Скачать</div>
    <div class="dlrow">
      <a class="dlbtn" href="{DL_CLASH['win']}" target="_blank">🪟 Windows</a>
      <a class="dlbtn" href="{DL_CLASH['mac']}" target="_blank">🍎 macOS</a>
      <a class="dlbtn" href="{DL_CLASH['linux']}" target="_blank">🐧 Linux</a>
    </div>
  </div>

  <div class="card">
    <div class="card-head">
      <div class="icon icon-happ">📱</div>
      <div><div class="card-title">HAPP</div>
        <div><span class="ptag">Android</span><span class="ptag">iOS</span></div></div>
    </div>
    <div class="card-body">
      <div>
        <div class="flabel">Ссылка подписки</div>
        <div class="crow" id="r-happ">
          <span class="cv">http://{SERVER_IP}/sub/user1</span>
          <button class="cb" onclick="copy('r-happ','http://{SERVER_IP}/sub/user1',this)">Копировать</button>
        </div>
      </div>
    </div>
    <div class="dllabel">Скачать</div>
    <div class="dlrow">
      <a class="dlbtn" href="{DL_HAPP['android']}" target="_blank">🤖 Android</a>
      <a class="dlbtn" href="{DL_HAPP['ios']}" target="_blank">🍎 iOS</a>
    </div>
  </div>

  <a href="http://{SERVER_IP}:8006" target="_blank" class="pxbtn">
    <svg width="28" height="28" viewBox="0 0 120 120" fill="none">
      <rect width="120" height="120" rx="24" fill="#E57000"/>
      <path d="M28 38h28l-8 14h16l-36 30 10-20H22l6-24z" fill="white"/>
      <path d="M64 38h28l-6 24H70l-10 20-4-7 14-13H56l8-24z" fill="white" opacity=".85"/>
    </svg>
    <div class="pxtxt">
      <span class="pxname">Proxmox VE</span>
      <span class="pxsub">Открыть панель управления →</span>
    </div>
    <div class="pxport">:8006</div>
  </a>
</div>
<script>{JS}</script></body></html>"""

# ── HTTP handler ──────────────────────────────────────────────────────────────
def get_system_status() -> dict:
    # Bot
    bot = subprocess.run(["systemctl", "is-active", "vpnbot"],
                         capture_output=True, text=True).stdout.strip()
    # Proxmox — TCP check on port 8006
    px_up = False
    if PROXMOX_HOST:
        import socket
        try:
            s = socket.create_connection((PROXMOX_HOST, 8006), timeout=3)
            s.close(); px_up = True
        except Exception:
            px_up = False
    return {"bot": bot == "active", "proxmox": px_up,
            "proxmox_host": PROXMOX_HOST, "routing": get_routing_mode()}

def bot_control(action: str) -> bool:
    cmd = "start" if action == "start" else "stop"
    r = subprocess.run(["systemctl", cmd, "vpnbot"], capture_output=True)
    return r.returncode == 0

def proxmox_shutdown() -> str:
    if not PROXMOX_HOST:
        return "PROXMOX_HOST не настроен"
    try:
        r = subprocess.run(
            ["ssh", "-i", PROXMOX_SSH_KEY,
             "-p", str(PROXMOX_SSH_PORT),
             "-o", "StrictHostKeyChecking=no",
             "-o", "ConnectTimeout=5",
             f"{PROXMOX_SSH_USER}@{PROXMOX_HOST}",
             PROXMOX_SHUTDOWN_CMD],
            capture_output=True, text=True, timeout=10
        )
        return "ok" if r.returncode == 0 else r.stderr.strip()
    except Exception as e:
        return str(e)

def is_browser(ua: str) -> bool:
    ua = ua.lower()
    # Known subscription client identifiers — never HTML
    if any(k in ua for k in ("clash", "sing-box", "happ", "hiddify", "v2ray", "xray",
                              "okhttp", "go-http-client", "python-requests", "curl", "wget",
                              "shadowrocket", "streisand", "quantumult", "dalvik")):
        return False
    # Any real browser (desktop or mobile) has Mozilla in UA
    return "mozilla" in ua

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass

    def cookies(self):
        return self.headers.get("Cookie", "")

    def redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def html(self, body: str, status=200):
        b = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def sub_response(self, data: bytes, ul: int, dl: int, token: str = "",
                     content_type: str = "text/plain", filename: str = "myvpn"):
        page_url = f"http://{SERVER_IP}/sub/{token}" if token else f"http://{SERVER_IP}"
        title_b64 = base64.b64encode(REMARK.encode()).decode()
        self.send_response(200)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("subscription-userinfo",
                         f"upload={ul}; download={dl}; total={TOTAL_LIMIT}")
        self.send_header("profile-title",         f"base64:{title_b64}")
        self.send_header("profile-web-page-url",  page_url)
        self.send_header("profile-update-interval", "24")
        self.send_header("support-url",           page_url)
        self.send_header("update-always",         "true")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?")[0]
        ua   = self.headers.get("User-Agent", "")

        # ── login page ──
        if path == "/login":
            self.html(LOGIN_HTML.replace("WRONG_MSG", ""))
            return

        # ── logout ──
        if path == "/logout":
            self.send_response(302)
            self.send_header("Location", "/login")
            self.send_header("Set-Cookie", "session=; Max-Age=0; Path=/")
            self.end_headers()
            return

        # ── public user stats (no auth) ──
        if path.startswith("/api/user-stats/"):
            token = path[len("/api/user-stats/"):]
            user  = find_user(token)
            if not user:
                self.send_response(404); self.end_headers(); return
            raw = get_stats()
            all_ul = sum(v.get("uplink", 0)   for v in raw.values())
            all_dl = sum(v.get("downlink", 0) for v in raw.values())
            email = user["email"]
            s1 = raw.get(email, {})
            s2 = raw.get(email + "_happ", {})
            resp = json.dumps({
                "uplink":        s1.get("uplink", 0)   + s2.get("uplink", 0),
                "downlink":      s1.get("downlink", 0) + s2.get("downlink", 0),
                "total_server":  all_ul + all_dl,
                "limit":         TOTAL_LIMIT,
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(resp)
            return

        # ── admin pages (require auth) ──
        if path in ("/", "/index.html") or path.startswith("/api/"):
            if not is_authenticated(self.cookies()):
                self.redirect("/login")
                return

            if path == "/api/system":
                resp = json.dumps(get_system_status()).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(resp)
                return

            if path == "/api/stats":
                raw = get_stats()
                users_out = []
                for u in all_users_for_stats():
                    s = raw.get(u["email"], {})
                    users_out.append({
                        "email":    u["email"],
                        "label":    u["label"],
                        "approved": u.get("approved", True),
                        "uplink":   s.get("uplink", 0),
                        "downlink": s.get("downlink", 0),
                    })
                resp = json.dumps({"users": users_out}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(resp)
                return

            self.html(admin_page())
            return

        # ── clash sub ──
        if path.startswith("/sub/clash/"):
            token = path[len("/sub/clash/"):]
            user  = find_user(token)
            if not user:
                self.send_response(404); self.end_headers(); return
            email = user.get("email", "myvpn")
            stats = get_stats()
            all_ul = sum(v.get("uplink", 0)   for v in stats.values())
            all_dl = sum(v.get("downlink", 0) for v in stats.values())
            data = clash_yaml(user["uuid"]).encode()
            self.sub_response(data, all_ul, all_dl,
                              token, content_type="text/yaml", filename=email)
            return

        # ── user sub / personal page ──
        if path.startswith("/sub/"):
            token = path[len("/sub/"):]
            user  = find_user(token)
            if not user:
                self.html("<h2 style='font-family:sans-serif;color:#f87171;padding:40px'>Ссылка недействительна или доступ отозван.</h2>", 404)
                return
            email = user.get("email", "myvpn")
            if is_browser(ua):
                self.html(user_page(user))
            else:
                stats = get_stats()
                all_ul = sum(v.get("uplink", 0)   for v in stats.values())
                all_dl = sum(v.get("downlink", 0) for v in stats.values())
                data = v2ray_sub(user["uuid"]).encode()
                self.sub_response(data, all_ul, all_dl, token, filename=email)
            return

        self.send_response(404); self.end_headers()
        self.wfile.write(b"Not found")

    def do_POST(self):
        if self.path.startswith("/api/") and not is_authenticated(self.cookies()):
            self.send_response(401); self.end_headers(); return

        if self.path == "/api/routing/set":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length).decode())
            mode = body.get("mode", "full")
            if mode in ("full", "split"):
                set_routing_mode(mode)
            self.send_response(200); self.send_header("Content-Type","application/json"); self.end_headers()
            self.wfile.write(json.dumps({"mode": get_routing_mode()}).encode()); return

        if self.path == "/api/bot/start":
            ok = bot_control("start")
            self.send_response(200); self.send_header("Content-Type","application/json"); self.end_headers()
            self.wfile.write(json.dumps({"ok": ok}).encode()); return

        if self.path == "/api/bot/stop":
            ok = bot_control("stop")
            self.send_response(200); self.send_header("Content-Type","application/json"); self.end_headers()
            self.wfile.write(json.dumps({"ok": ok}).encode()); return

        if self.path == "/api/proxmox/shutdown":
            result = proxmox_shutdown()
            self.send_response(200); self.send_header("Content-Type","application/json"); self.end_headers()
            self.wfile.write(json.dumps({"result": result}).encode()); return

        if self.path == "/login":
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length).decode()
            params = dict(p.split("=", 1) for p in body.split("&") if "=" in p)
            pwd    = urllib.parse.unquote_plus(params.get("password", ""))
            if pwd == ADMIN_PASSWORD:
                self.send_response(302)
                self.send_header("Location", "/")
                self.send_header("Set-Cookie",
                    f"session={SESSION_TOKEN}; Path=/; HttpOnly; SameSite=Strict")
                self.end_headers()
            else:
                self.html(LOGIN_HTML.replace(
                    'class="err" id="err"',
                    'class="err show" id="err"'
                ).replace("WRONG_MSG", "Неверный пароль"), 401)
            return
        self.send_response(405); self.end_headers()


if __name__ == "__main__":
    _autosave_stats()
    server = HTTPServer(("0.0.0.0", WEB_PORT), Handler)
    print(f"Running on :{WEB_PORT}")
    server.serve_forever()
