#!/usr/bin/env python3
import base64, hashlib, hmac, json, os, secrets, time, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime, timedelta
from pathlib import Path
from dotenv import load_dotenv

load_dotenv("/opt/vpnserver/.env")

# ── config ────────────────────────────────────────────────────────────────────
BOT_TOKEN = os.getenv("REMIND_BOT_TOKEN", "")
BOT_USERNAME = os.getenv("REMIND_BOT_USERNAME", "RemindMeShockBot")
SESSION_SECRET = os.getenv("SESSION_SECRET") or secrets.token_hex(32)
DOMAIN = os.getenv("REMIND_DOMAIN", "shocknet.online")
WEB_PORT = 5050
PREFIX = "/remind"
USERS_FILE = Path("/opt/remindbot/users.json")
REMINDERS_FILE = Path("/opt/remindbot/reminders.json")
VPN_USERS_FILE = Path("/opt/vpnbot/users.json")
ADMIN_TG_ID = 652872261  # Dmitry_Shock

# ── auth (shared with VPN admin) ─────────────────────────────────────────────
def make_vpn_admin_token() -> str:
    """Same token as VPN subserver for admin."""
    return hmac.new(SESSION_SECRET.encode(), b"admin", hashlib.sha256).hexdigest()

VPN_ADMIN_TOKEN = make_vpn_admin_token()

def make_session_token(tg_id: int) -> str:
    return hmac.new(SESSION_SECRET.encode(), f"remind:{tg_id}".encode(), hashlib.sha256).hexdigest()

def is_authenticated(cookie_header: str) -> int | None:
    if not cookie_header:
        return None
    for part in cookie_header.split(";"):
        k, _, v = part.strip().partition("=")
        if k.strip() == "session":
            token = v.strip()
            # Check VPN admin token
            if token == VPN_ADMIN_TOKEN:
                return ADMIN_TG_ID
            # Check remind-specific tokens
            for uid, tok in load_sessions().items():
                if tok == token:
                    return int(uid)
    return None

def load_sessions() -> dict:
    try:
        return json.loads(USERS_FILE.read_text()).get("sessions", {})
    except Exception:
        return {}

def save_sessions(sessions: dict):
    db = load_db()
    db["sessions"] = sessions
    USERS_FILE.write_text(json.dumps(db, indent=2, ensure_ascii=False))

def load_db() -> dict:
    try:
        return json.loads(USERS_FILE.read_text())
    except Exception:
        return {"admin_id": 0, "users": {}, "sessions": {}}

def save_db(db: dict):
    USERS_FILE.write_text(json.dumps(db, indent=2, ensure_ascii=False))

def verify_telegram_auth(data: dict) -> bool:
    check_hash = data.get("hash", "")
    auth_date = int(data.get("auth_date", 0))
    if abs(time.time() - auth_date) > 86400:
        return False
    fields = {k: v for k, v in data.items() if k != "hash"}
    check_string = "\n".join(f"{k}={v}" for k, v in sorted(fields.items()))
    secret = hashlib.sha256(BOT_TOKEN.encode()).digest()
    computed = hmac.new(secret, check_string.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, check_hash)

# ── reminders ─────────────────────────────────────────────────────────────────
def load_reminders() -> list:
    try:
        return json.loads(REMINDERS_FILE.read_text())
    except Exception:
        return []

def save_reminders(reminders: list):
    REMINDERS_FILE.write_text(json.dumps(reminders, indent=2, ensure_ascii=False))

def add_reminder(tg_id: int, text: str, remind_at: str) -> dict:
    reminders = load_reminders()
    r = {
        "id": secrets.token_hex(8),
        "tg_id": tg_id,
        "text": text,
        "remind_at": remind_at,
        "created_at": datetime.now().isoformat(),
        "sent": False,
    }
    reminders.append(r)
    save_reminders(reminders)
    return r

def delete_reminder(rid: str, tg_id: int) -> bool:
    reminders = load_reminders()
    before = len(reminders)
    reminders = [r for r in reminders if not (r["id"] == rid and r["tg_id"] == tg_id)]
    save_reminders(reminders)
    return len(reminders) < before

def update_reminder(rid: str, tg_id: int, text: str, remind_at: str) -> bool:
    reminders = load_reminders()
    for r in reminders:
        if r["id"] == rid and r["tg_id"] == tg_id:
            r["text"] = text
            r["remind_at"] = remind_at
            save_reminders(reminders)
            return True
    return False

def get_pending_reminders() -> list:
    now = datetime.now()
    reminders = load_reminders()
    pending = []
    for r in reminders:
        if r["sent"]:
            continue
        try:
            rt = datetime.fromisoformat(r["remind_at"])
            if rt <= now:
                pending.append(r)
        except Exception:
            pass
    return pending

def mark_sent(rid: str):
    reminders = load_reminders()
    for r in reminders:
        if r["id"] == rid:
            r["sent"] = True
    save_reminders(reminders)

# ── CSS / HTML ────────────────────────────────────────────────────────────────
CSS = """
:root{--bg:#0d0d12;--s:#16161f;--s2:#1e1e2a;--br:rgba(255,255,255,0.07);
  --p:#a78bfa;--g:#34d399;--r:#f87171;--t:#e2e8f0;--m:#64748b;--o:#fb923c}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--t);font-family:-apple-system,'Segoe UI',sans-serif;
  min-height:100vh;padding:32px 16px 60px}
.wrap{max-width:680px;margin:0 auto;display:flex;flex-direction:column;gap:16px}
h1{font-size:1.9rem;font-weight:700;
  background:linear-gradient(135deg,#e2e8f0,var(--o));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:4px}
.sub{color:var(--m);font-size:.9rem}
.badge{display:inline-flex;align-items:center;gap:6px;background:rgba(251,146,60,.1);
  border:1px solid rgba(251,146,60,.25);border-radius:100px;padding:5px 12px;
  font-size:.72rem;color:var(--o);text-transform:uppercase;letter-spacing:.05em;margin-bottom:16px}
.dot{width:6px;height:6px;border-radius:50%;background:var(--g);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.card{background:var(--s);border:1px solid var(--br);border-radius:16px;overflow:hidden}
.card:hover{border-color:rgba(251,146,60,.25)}
.card-head{display:flex;align-items:center;gap:14px;padding:20px;border-bottom:1px solid var(--br)}
.icon{width:46px;height:46px;border-radius:12px;display:flex;align-items:center;
  justify-content:center;font-size:1.4rem;flex-shrink:0}
.icon-remind{background:linear-gradient(135deg,#f59e0b,#ea580c)}
.icon-add{background:linear-gradient(135deg,#34d399,#059669)}
.card-title{font-size:1rem;font-weight:700}
.card-sub{font-size:.75rem;color:var(--m);margin-top:2px}
.card-body{padding:16px 20px;display:flex;flex-direction:column;gap:12px}
.form-group{display:flex;flex-direction:column;gap:6px}
.form-label{font-size:.72rem;color:var(--m);text-transform:uppercase;letter-spacing:.05em}
.form-input{background:var(--s2);border:1px solid var(--br);border-radius:8px;padding:10px 14px;
  color:var(--t);font-size:.9rem;outline:none;transition:border-color .15s}
.form-input:focus{border-color:var(--o)}
textarea.form-input{min-height:80px;resize:vertical;font-family:inherit}
.btn{border:none;border-radius:10px;padding:12px 24px;font-size:.9rem;font-weight:600;
  cursor:pointer;transition:all .15s;display:inline-flex;align-items:center;gap:8px}
.btn-primary{background:linear-gradient(135deg,#f59e0b,#ea580c);color:#fff}
.btn-primary:hover{opacity:.85}
.btn-danger{background:rgba(239,68,68,.15);border:1px solid rgba(239,68,68,.4);color:#ef4444}
.btn-danger:hover{background:rgba(239,68,68,.25)}
.btn-ghost{background:transparent;border:1px solid var(--br);color:var(--m)}
.btn-ghost:hover{border-color:var(--o);color:var(--o)}
.remind-item{background:var(--s2);border:1px solid var(--br);border-radius:12px;
  padding:16px;display:flex;flex-direction:column;gap:10px;transition:border-color .15s}
.remind-item:hover{border-color:rgba(251,146,60,.25)}
.remind-item.sent{opacity:.5}
.remind-text{font-size:.95rem;line-height:1.5}
.remind-meta{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.remind-time{font-size:.78rem;color:var(--o);font-family:monospace;
  background:rgba(251,146,60,.1);border:1px solid rgba(251,146,60,.2);
  border-radius:6px;padding:3px 8px}
.remind-status{font-size:.72rem;color:var(--m)}
.remind-status.done{color:var(--g)}
.remind-actions{display:flex;gap:8px;margin-left:auto}
.remind-btn{background:none;border:1px solid var(--br);border-radius:6px;
  color:var(--m);padding:4px 10px;font-size:.72rem;cursor:pointer;transition:all .15s}
.remind-btn:hover{border-color:var(--p);color:var(--p)}
.remind-btn.del:hover{border-color:var(--r);color:var(--r)}
.empty{text-align:center;padding:40px;color:var(--m);font-size:.9rem}
.tg-btn{display:inline-flex;align-items:center;gap:8px;
  background:linear-gradient(135deg,#2AABEE,#229ED9);
  border:none;border-radius:10px;color:#fff;padding:13px 28px;
  font-size:.95rem;font-weight:600;text-decoration:none;transition:opacity .15s}
.tg-btn:hover{opacity:.85}
.hero{text-align:center;padding:60px 20px;position:relative}
.hero::before{content:'';position:absolute;top:-100px;left:50%;transform:translateX(-50%);
  width:500px;height:500px;border-radius:50%;
  background:radial-gradient(circle,rgba(251,146,60,.12) 0%,transparent 70%);pointer-events:none}
h1.hero-title{font-size:clamp(2rem,5vw,3rem);font-weight:800;
  background:linear-gradient(135deg,#fff 30%,var(--o));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:12px}
.hero-sub{color:var(--m);font-size:1.05rem;max-width:420px;margin:0 auto 32px;line-height:1.6}
.logout{font-size:.75rem;color:var(--m);text-decoration:none;border:1px solid var(--br);
  border-radius:6px;padding:4px 10px;transition:all .15s}
.logout:hover{border-color:var(--r);color:var(--r)}
.strip{display:flex;justify-content:center;max-width:560px;margin:0 auto 40px;
  background:var(--s);border:1px solid var(--br);border-radius:16px;overflow:hidden;flex-wrap:wrap}
.si{padding:20px 32px;text-align:center;border-right:1px solid var(--br);flex:1;min-width:120px}
.si:last-child{border-right:none}
.sv{font-size:1.3rem;font-weight:700;color:var(--o);font-family:monospace}
.sl{font-size:.72rem;color:var(--m);text-transform:uppercase;letter-spacing:.06em;margin-top:4px}
footer{border-top:1px solid var(--br);padding:24px 20px;text-align:center;
  color:var(--m);font-size:.78rem;margin-top:40px}
@media(max-width:480px){.si{padding:16px 20px}.remind-actions{margin-left:0;margin-top:8px}}
"""

JS = """
function doDelete(id, btn) {
  if (!confirm('Удалить напоминание?')) return;
  btn.disabled = true;
  fetch('/api/reminders/' + id, {method: 'DELETE'})
    .then(r => r.json())
    .then(d => { if (d.ok) btn.closest('.remind-item').remove(); else btn.disabled = false; })
    .catch(() => btn.disabled = false);
}
function doEdit(id) {
  const item = document.getElementById('r-' + id);
  const textEl = item.querySelector('.remind-text');
  const timeEl = item.querySelector('.remind-time');
  const oldText = textEl.textContent;
  const oldTime = timeEl.textContent;
  item.innerHTML = `
    <textarea class="form-input" id="et-${id}">${oldText}</textarea>
    <input type="datetime-local" class="form-input" id="etm-${id}" value="${oldTime.replace(' ', 'T')}">
    <div style="display:flex;gap:8px">
      <button class="btn btn-primary" style="padding:8px 16px;font-size:.8rem" onclick="doSave('${id}')">Сохранить</button>
      <button class="btn btn-ghost" style="padding:8px 16px;font-size:.8rem" onclick="location.reload()">Отмена</button>
    </div>`;
}
function doSave(id) {
  const text = document.getElementById('et-' + id).value;
  const remind_at = document.getElementById('etm-' + id).value;
  fetch('/api/reminders/' + id, {
    method: 'PUT',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({text, remind_at})
  }).then(r => r.json()).then(d => { if (d.ok) location.reload(); });
}
"""

# ── pages ─────────────────────────────────────────────────────────────────────
def landing_page():
    return f"""<!DOCTYPE html>
<html lang="ru"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RemindMe — Напоминания в Telegram</title>
<style>{CSS}
.hero-btns{{display:flex;gap:12px;justify-content:center;flex-wrap:wrap}}
</style></head>
<body>
<div class="hero">
  <div class="badge"><span class="dot"></span> Бот активен</div>
  <h1 class="hero-title">RemindMe</h1>
  <p class="hero-sub">Никогда больше не забывай важное.<br>Напоминания прямо в Telegram.</p>
  <div class="hero-btns">
    <a href="https://t.me/{BOT_USERNAME}" class="tg-btn">📱 Открыть бота</a>
    <a href="#how" class="btn btn-ghost" style="color:var(--t)">Как работает?</a>
  </div>
</div>

<div class="strip">
  <div class="si"><div class="sv">🔔</div><div class="sl">Напоминания</div></div>
  <div class="si"><div class="sv">📱</div><div class="sl">В Telegram</div></div>
  <div class="si"><div class="sv">⚡</div><div class="sl">Мгновенно</div></div>
</div>

<div class="wrap">
  <div class="card">
    <div class="card-head">
      <div class="icon icon-remind">📋</div>
      <div><div class="card-title">Как подключиться</div></div>
    </div>
    <div class="card-body">
      <div style="display:flex;gap:14px;align-items:flex-start">
        <div style="width:32px;height:32px;border-radius:8px;background:rgba(251,146,60,.15);
          display:flex;align-items:center;justify-content:center;font-weight:800;color:var(--o);flex-shrink:0">1</div>
        <div><b>Напиши боту</b><br><span style="color:var(--m);font-size:.85rem">Открой <a href="https://t.me/{BOT_USERNAME}" style="color:var(--o)">@{BOT_USERNAME}</a> и нажми /start</span></div>
      </div>
      <div style="display:flex;gap:14px;align-items:flex-start">
        <div style="width:32px;height:32px;border-radius:8px;background:rgba(251,146,60,.15);
          display:flex;align-items:center;justify-content:center;font-weight:800;color:var(--o);flex-shrink:0">2</div>
        <div><b>Добавь напоминание</b><br><span style="color:var(--m);font-size:.85rem">Через бота или на сайте — удобнее</span></div>
      </div>
      <div style="display:flex;gap:14px;align-items:flex-start">
        <div style="width:32px;height:32px;border-radius:8px;background:rgba(251,146,60,.15);
          display:flex;align-items:center;justify-content:center;font-weight:800;color:var(--o);flex-shrink:0">3</div>
        <div><b>Получи уведомление</b><br><span style="color:var(--m);font-size:.85rem">Бот пришлёт сообщение в точно указанное время</span></div>
      </div>
    </div>
  </div>
</div>

<footer>RemindMe · {DOMAIN} · Напоминания в Telegram</footer>
</body></html>"""

def dashboard_page(tg_id: int, name: str):
    reminders = [r for r in load_reminders() if r["tg_id"] == tg_id]
    now = datetime.now()
    items = ""
    for r in sorted(reminders, key=lambda x: x["remind_at"], reverse=True):
        status_class = "done" if r["sent"] else ""
        status_text = "✅ Отправлено" if r["sent"] else "⏳ Ожидание"
        try:
            rt = datetime.fromisoformat(r["remind_at"])
            time_str = rt.strftime("%d.%m.%Y %H:%M")
        except Exception:
            time_str = r["remind_at"]
        edit_btn = f'<button class="remind-btn" onclick="doEdit(\'{r["id"]}\')">✏️</button>' if not r["sent"] else ""
        del_id = r["id"]
        items += f"""
        <div class="remind-item {'sent' if r['sent'] else ''}" id="r-{r['id']}">
          <div class="remind-text">{r['text']}</div>
          <div class="remind-meta">
            <span class="remind-time">⏰ {time_str}</span>
            <span class="remind-status {status_class}">{status_text}</span>
            <div class="remind-actions">
              {edit_btn}
              <button class="remind-btn del" onclick="doDelete('{del_id}', this)">🗑</button>
            </div>
          </div>
        </div>"""
    if not reminders:
        items = '<div class="empty">Пока нет напоминаний. Добавь первое!</div>'

    active = sum(1 for r in reminders if not r["sent"])
    done = sum(1 for r in reminders if r["sent"])

    return f"""<!DOCTYPE html>
<html lang="ru"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RemindMe — Панель</title>
<style>{CSS}</style></head>
<body>
<div class="wrap">
  <div style="display:flex;align-items:flex-start;justify-content:space-between">
    <div>
      <div class="badge"><span class="dot"></span> Авторизован</div>
      <h1>RemindMe</h1>
      <p class="sub">Привет, {name}!</p>
    </div>
    <div style="display:flex;gap:8px;align-items:center">
      <a href="https://shocknet.online/" class="logout" style="border-color:rgba(167,139,250,.3);color:var(--p)">🌐 VPN</a>
      <a href="/remind/logout" class="logout">Выйти</a>
    </div>
  </div>

  <div class="strip">
    <div class="si"><div class="sv">{active}</div><div class="sl">Активных</div></div>
    <div class="si"><div class="sv">{done}</div><div class="sl">Выполнено</div></div>
    <div class="si"><div class="sv">{len(reminders)}</div><div class="sl">Всего</div></div>
  </div>

  <div class="card">
    <div class="card-head">
      <div class="icon icon-add">➕</div>
      <div><div class="card-title">Новое напоминание</div></div>
    </div>
    <div class="card-body">
      <form method="POST" action="/api/reminders" style="display:flex;flex-direction:column;gap:12px">
        <div class="form-group">
          <label class="form-label">Текст напоминания</label>
          <textarea name="text" class="form-input" placeholder="Не забуть купить молоко..." required></textarea>
        </div>
        <div class="form-group">
          <label class="form-label">Когда напомнить</label>
          <input type="datetime-local" name="remind_at" class="form-input" required>
        </div>
        <button type="submit" class="btn btn-primary" style="align-self:flex-start">🔔 Добавить</button>
      </form>
    </div>
  </div>

  <div class="card">
    <div class="card-head">
      <div class="icon icon-remind">📋</div>
      <div><div class="card-title">Мои напоминания</div>
        <div class="card-sub">{len(reminders)} шт.</div></div>
    </div>
    <div class="card-body" style="gap:10px">
      {items}
    </div>
  </div>
</div>
<script>{JS}</script>
</body></html>"""

def login_page(error: str = ""):
    err_html = f'<div style="color:var(--r);font-size:.8rem;margin-top:16px">{error}</div>' if error else ""
    return f"""<!DOCTYPE html>
<html lang="ru"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RemindMe — Вход</title>
<style>{CSS}
.box{{background:var(--s);border:1px solid var(--br);border-radius:20px;
  padding:40px;width:100%;max-width:360px;text-align:center;margin:80px auto}}
h2{{font-size:1.5rem;font-weight:700;margin-bottom:6px;
  background:linear-gradient(135deg,#e2e8f0,var(--o));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent}}
.sub{{color:var(--m);font-size:.85rem;margin-bottom:32px}}
.tg-wrap{{display:flex;justify-content:center}}
</style></head>
<body>
<div class="box">
  <h2>RemindMe</h2>
  <p class="sub">Войдите через Telegram</p>
  <div class="tg-wrap">
    <script async src="https://telegram.org/js/telegram-widget.js?22"
      data-telegram-login="{BOT_USERNAME}"
      data-size="large"
      data-auth-url="https://{DOMAIN}/remind/tg-auth"
      data-request-access="write"></script>
  </div>
  {err_html}
</div>
</body></html>"""

# ── HTTP handler ──────────────────────────────────────────────────────────────
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

    def json_response(self, data, status=200):
        b = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        path = self.path.split("?")[0]
        # Strip /remind prefix for subpath routing
        if path.startswith("/remind"):
            path = path[7:] or "/"
        tg_id = is_authenticated(self.cookies())

        # ── login ──
        if path == "/login":
            self.html(login_page())
            return

        # ── telegram auth callback ──
        if path == "/tg-auth":
            qs = urllib.parse.parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
            data = {k: v[0] for k, v in qs.items()}
            tg_id_auth = int(data.get("id", 0))
            if verify_telegram_auth(data) and tg_id_auth:
                # If this is the VPN admin, use VPN admin token
                if tg_id_auth == ADMIN_TG_ID:
                    token = VPN_ADMIN_TOKEN
                else:
                    sessions = load_sessions()
                    token = make_session_token(tg_id_auth)
                    sessions[str(tg_id_auth)] = token
                    save_sessions(sessions)
                # save user info
                db = load_db()
                if str(tg_id_auth) not in db.get("users", {}):
                    db.setdefault("users", {})[str(tg_id_auth)] = {
                        "name": data.get("first_name", ""),
                        "username": data.get("username", ""),
                    }
                    save_db(db)
                self.send_response(302)
                self.send_header("Location", "/remind/dashboard")
                self.send_header("Set-Cookie",
                    f"session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000")
                self.end_headers()
            else:
                self.html(login_page("Доступ запрещён"))
            return

        # ── logout ──
        if path in ("/logout", "/remind/logout"):
            self.send_response(302)
            self.send_header("Location", "/remind")
            self.send_header("Set-Cookie", "session=; Max-Age=0; Path=/")
            self.end_headers()
            return

        # ── dashboard ──
        if path in ("/dashboard", "/dashboard/"):
            if not tg_id:
                self.redirect("/remind/login")
                return
            db = load_db()
            user = db.get("users", {}).get(str(tg_id), {})
            name = user.get("name", "Пользователь")
            # Use admin name for VPN admin
            if tg_id == ADMIN_TG_ID:
                name = "Дмитрий Орлов"
            self.html(dashboard_page(tg_id, name))
            return

        # ── landing ──
        if path in ("/", "/index.html"):
            if tg_id:
                self.redirect("/remind/dashboard")
            else:
                self.html(landing_page())
            return

        self.send_response(404); self.end_headers()

    def do_POST(self):
        path = self.path.split("?")[0]
        if path.startswith("/remind"):
            path = path[7:] or "/"
        tg_id = is_authenticated(self.cookies())
        if not tg_id:
            self.json_response({"error": "unauthorized"}, 401)
            return

        if path == "/api/reminders":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode()
            data = urllib.parse.parse_qs(body)
            text = data.get("text", [""])[0]
            remind_at = data.get("remind_at", [""])[0]
            if text and remind_at:
                # convert datetime-local to ISO
                try:
                    dt = datetime.strptime(remind_at, "%Y-%m-%dT%H:%M")
                    remind_at = dt.isoformat()
                except Exception:
                    pass
                add_reminder(tg_id, text, remind_at)
            self.redirect("/remind/dashboard")
            return

        self.send_response(405); self.end_headers()

    def do_PUT(self):
        path = self.path.split("?")[0]
        if path.startswith("/remind"):
            path = path[7:] or "/"
        tg_id = is_authenticated(self.cookies())
        if not tg_id:
            self.json_response({"error": "unauthorized"}, 401)
            return

        if path.startswith("/api/reminders/"):
            rid = path[len("/api/reminders/"):]
            length = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(length))
            text = data.get("text", "")
            remind_at = data.get("remind_at", "")
            if remind_at:
                try:
                    dt = datetime.strptime(remind_at, "%Y-%m-%dT%H:%M")
                    remind_at = dt.isoformat()
                except Exception:
                    pass
            ok = update_reminder(rid, tg_id, text, remind_at)
            self.json_response({"ok": ok})
            return

        self.send_response(405); self.end_headers()

    def do_DELETE(self):
        path = self.path.split("?")[0]
        if path.startswith("/remind"):
            path = path[7:] or "/"
        tg_id = is_authenticated(self.cookies())
        if not tg_id:
            self.json_response({"error": "unauthorized"}, 401)
            return

        if path.startswith("/api/reminders/"):
            rid = path[len("/api/reminders/"):]
            ok = delete_reminder(rid, tg_id)
            self.json_response({"ok": ok})
            return

        self.send_response(405); self.end_headers()


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", WEB_PORT), Handler)
    print(f"RemindBot running on :{WEB_PORT}")
    server.serve_forever()
