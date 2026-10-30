"""PSW Lead & Task Tracker server.

FastAPI + SQLite, following Dave's database plan:
- the browser talks only to this API; the app listens on 127.0.0.1 behind Caddy (HTTPS)
- core records: users and sessions (/api/auth/)
- tracker module: leads, contacts, tasks and PDF files (/api/tracker/), switchable via PSW_MODULES
- secrets live in .env next to this file, never in the code
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response

BASE = Path(__file__).resolve().parent
STATIC = BASE / "static"


def load_env():
    f = BASE / ".env"
    if f.exists():
        for line in f.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


load_env()
DATA = Path(os.environ.get("PSW_DATA", "/var/lib/psw-tracker"))
# who gets Payment Yes when that column is first added (by user name or first name); Admin changes it after that
PAY_PEOPLE = {x.strip().lower() for x in os.environ.get("PSW_PAYMENT_PEOPLE", "alex,anna,patricia").split(",") if x.strip()}
DB_PATH = DATA / "tracker.db"
BLOBS = DATA / "blobs"
MODULES = {m.strip() for m in os.environ.get("PSW_MODULES", "tracker").split(",") if m.strip()}
SECURE_COOKIE = os.environ.get("PSW_SECURE_COOKIE", "1") == "1"
SESSION_DAYS = 30
MAX_BLOB = 20 * 1024 * 1024
MAX_DOC = 1024 * 1024
COOKIE = "psw_session"
SEG = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
OK_TYPES = re.compile(r"^(application/pdf|image/(png|jpeg|gif|webp)|text/(plain|csv)|application/json)$")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  pw TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', active INTEGER NOT NULL DEFAULT 1, created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS invites(token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, name TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user', expires REAL NOT NULL, used REAL);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tracker_docs(path TEXT PRIMARY KEY, parent TEXT NOT NULL, id TEXT NOT NULL,
  data TEXT NOT NULL, updated REAL NOT NULL, updated_by TEXT);
CREATE INDEX IF NOT EXISTS tracker_docs_parent ON tracker_docs(parent);
CREATE TABLE IF NOT EXISTS api_keys(token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, created REAL NOT NULL,
  last_used REAL, active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS tracker_blobs(id TEXT PRIMARY KEY, type TEXT NOT NULL, size INTEGER NOT NULL,
  created REAL NOT NULL, created_by TEXT);
"""


def db():
    c = sqlite3.connect(DB_PATH, timeout=15)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    return c


def init_db():
    DATA.mkdir(parents=True, exist_ok=True)
    BLOBS.mkdir(parents=True, exist_ok=True)
    with db() as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript(SCHEMA)
        c.execute("INSERT OR IGNORE INTO meta(k,v) VALUES('version','0')")
        for t in ("users", "invites"):  # added after launch: each person's email address
            if "email" not in {r[1] for r in c.execute(f"PRAGMA table_info({t})")}:
                c.execute(f"ALTER TABLE {t} ADD COLUMN email TEXT NOT NULL DEFAULT ''")
        if "secrets" not in {r[1] for r in c.execute("PRAGMA table_info(users)")}:  # can this person see company/GA user names and passwords
            c.execute("ALTER TABLE users ADD COLUMN secrets INTEGER NOT NULL DEFAULT 0")
        c.execute("CREATE TABLE IF NOT EXISTS locks(path TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, tab TEXT NOT NULL, expires REAL NOT NULL)")
        if "can_delete" not in {r[1] for r in c.execute("PRAGMA table_info(users)")}:  # Admin's Delete Yes/No (everyone could delete before this)
            c.execute("ALTER TABLE users ADD COLUMN can_delete INTEGER NOT NULL DEFAULT 1")
        if "payment" not in {r[1] for r in c.execute("PRAGMA table_info(users)")}:  # Admin's Payment Yes/No: sees clients' Payment info
            c.execute("ALTER TABLE users ADD COLUMN payment INTEGER NOT NULL DEFAULT 0")
            for r in c.execute("SELECT id,username,name FROM users").fetchall():  # starts on for the people first asked for
                first = (r["name"] or "").split()[:1]
                if r["username"].lower() in PAY_PEOPLE or (first and first[0].lower() in PAY_PEOPLE):
                    c.execute("UPDATE users SET payment=1 WHERE id=?", (r["id"],))
        if "sig" not in {r[1] for r in c.execute("PRAGMA table_info(users)")}:  # Admin's Signature: picture stamped on ACORDs this person makes
            c.execute("ALTER TABLE users ADD COLUMN sig TEXT NOT NULL DEFAULT ''")
        c.execute("CREATE TABLE IF NOT EXISTS quote_links(token_hash TEXT PRIMARY KEY, lead TEXT NOT NULL, title TEXT NOT NULL, form TEXT NOT NULL, "
                  "vals TEXT NOT NULL, answers TEXT, agent TEXT NOT NULL, created REAL NOT NULL, created_by TEXT NOT NULL, expires REAL NOT NULL, submitted REAL)")


# ---------- passwords ----------
def hash_pw(pw: str) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"scrypt${salt.hex()}${h.hex()}"


def check_pw(pw: str, stored: str) -> bool:
    try:
        _, salt, h = stored.split("$")
        got = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1)
        return hmac.compare_digest(got.hex(), h)
    except Exception:
        return False


def new_id(n=20):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(n))


# ---------- app ----------
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


@app.on_event("startup")
def _startup():
    init_db()
    binder_backfill()


def err(status, code):
    raise HTTPException(status_code=status, detail=code)


@app.exception_handler(HTTPException)
async def _http_err(request: Request, exc: HTTPException):
    return JSONResponse({"code": exc.detail}, status_code=exc.status_code)


def bearer(request: Request):
    a = request.headers.get("authorization", "")
    return a[7:].strip() if a.lower().startswith("bearer ") else ""


def key_user(key: str):
    """Claude's data key, made with  sudo psw apikey  and sent as  Authorization: Bearer KEY.
    It acts as the "claude" login, which can only use the tracker data routes."""
    h = hashlib.sha256(key.encode()).hexdigest()
    with db() as c:
        row = c.execute(
            "SELECT u.* FROM api_keys k JOIN users u ON u.id=k.user_id WHERE k.token_hash=? AND k.active=1 AND u.active=1",
            (h,),
        ).fetchone()
        if row:
            c.execute("UPDATE api_keys SET last_used=? WHERE token_hash=?", (time.time(), h))
    return row


def current_user(request: Request):
    if bearer(request):
        if not request.url.path.startswith(("/api/tracker/", "/_blob/")):
            return None
        return key_user(bearer(request))
    tok = request.cookies.get(COOKIE)
    if not tok:
        return None
    with db() as c:
        row = c.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires>? AND u.active=1",
            (tok, time.time()),
        ).fetchone()
        if row:
            c.execute("UPDATE sessions SET expires=? WHERE token=?", (time.time() + SESSION_DAYS * 86400, tok))
    return row


def need_user(request: Request):
    u = current_user(request)
    if not u:
        err(401, "not_signed_in")
    return u


def need_module(name):
    if name not in MODULES:
        err(404, "module_off")


# ---------- core: sign in ----------
@app.get("/login")
def login_page():
    return FileResponse(STATIC / "login.html", headers={"Cache-Control": "no-store"})


@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    with db() as c:
        u = c.execute("SELECT * FROM users WHERE username=? AND active=1", (username.strip().lower(),)).fetchone()
        if not u or not check_pw(password, u["pw"]):
            time.sleep(1)
            return RedirectResponse("/login?bad=1", status_code=303)
        tok = secrets.token_urlsafe(32)
        c.execute("DELETE FROM sessions WHERE expires<?", (time.time(),))
        c.execute("INSERT INTO sessions(token,user_id,expires) VALUES(?,?,?)",
                  (tok, u["id"], time.time() + SESSION_DAYS * 86400))
    r = RedirectResponse("/", status_code=303)
    r.set_cookie(COOKIE, tok, max_age=SESSION_DAYS * 86400, httponly=True, secure=SECURE_COOKIE, samesite="lax")
    return r


@app.post("/logout")
def logout(request: Request):
    tok = request.cookies.get(COOKIE)
    if tok:
        with db() as c:
            c.execute("DELETE FROM sessions WHERE token=?", (tok,))
    r = RedirectResponse("/login", status_code=303)
    r.delete_cookie(COOKIE)
    return r


# ---------- core: sign-up links (made with  sudo psw invite USERNAME "Name") ----------
def token_hash(t: str) -> str:
    return hashlib.sha256(t.encode()).hexdigest()


def open_invite(c, t: str):
    return c.execute("SELECT * FROM invites WHERE token_hash=? AND used IS NULL AND expires>?",
                     (token_hash(t), time.time())).fetchone()


def start_session(c, user_id):
    tok = secrets.token_urlsafe(32)
    c.execute("DELETE FROM sessions WHERE expires<?", (time.time(),))
    c.execute("INSERT INTO sessions(token,user_id,expires) VALUES(?,?,?)", (tok, user_id, time.time() + SESSION_DAYS * 86400))
    return tok


@app.get("/invite")
def invite_page(t: str = ""):
    with db() as c:
        ok = bool(t) and open_invite(c, t)
    return FileResponse(STATIC / ("invite.html" if ok else "invite-expired.html"), headers={"Cache-Control": "no-store"})


@app.get("/api/auth/invite")
def invite_info(t: str):
    with db() as c:
        inv = open_invite(c, t)
    if not inv:
        err(404, "expired")
    return {"username": inv["username"], "name": inv["name"]}


@app.post("/invite")
def invite_accept(t: str = Form(...), password: str = Form(...), password2: str = Form(...)):
    if len(password) < 8 or password != password2:
        return RedirectResponse(f"/invite?t={t}&bad=1", status_code=303)
    with db() as c:
        inv = open_invite(c, t)
        if not inv:
            return RedirectResponse("/invite", status_code=303)
        if c.execute("SELECT 1 FROM users WHERE username=?", (inv["username"],)).fetchone():
            c.execute("UPDATE users SET pw=?, active=1 WHERE username=?", (hash_pw(password), inv["username"]))
        else:
            c.execute("INSERT INTO users(id,username,name,pw,role,active,created,email) VALUES(?,?,?,?,?,1,?,?)",
                      (new_id(), inv["username"], inv["name"], hash_pw(password), inv["role"], time.time(), inv["email"]))
        uid = c.execute("SELECT id FROM users WHERE username=?", (inv["username"],)).fetchone()["id"]
        c.execute("UPDATE invites SET used=? WHERE token_hash=?", (time.time(), inv["token_hash"]))
        tok = start_session(c, uid)
    r = RedirectResponse("/", status_code=303)
    r.set_cookie(COOKIE, tok, max_age=SESSION_DAYS * 86400, httponly=True, secure=SECURE_COOKIE, samesite="lax")
    return r


@app.get("/api/auth/me")
def me(request: Request):
    u = need_user(request)
    return {"id": u["id"], "name": u["name"], "username": u["username"], "role": u["role"],
            "binder": u["username"] in BINDER_OWNERS and not bearer(request),
            "owner": u["username"] in PANEL_OWNERS and not bearer(request), "secrets": can_secrets(u), "delete": may_delete(u), "pay": can_pay(u)}


@app.get("/api/auth/profiles")
def profiles(request: Request, ids: str = ""):
    need_user(request)
    want = [i for i in ids.split(",") if i][:200]
    if not want:
        return []
    with db() as c:
        rows = c.execute(f"SELECT id,name FROM users WHERE id IN ({','.join('?' * len(want))})", want).fetchall()
    return [{"id": r["id"], "name": r["name"]} for r in rows]


@app.post("/api/auth/password")
async def change_password(request: Request):
    u = need_user(request)
    body = await request.json()
    if not check_pw(str(body.get("old", "")), u["pw"]):
        err(403, "wrong_password")
    new = str(body.get("new", ""))
    if len(new) < 8:
        err(400, "too_short")
    with db() as c:
        c.execute("UPDATE users SET pw=? WHERE id=?", (hash_pw(new), u["id"]))
    return {"ok": True}


# ---------- core: admin panel (the owner only: list people and add new ones) ----------
PANEL_OWNERS = {x.strip() for x in os.environ.get("PSW_PANEL_OWNERS", os.environ.get("PSW_BINDER_OWNERS", "alex")).split(",") if x.strip()}


def clean_email(v, required=True):
    v = str(v or "").strip()
    if (v or required) and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", v):
        err(400, "bad_email")
    return v[:200]


def need_owner(request: Request):
    u = need_user(request)
    if bearer(request) or u["username"] not in PANEL_OWNERS:
        err(403, "owner_only")
    return u


@app.get("/api/admin/users")
def admin_users(request: Request):
    me = need_owner(request)
    with db() as c:
        rows = c.execute("SELECT username,name,email,role,active,created,secrets,can_delete,payment,sig FROM users ORDER BY active DESC, name COLLATE NOCASE").fetchall()
        pending = c.execute("SELECT username,name,email,role,expires FROM invites WHERE used IS NULL AND expires>? ORDER BY expires",
                            (time.time(),)).fetchall()
    have = {r["username"] for r in rows}
    return {"me": me["username"], "owners": sorted(PANEL_OWNERS), "users": [dict(r) for r in rows], "invites": [dict(r) for r in pending if r["username"] not in have]}


@app.post("/api/admin/users")
async def admin_add_user(request: Request):
    need_owner(request)
    body = await request.json()
    username = str(body.get("username", "")).strip().lower()
    name = " ".join(str(body.get("name", "")).split())
    role = "admin" if body.get("admin") else "user"
    pw = str(body.get("password", ""))
    email = clean_email(body.get("email", ""))
    if not re.fullmatch(r"[a-z0-9._-]{2,32}", username):
        err(400, "bad_username")
    if not name or len(name) > 80:
        err(400, "bad_name")
    with db() as c:
        if c.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            err(409, "exists")
        if pw:
            if len(pw) < 8:
                err(400, "too_short")
            c.execute("INSERT INTO users(id,username,name,pw,role,active,created,email) VALUES(?,?,?,?,?,1,?,?)",
                      (new_id(), username, name, hash_pw(pw), role, time.time(), email))
            return {"ok": True}
        t = secrets.token_urlsafe(24)  # same one-time sign-up link as  sudo psw invite
        c.execute("DELETE FROM invites WHERE username=? AND used IS NULL", (username,))
        c.execute("INSERT INTO invites(token_hash,username,name,role,expires,used,email) VALUES(?,?,?,?,?,NULL,?)",
                  (token_hash(t), username, name, role, time.time() + 7 * 86400, email))
    return {"ok": True, "invite": f"/invite?t={t}"}


@app.post("/api/admin/users/{username}/active")
async def admin_set_active(username: str, request: Request):
    """Remove = turn the login off and sign them out (their leads, tasks and notes stay); Restore turns it back on."""
    me = need_owner(request)
    on = bool((await request.json()).get("active"))
    if username == me["username"] and not on:
        err(400, "not_yourself")
    with db() as c:
        n = c.execute("UPDATE users SET active=? WHERE username=?", (1 if on else 0, username)).rowcount
        if not on:
            c.execute("DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE username=?)", (username,))
            n += c.execute("DELETE FROM invites WHERE username=? AND used IS NULL", (username,)).rowcount
    if not n:
        err(404, "no_such_user")
    return {"ok": True}


@app.post("/api/admin/users/{username}/email")
async def admin_set_email(username: str, request: Request):
    need_owner(request)
    email = clean_email((await request.json()).get("email", ""), required=False)
    with db() as c:
        n = c.execute("UPDATE users SET email=? WHERE username=?", (email, username)).rowcount
        n += c.execute("UPDATE invites SET email=? WHERE username=? AND used IS NULL", (email, username)).rowcount
    if not n:
        err(404, "no_such_user")
    return {"ok": True}


@app.post("/api/admin/users/{username}/secrets")
async def admin_set_secrets(username: str, request: Request):
    """User/Pass Yes or No: whether this person sees the user names and passwords saved for companies and GAs."""
    need_owner(request)
    on = bool((await request.json()).get("secrets"))
    with db() as c:
        n = c.execute("UPDATE users SET secrets=? WHERE username=?", (1 if on else 0, username)).rowcount
    if not n:
        err(404, "no_such_user")
    return {"ok": True}


@app.post("/api/admin/users/{username}/payment")
async def admin_set_payment(username: str, request: Request):
    """Payment Yes or No: whether this person sees and edits clients' Payment info."""
    need_owner(request)
    on = bool((await request.json()).get("payment"))
    with db() as c:
        n = c.execute("UPDATE users SET payment=? WHERE username=?", (1 if on else 0, username)).rowcount
    if not n:
        err(404, "no_such_user")
    return {"ok": True}


@app.post("/api/admin/users/{username}/signature")
async def admin_set_signature(username: str, request: Request):
    """Signature: a PNG picture (data URL) put on the ACORDs this person makes; empty removes it."""
    need_owner(request)
    sig = str((await request.json()).get("sig") or "")
    if sig and (not re.fullmatch(r"data:image/png;base64,[A-Za-z0-9+/=]+", sig) or len(sig) > 400_000):
        err(400, "bad_signature")
    with db() as c:
        n = c.execute("UPDATE users SET sig=? WHERE username=?", (sig, username)).rowcount
    if not n:
        err(404, "no_such_user")
    return {"ok": True}


@app.get("/api/auth/signature")
def my_signature(request: Request):
    u = need_user(request)
    return {"sig": u["sig"] if "sig" in u.keys() else ""}


@app.post("/api/admin/users/{username}/delete")
async def admin_set_delete(username: str, request: Request):
    """Delete Yes or No: whether this person can delete leads, clients, tasks, notes and files."""
    need_owner(request)
    on = bool((await request.json()).get("delete"))
    with db() as c:
        n = c.execute("UPDATE users SET can_delete=? WHERE username=?", (1 if on else 0, username)).rowcount
    if not n:
        err(404, "no_such_user")
    return {"ok": True}


def may_delete(u):
    return u["username"] in PANEL_OWNERS or bool(u["can_delete"])


# ---------- company/GA logins ----------
# siteLinks records hold each company's and GA's portal user name and password; everyone sees them, only owners and people set to Yes change them.
SITE_COL = "siteLinks"
SECRET_KEYS = ("user", "pass")


def can_secrets(u):
    return u["username"] in PANEL_OWNERS or bool(u["secrets"])


# clients' payInfo (Payment info box): only owners and people set to Yes in Admin's Payment column see or change it.
PAY_COL = "clients"
PAY_KEYS = ("payInfo",)


def can_pay(u):
    return u["username"] in PANEL_OWNERS or bool(u["payment"])


def hidden_keys(u, col):
    """Fields of records in collection `col` that this person may not see (or change)."""
    if col == PAY_COL and not can_pay(u):
        return PAY_KEYS
    return ()


def locked_keys(u, col):
    """Fields of records in collection `col` that this person may not change."""
    if col == SITE_COL and not can_secrets(u):
        return SECRET_KEYS
    return hidden_keys(u, col)


def hide_keys(data, keys):
    return {k: v for k, v in data.items() if k not in keys} if keys and isinstance(data, dict) else data


# ---------- tracker module: documents ----------
# Paths under private/<username>/ belong to that one person: nobody else, no admin and no data key can read or change them.
BINDER_OWNERS = {x.strip() for x in os.environ.get("PSW_BINDER_OWNERS", "alex").split(",") if x.strip()}


# a policy added to a client with one of these producers also goes into that person's binder log ("username:Producer name", comma separated)
BINDER_PRODUCERS = {}
for x in os.environ.get("PSW_BINDER_PRODUCERS", "alex:Alex K").split(","):
    if ":" in x:
        BINDER_PRODUCERS[x.split(":", 1)[1].strip().lower()] = x.split(":", 1)[0].strip()


def com_pct(c, p):
    """The policy's Commission % (extra.comPct, like "15%"), else its company's New or Renewal com % (Company info), as a number, or None."""
    x = str(((p.get("extra") or {}) if isinstance(p.get("extra"), dict) else {}).get("comPct") or "")
    if not x and p.get("company"):
        k = "$.comRen" if str(p.get("nb") or "").lower() == "renewal" else "$.com"
        r = c.execute(f"SELECT coalesce(nullif(json_extract(data,'{k}'),''),json_extract(data,'$.com')) FROM tracker_docs WHERE parent='siteLinks' AND json_extract(data,'$.kind')='company' "
                      "AND lower(trim(json_extract(data,'$.name')))=?", (str(p["company"]).strip().lower(),)).fetchone()
        x = str(r[0] or "") if r else ""
    x = re.sub(r"[^\d.]", "", x)
    return float(x) if re.fullmatch(r"\d+(\.\d+)?", x) else None


def binder_owner(p):
    """The username whose binder log a policy goes to: its producer by name ("Alex K") or username ("alex"), else None."""
    x = str(p.get("producer") or "").strip().lower()
    return BINDER_PRODUCERS.get(x) or next((u for u in BINDER_PRODUCERS.values() if u.lower() == x), None) if x else None


def binder_prem(p, key="premium"):
    """A dollar amount on the policy as a number: its premium, or a fee kept in extra (pswFee = PSW agency fee, the binder's BF)."""
    x = re.sub(r"[^\d.]", "", str((p if key == "premium" else p.get("extra") if isinstance(p.get("extra"), dict) else {}).get(key) or ""))
    return float(x) if re.fullmatch(r"\d+(\.\d+)?", x) else None


def binder_month(p):
    """The binder month a policy goes in: its effective date's month (2026-09-15 or 09/15/2026), else this month."""
    e = str(p.get("eff") or "")
    m = re.match(r"(\d{4})-(\d\d)", e) or re.match(r"(\d\d?)/\d\d?/(\d{4})", e)
    if not m:
        return time.strftime("%Y-%m")
    return f"{m[1]}-{m[2]}" if len(m[1]) == 4 else f"{m[2]}-{int(m[1]):02d}"


BINDER_FROM = "2026-09"  # the binder pulls in every policy from this month on; older ones only when they are new or newly given that producer


def binder_sync(c, path, old, new, backfill=False):
    """The binder log pulls from the clients: a policy whose producer has a binder log gets an entry in that log, in its effective date's month
    (new policies, ones just given that producer, and any from BINDER_FROM on that are missing).
    A policy already in the log keeps that entry's premium, com %, broker fee, dates, ... up to date, except boxes changed in the log by hand.
    When a policy's producer changes to someone else, or the policy is removed, its entry leaves the log (unless its commission or BF is marked paid).
    backfill: a check of a client as it stands (on startup), so nothing counts as new."""
    segs = path.split("/")
    if len(segs) != 2 or segs[0] != "clients" or not isinstance(new, dict):
        return
    olds = [p for p in (old or {}).get("policies") or [] if isinstance(p, dict)]
    same = lambda p: tuple(str(p.get(k) or "").strip().lower() for k in ("line", "number", "eff", "company"))
    # the producer each policy had before (by pid; older policies got their pid later, so also by line/number/eff/company)
    was = {**{same(p): binder_owner(p) for p in olds}, **{p.get("pid"): binder_owner(p) for p in olds if p.get("pid")}}
    prev = {p["pid"]: p for p in olds if p.get("pid")}
    name = (new.get("company") or " ".join(x for x in (new.get("firstName"), new.get("lastName")) if x) or "").strip()
    for p in new.get("policies") or []:
        if not isinstance(p, dict) or not p.get("pid"):
            continue
        owner = binder_owner(p)
        if not owner:
            continue
        col = f"private/{owner}/binder"
        eff, exp = str(p.get("eff") or ""), str(p.get("exp") or "")
        term = 1
        m1, m2 = re.match(r"(\d{4})-(\d\d)", eff), re.match(r"(\d{4})-(\d\d)", exp)
        if m1 and m2 and (int(m2[1]) - int(m1[1])) * 12 + int(m2[2]) - int(m1[2]) == 6:
            term = 6
        prem = binder_prem(p)
        r = c.execute("SELECT path,data FROM tracker_docs WHERE parent=? AND json_extract(data,'$.pid')=?", (col, p["pid"])).fetchone()
        if r:  # already in the log: it follows the policy's premium, com %, dates, ... unless that box was changed in the log by hand
            d = json.loads(r["data"])
            fields = lambda q: {"eff": str(q.get("eff") or ""), "exp": str(q.get("exp") or ""), "type": q.get("line") or "", "carrier": q.get("company") or "",
                                "ga": q.get("carrier") or "", "premium": binder_prem(q), "comPct": com_pct(c, q), "bf": binder_prem(q, "pswFee"), "month": binder_month(q) if q.get("eff") else ""}
            now, before = fields(p), fields(prev.get(p["pid"]) or {})
            add = {k: v for k, v in now.items() if v not in (None, "") and v != d.get(k) and d.get(k) in (None, "", before[k])}
            if now["month"] and now["month"] != d.get("month") and d.get("month") == str(d.get("createdAt") or "")[:7]:
                add["month"] = now["month"]  # entries made before the month followed the eff date sat in the month they were added
            if add:
                c.execute("UPDATE tracker_docs SET data=?, updated=?, updated_by='binder' WHERE path=?", (json.dumps({**d, **add}, separators=(",", ":")), time.time(), r["path"]))
            continue
        # a new policy, one whose producer was just set to someone with a binder log, or one from BINDER_FROM on that is missing
        not_new = backfill or owner == was.get(p["pid"], was.get(same(p)))
        if not_new and (not p.get("eff") or binder_month(p) < BINDER_FROM):
            continue
        note = ", ".join(x for x in ("Policy # " + p["number"] if p.get("number") else "", p.get("nb") or "") if x)
        d = {"name": name or "Client", "month": binder_month(p), "eff": eff, "exp": exp, "type": p.get("line") or "", "carrier": p.get("company") or "",
             "ga": p.get("carrier") or "", "term": term, "premium": prem, "comPct": com_pct(c, p), "commAmt": None, "yrAmt": None,
             "bf": binder_prem(p, "pswFee"), "finance": "", "splitPct": None, "notes": note, "comPaid": "", "bfPaid": "", "pid": p["pid"], "clientId": segs[1],
             "createdAt": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())}
        i = new_id()
        c.execute("INSERT INTO tracker_docs(path,parent,id,data,updated,updated_by) VALUES(?,?,?,?,?,?)",
                  (f"{col}/{i}", col, i, json.dumps(d, separators=(",", ":")), time.time(), "binder"))
    # entries this client's policies put in a log whose owner is no longer the producer (or whose policy is gone) leave it, unless marked paid
    now_owner = {p["pid"]: binder_owner(p) for p in new.get("policies") or [] if isinstance(p, dict) and p.get("pid")}
    for owner in set(BINDER_PRODUCERS.values()):
        col = f"private/{owner}/binder"
        for r in c.execute("SELECT path,data FROM tracker_docs WHERE parent=? AND json_extract(data,'$.clientId')=?", (col, segs[1])).fetchall():
            d = json.loads(r["data"])
            if d.get("pid") and now_owner.get(d["pid"]) != owner and not d.get("comPaid") and not d.get("bfPaid"):
                c.execute("DELETE FROM tracker_docs WHERE path=?", (r["path"],))


def binder_backfill():
    """On startup: every client's policies checked against the binder logs, so the logs match the clients (see binder_sync)."""
    with db() as c:
        for r in c.execute("SELECT path,data FROM tracker_docs WHERE parent='clients'").fetchall():
            try:
                d = json.loads(r["data"])
            except ValueError:
                continue
            binder_sync(c, r["path"], d, d, backfill=True)
        bump(c)


def guard(request: Request, u, segs):
    if segs[0] == "private" and (len(segs) < 2 or bearer(request) or segs[1] != u["username"]):
        err(403, "private")


def split_path(path: str, kind: str):
    segs = path.split("/") if path else []
    if not segs or not all(SEG.match(s) for s in segs):
        err(400, "bad_path")
    if kind == "doc" and len(segs) % 2:
        err(400, "bad_path")
    if kind == "col" and not len(segs) % 2:
        err(400, "bad_path")
    return segs


def bump(c):
    c.execute("UPDATE meta SET v=CAST(v AS INTEGER)+1 WHERE k='version'")


def version(c):
    return int(c.execute("SELECT v FROM meta WHERE k='version'").fetchone()[0])


def clean_data(data):
    if not isinstance(data, dict):
        err(400, "bad_data")
    s = json.dumps(data, separators=(",", ":"))
    if len(s) > MAX_DOC:
        err(413, "too_large")
    return s


@app.get("/api/tracker/version")
def tracker_version(request: Request):
    need_module("tracker"); need_user(request)
    with db() as c:
        return {"v": version(c)}


@app.get("/api/tracker/col")
def col_get(request: Request, path: str):
    need_module("tracker"); u = need_user(request)
    guard(request, u, split_path(path, "col"))
    with db() as c:
        rows = c.execute("SELECT id,data FROM tracker_docs WHERE parent=? ORDER BY id", (path,)).fetchall()
        keys = hidden_keys(u, path)
        return {"v": version(c), "docs": [{"id": r["id"], "data": hide_keys(json.loads(r["data"]), keys)} for r in rows]}


@app.post("/api/tracker/col")
async def col_add(request: Request):
    need_module("tracker"); u = need_user(request)
    body = await request.json()
    path = body.get("path", "")
    guard(request, u, split_path(path, "col"))
    data = body.get("data")
    data = clean_data(hide_keys(data, locked_keys(u, path)))
    i = new_id()
    with db() as c:
        c.execute("INSERT INTO tracker_docs(path,parent,id,data,updated,updated_by) VALUES(?,?,?,?,?,?)",
                  (f"{path}/{i}", path, i, data, time.time(), u["id"]))
        binder_sync(c, f"{path}/{i}", None, json.loads(data))
        bump(c)
    return {"id": i}


@app.get("/api/tracker/doc")
def doc_get(request: Request, path: str):
    need_module("tracker"); u = need_user(request)
    segs = split_path(path, "doc")
    guard(request, u, segs)
    with db() as c:
        r = c.execute("SELECT data FROM tracker_docs WHERE path=?", (path,)).fetchone()
    data = json.loads(r["data"]) if r else None
    data = hide_keys(data, hidden_keys(u, "/".join(segs[:-1])))
    return {"exists": bool(r), "data": data}


@app.put("/api/tracker/doc")
async def doc_set(request: Request):
    need_module("tracker"); u = need_user(request)
    body = await request.json()
    path = body.get("path", "")
    segs = split_path(path, "doc")
    guard(request, u, segs)
    data = body.get("data")
    keys = locked_keys(u, "/".join(segs[:-1])) if isinstance(data, dict) else ()
    with db() as c:
        if keys:  # fields this person can't change keep what is there
            old = c.execute("SELECT data FROM tracker_docs WHERE path=?", (path,)).fetchone()
            data = {**hide_keys(data, keys), **{k: v for k, v in (json.loads(old["data"]) if old else {}).items() if k in keys}}
        data = clean_data(data)
        prev = c.execute("SELECT data FROM tracker_docs WHERE path=?", (path,)).fetchone()
        binder_sync(c, path, json.loads(prev["data"]) if prev else None, json.loads(data))
        c.execute("INSERT INTO tracker_docs(path,parent,id,data,updated,updated_by) VALUES(?,?,?,?,?,?) "
                  "ON CONFLICT(path) DO UPDATE SET data=excluded.data, updated=excluded.updated, updated_by=excluded.updated_by",
                  (path, "/".join(segs[:-1]), segs[-1], data, time.time(), u["id"]))
        bump(c)
    return {"ok": True}


@app.patch("/api/tracker/doc")
async def doc_update(request: Request):
    need_module("tracker"); u = need_user(request)
    body = await request.json()
    path = body.get("path", "")
    guard(request, u, split_path(path, "doc"))
    patch = body.get("data")
    if not isinstance(patch, dict):
        err(400, "bad_data")
    patch = hide_keys(patch, locked_keys(u, path.rsplit("/", 1)[0]))
    with db() as c:
        r = c.execute("SELECT data FROM tracker_docs WHERE path=?", (path,)).fetchone()
        if not r:
            err(404, "not_found")
        cur = json.loads(r["data"])
        binder_sync(c, path, cur, {**cur, **patch})
        cur.update(patch)
        c.execute("UPDATE tracker_docs SET data=?, updated=?, updated_by=? WHERE path=?",
                  (clean_data(cur), time.time(), u["id"], path))
        bump(c)
    return {"ok": True}


@app.delete("/api/tracker/doc")
def doc_delete(request: Request, path: str):
    need_module("tracker"); u = need_user(request)
    segs = split_path(path, "doc")
    guard(request, u, segs)
    if segs[0] != "private" and not may_delete(u):
        err(403, "no_delete")
    with db() as c:
        c.execute("DELETE FROM tracker_docs WHERE path=?", (path,))
        bump(c)
    return {"ok": True}


# ---------- record locks ----------
# Whoever opens a client or lead first holds it (one browser tab); everyone else sees it read-only.
# The open tab renews the lock every 30 seconds, so a closed or crashed tab frees it within LOCK_TTL.
LOCK_TTL = 90
LOCKABLE = ("clients", "leads")


def lock_args(body):
    path, tab = str(body.get("path", "")), str(body.get("tab", ""))
    segs = split_path(path, "doc")
    if len(segs) != 2 or segs[0] not in LOCKABLE or not re.fullmatch(r"[A-Za-z0-9]{6,40}", tab):
        err(400, "bad_lock")
    return path, tab


@app.post("/api/tracker/lock")
async def lock_take(request: Request):
    """Take or renew the lock. force (owners only) takes it from whoever has it."""
    need_module("tracker"); u = need_user(request)
    body = await request.json()
    path, tab = lock_args(body)
    force = bool(body.get("force")) and u["username"] in PANEL_OWNERS and not bearer(request)
    now = time.time()
    with db() as c:
        r = c.execute("SELECT * FROM locks WHERE path=?", (path,)).fetchone()
        if r and r["expires"] > now and not (r["user_id"] == u["id"] and r["tab"] == tab) and not force:
            return {"ok": False, "name": r["name"], "mine": r["user_id"] == u["id"]}
        c.execute("INSERT INTO locks(path,user_id,name,tab,expires) VALUES(?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET "
                  "user_id=excluded.user_id, name=excluded.name, tab=excluded.tab, expires=excluded.expires",
                  (path, u["id"], u["name"], tab, now + LOCK_TTL))
    return {"ok": True}


def lock_drop(u, path, tab):
    with db() as c:
        c.execute("DELETE FROM locks WHERE path=? AND user_id=? AND tab=?", (path, u["id"], tab))
    return {"ok": True}


@app.delete("/api/tracker/lock")
def lock_release(request: Request, path: str = "", tab: str = ""):
    need_module("tracker"); u = need_user(request)
    return lock_drop(u, *lock_args({"path": path, "tab": tab}))


@app.post("/api/tracker/unlock")
async def lock_release_beacon(request: Request):
    """Same as DELETE, for navigator.sendBeacon when a tab closes."""
    need_module("tracker"); u = need_user(request)
    return lock_drop(u, *lock_args(json.loads(await request.body() or b"{}")))


# ---------- tracker module: files ----------
@app.post("/api/tracker/blobs")
async def blob_upload(request: Request):
    need_module("tracker"); u = need_user(request)
    ctype = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
    if not OK_TYPES.match(ctype):
        err(415, "unsupported_type")
    body = await request.body()
    if len(body) > MAX_BLOB:
        err(413, "too_large")
    i = new_id(32)
    (BLOBS / i).write_bytes(body)
    with db() as c:
        c.execute("INSERT INTO tracker_blobs(id,type,size,created,created_by) VALUES(?,?,?,?,?)",
                  (i, ctype, len(body), time.time(), u["id"]))
    return {"id": i, "url": f"/_blob/{i}", "sizeBytes": len(body), "contentType": ctype}


@app.get("/api/tracker/blobs")
def blob_list(request: Request):
    need_module("tracker"); need_user(request)
    with db() as c:
        rows = c.execute("SELECT id,type,size,created FROM tracker_blobs ORDER BY created").fetchall()
    total = sum(r["size"] for r in rows)
    return {"assets": [{"id": r["id"], "url": f"/_blob/{r['id']}", "sizeBytes": r["size"], "contentType": r["type"]}
                       for r in rows], "usage": {"bytes": total}}


@app.delete("/api/tracker/blobs/{bid}")
def blob_delete(request: Request, bid: str):
    need_module("tracker"); need_user(request)
    if not SEG.match(bid):
        err(400, "bad_id")
    with db() as c:
        c.execute("DELETE FROM tracker_blobs WHERE id=?", (bid,))
    (BLOBS / bid).unlink(missing_ok=True)
    return {"ok": True}


@app.get("/_blob/{bid}")
def blob_get(request: Request, bid: str):
    need_user(request)
    if not SEG.match(bid):
        err(400, "bad_id")
    with db() as c:
        r = c.execute("SELECT type FROM tracker_blobs WHERE id=?", (bid,)).fetchone()
    f = BLOBS / bid
    if not r or not f.exists():
        err(404, "not_found")
    return FileResponse(f, media_type=r["type"], headers={"Cache-Control": "private, max-age=31536000, immutable"})


# ---------- tracker module: state ACORD 137s (CA ships with the app; others are added from the lead's ACORD box) ----------
A137 = DATA / "acord137"
ST2 = re.compile(r"^[A-Z]{2}$")


def plain_pdf(body: bytes) -> bytes:
    """Unlock a fillable PDF that is locked against editing (most ACORD downloads) and drop its XFA so the boxes fill; as-is if that can't be done."""
    try:
        import io
        import pypdf
        r = pypdf.PdfReader(io.BytesIO(body))
        if r.is_encrypted:
            r.decrypt("")
        w = pypdf.PdfWriter(clone_from=r)
        af = w._root_object.get("/AcroForm")
        if af is not None and "/XFA" in af:
            del af["/XFA"]
        out = io.BytesIO()
        w.write(out)
        return out.getvalue()
    except Exception:
        return body


@app.get("/api/acord137")
def acord137_list(request: Request):
    need_module("tracker"); need_user(request)
    have = sorted(f.stem for f in A137.glob("*.pdf")) if A137.is_dir() else []
    return {"states": sorted(set(have) | {"CA"})}


@app.get("/api/acord137/{st}")
def acord137_get(request: Request, st: str):
    """That state's 137, or the CA 137 when the state has none (X-State says which)."""
    need_module("tracker"); need_user(request)
    st = st.upper()
    f = A137 / f"{st}.pdf" if ST2.match(st) else None
    if not f or not f.is_file():
        st, f = "CA", (A137 / "CA.pdf" if (A137 / "CA.pdf").is_file() else STATIC / "tpl137-CA.pdf")
    return FileResponse(f, media_type="application/pdf", headers={"X-State": st, "Cache-Control": "no-cache"})


@app.post("/api/acord137/{st}")
async def acord137_put(request: Request, st: str):
    need_module("tracker"); need_user(request)
    st = st.upper()
    if not ST2.match(st):
        err(400, "bad_state")
    body = await request.body()
    if len(body) > 8_000_000:
        err(413, "too_large")
    if not body.startswith(b"%PDF"):
        err(415, "not_a_pdf")
    A137.mkdir(parents=True, exist_ok=True)
    (A137 / f"{st}.pdf").write_bytes(plain_pdf(body))
    return {"ok": True, "state": st}


# ---------- tracker module: Quick fill reading (optional, needs ANTHROPIC_API_KEY in .env) ----------
# ---------- tracker module: whole-database read and backup (for Claude's data key, or an admin) ----------
def need_data_admin(request: Request):
    u = need_user(request)
    if u["role"] != "admin" and not bearer(request):
        err(403, "admins_only")
    return u


@app.get("/api/tracker/export")
def tracker_export(request: Request):
    """Every record keyed by path (leads/ID, leads/ID/contacts/ID, tasks/ID), plus the list of files. Private records are left out."""
    need_module("tracker"); u = need_data_admin(request)
    with db() as c:
        docs = {r["path"]: hide_keys(json.loads(r["data"]), () if can_pay(u) or r["path"].rsplit("/", 1)[0] != PAY_COL else PAY_KEYS) for r in c.execute("SELECT path,data FROM tracker_docs WHERE path NOT LIKE 'private/%' ORDER BY path")}
        blobs = {r["id"]: {"type": r["type"], "size": r["size"]} for r in c.execute("SELECT id,type,size FROM tracker_blobs")}
        return {"v": version(c), "docs": docs, "blobs": blobs}


@app.post("/api/tracker/backup")
def tracker_backup(request: Request):
    """Copies the database into the dated backups folder. Run before any bulk change."""
    need_module("tracker"); need_data_admin(request)
    folder = DATA / "backups"
    folder.mkdir(parents=True, exist_ok=True)
    dest = folder / f"tracker-{time.strftime('%Y-%m-%d_%H%M%S')}.db"
    src = sqlite3.connect(DB_PATH)
    out = sqlite3.connect(dest)
    with out:
        src.backup(out)
    src.close(); out.close()
    return {"backup": dest.name}


@app.get("/api/tracker/sample")
def sample_status(request: Request):
    need_module("tracker"); need_user(request)
    return {"enabled": bool(os.environ.get("ANTHROPIC_API_KEY"))}


@app.post("/api/tracker/sample")
async def sample(request: Request):
    need_module("tracker"); need_user(request)
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        err(404, "not_granted")
    body = await request.json()
    content = []
    for im in (body.get("images") or [])[:5]:
        content.append({"type": "image", "source": {"type": "base64", "media_type": im.get("type", "image/png"),
                                                     "data": im.get("b64", "")}})
    content.append({"type": "text", "text": str(body.get("input", ""))[:200000]})
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=json.dumps({"model": os.environ.get("PSW_CLAUDE_MODEL", "claude-haiku-5-5"), "max_tokens": 8000,
                         "messages": [{"role": "user", "content": content}]}).encode(),
        headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            out = json.loads(r.read())
    except urllib.error.HTTPError as e:
        # say which: a bad key, a model the key can't use, or a request Anthropic turned down
        code = {429: "rate_limited", 401: "bad_key", 403: "bad_key", 404: "bad_model", 400: "rejected", 413: "too_large"}.get(e.code, "unavailable")
        err(429 if e.code == 429 else 502, code)
    except Exception:
        err(502, "unavailable")
    text = "".join(b.get("text", "") for b in out.get("content", []) if b.get("type") == "text")
    return {"text": text, "truncated": out.get("stop_reason") == "max_tokens"}


# ---------- tracker module: com quote fill-in link for the client ----------
# An agent sends the client a private link (/q/<token>) to a web copy of the lead's com quote sheet.
# The client fills in the blanks and submits once; the answers wait on the lead, and the lead's agent gets a task.
LINK_DAYS = 14
LEAD_PATH = re.compile(r"^leads/[A-Za-z0-9_\-]{1,64}$")
QKEY = re.compile(r"^[a-z0-9_]{1,40}$")


def form_keys(form):
    return {f.get("k") for s in form for f in (s.get("fields") or []) if isinstance(f, dict)}


def lead_patch(c, lead, patch):
    r = c.execute("SELECT data FROM tracker_docs WHERE path=?", (lead,)).fetchone()
    if r:
        d = json.loads(r["data"]); d.update(patch)
        c.execute("UPDATE tracker_docs SET data=?, updated=? WHERE path=?", (clean_data(d), time.time(), lead))
    return json.loads(r["data"]) if r else None


@app.post("/api/tracker/quote-link")
async def quote_link_new(request: Request):
    need_module("tracker"); u = need_user(request)
    body = await request.json()
    lead, form, vals = body.get("lead", ""), body.get("form"), body.get("values") or {}
    if not LEAD_PATH.match(lead) or not isinstance(form, list) or not isinstance(vals, dict):
        err(400, "bad_data")
    keys = form_keys(form)
    if not keys or not all(isinstance(k, str) and QKEY.match(k) for k in keys):
        err(400, "bad_form")
    vals = {k: str(v)[:4000] for k, v in vals.items() if k in keys and v not in (None, "")}
    title = str(body.get("title") or "")[:200]
    form_s, vals_s = json.dumps(form), json.dumps(vals)
    if len(form_s) + len(vals_s) > MAX_DOC:
        err(413, "too_large")
    tok = secrets.token_urlsafe(24)
    now = time.time()
    with db() as c:
        if not c.execute("SELECT 1 FROM tracker_docs WHERE path=?", (lead,)).fetchone():
            err(404, "not_found")
        # earlier links stay open until they expire, so a client holding an older link can still send it
        c.execute("INSERT INTO quote_links(token_hash,lead,title,form,vals,agent,created,created_by,expires) VALUES(?,?,?,?,?,?,?,?,?)",
                  (token_hash(tok), lead, title, form_s, vals_s, u["name"], now, u["id"], now + LINK_DAYS * 86400))
        lead_patch(c, lead, {"qlink": {"state": "sent", "sentAt": now, "expires": now + LINK_DAYS * 86400}})
        bump(c)
    return {"token": tok, "url": f"/q/{tok}", "expires": now + LINK_DAYS * 86400}


@app.get("/api/tracker/quote-link")
def quote_link_get(request: Request, lead: str):
    need_module("tracker"); need_user(request)
    if not LEAD_PATH.match(lead):
        err(400, "bad_data")
    with db() as c:
        r = c.execute("SELECT * FROM quote_links WHERE lead=? ORDER BY submitted IS NULL, COALESCE(submitted, created) DESC LIMIT 1", (lead,)).fetchone()
    if not r:
        return {"exists": False}
    return {"exists": True, "submitted": r["submitted"], "expires": r["expires"], "values": json.loads(r["vals"]),
            "answers": json.loads(r["answers"]) if r["answers"] else None}


def open_link(c, tok):
    r = c.execute("SELECT * FROM quote_links WHERE token_hash=?", (token_hash(tok or ""),)).fetchone()
    if not r:
        err(404, "not_found")
    if r["submitted"]:
        err(410, "submitted")
    if r["expires"] < time.time():
        err(410, "expired")
    return r


@app.get("/api/public/quote/{tok}")
def quote_public_get(tok: str):
    with db() as c:
        r = open_link(c, tok)
    return {"title": r["title"], "agent": r["agent"], "form": json.loads(r["form"]), "values": json.loads(r["vals"])}


@app.post("/api/public/quote/{tok}")
async def quote_public_submit(tok: str, request: Request):
    body = await request.json()
    ans = body.get("answers")
    if not isinstance(ans, dict):
        err(400, "bad_data")
    with db() as c:
        r = open_link(c, tok)
        keys = form_keys(json.loads(r["form"]))
        ans = {k: str(v).strip()[:4000] for k, v in ans.items() if k in keys and isinstance(v, (str, int, float)) and str(v).strip()}
        now = time.time()
        if c.execute("UPDATE quote_links SET answers=?, submitted=? WHERE token_hash=? AND submitted IS NULL",
                     (json.dumps(ans), now, r["token_hash"])).rowcount != 1:
            err(410, "submitted")
        d = lead_patch(c, r["lead"], {"qlink": {"state": "done", "sentAt": r["created"], "doneAt": now}}) or {}
        who = " ".join(x for x in (d.get("firstName", ""), d.get("lastName", "")) if x).strip() or d.get("company") or r["title"] or "A client"
        task = {"title": f"{who} filled in the com quote link: open the lead and click Update quote sheet",
                "firstName": d.get("firstName", ""), "lastName": d.get("lastName", ""), "company": d.get("company", ""),
                "assignedTo": d.get("assignedTo") or r["agent"], "due": time.strftime("%Y-%m-%d"), "priority": "High",
                "leadId": r["lead"].split("/", 1)[1], "notes": "", "files": [], "done": False, "doneAt": "",
                "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        i = new_id()
        c.execute("INSERT INTO tracker_docs(path,parent,id,data,updated,updated_by) VALUES(?,?,?,?,?,?)",
                  (f"tasks/{i}", "tasks", i, clean_data(task), now, r["created_by"]))
        bump(c)
    return {"ok": True}


@app.get("/q/{tok}")
def quote_public_page(tok: str):
    return FileResponse(STATIC / "quote-form.html", headers={**NO_STORE, "X-Robots-Tag": "noindex", "Referrer-Policy": "no-referrer"})


# ---------- pages and supporting files ----------
NO_STORE = {"Cache-Control": "no-store"}


# ---------- Email from the database: sent through Resend (an email-sending service, over HTTPS, so DigitalOcean's block on
# email ports doesn't matter), from the person's own @pswinsurance.com address. Each person connects once with their
# email address and password (Bluehost sells it as Titan email); the password is only used to put a copy of each email in their Sent folder (IMAP).
# Needs RESEND_API_KEY in .env, and pswinsurance.com verified in Resend (DNS records at Bluehost).
MAIL_MAX = 25 * 1024 * 1024  # Resend takes 40 MB per email after base64, which adds a third
MAIL_DOMAIN = os.environ.get("PSW_MAIL_DOMAIN", "pswinsurance.com").strip().lower()
IMAP_HOST = os.environ.get("PSW_IMAP_HOST", "imap.titan.email").strip()  # PSW mail is Titan (Outlook: Incoming mail server)
IMAP_PORT = int(os.environ.get("PSW_IMAP_PORT", "993"))
EMAIL_RE = re.compile(r"^[^@\s,;<>]+@[^@\s,;<>]+\.[^@\s,;<>]+$")


def mail_on():
    return bool(os.environ.get("RESEND_API_KEY", "").strip())


def mail_box():
    """email passwords are kept encrypted with a key that lives only on the server (DATA/mail.key, made the first time)"""
    from cryptography.fernet import Fernet
    f = DATA / "mail.key"
    if not f.exists():
        f.write_bytes(Fernet.generate_key())
        os.chmod(f, 0o600)
    return Fernet(f.read_bytes().strip())


def mail_table(c):
    c.execute("CREATE TABLE IF NOT EXISTS mail_accounts(user_id TEXT PRIMARY KEY, email TEXT NOT NULL DEFAULT '', "
              "refresh TEXT NOT NULL DEFAULT '', sig TEXT NOT NULL DEFAULT '', updated REAL NOT NULL)")
    if "sent_box" not in {r[1] for r in c.execute("PRAGMA table_info(mail_accounts)")}:  # `refresh` holds the encrypted email password
        c.execute("ALTER TABLE mail_accounts ADD COLUMN sent_box TEXT NOT NULL DEFAULT ''")


def imap_open(email, pw):
    """Log in to the mail server. A password with letters outside plain ASCII (é, ñ, curly quotes, ...) can't go through LOGIN, so it goes as AUTHENTICATE PLAIN in UTF-8."""
    import imaplib
    m = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, timeout=20)
    if pw.isascii() and email.isascii():
        m.login(email, pw)
    else:
        m.authenticate("PLAIN", lambda _: ("\0" + email + "\0" + pw).encode("utf-8"))
    return m


def imap_sent_box(m):
    """the Sent folder Outlook uses: the one marked \\Sent, else the usual names (older Bluehost boxes use INBOX.Sent)"""
    typ, rows = m.list()
    names = []
    for r in rows or []:
        s = r.decode(errors="replace") if isinstance(r, bytes) else str(r)
        mm = re.match(r'^\((?P<f>[^)]*)\)\s+(?:"[^"]*"|NIL)\s+(?P<n>.+)$', s)
        if not mm:
            continue
        n = mm.group("n").strip()
        if "\\sent" in mm.group("f").lower():
            return n
        names.append(n.strip('"'))
    for want in ("INBOX.Sent", "Sent", "INBOX.Sent Items", "Sent Items", "INBOX.Sent Messages", "Sent Messages"):
        for n in names:
            if n.lower() == want.lower():
                return '"%s"' % n if " " in n else n
    return "INBOX.Sent"


def resend_post(payload):
    req = urllib.request.Request("https://api.resend.com/emails", data=json.dumps(payload).encode(), headers={
        "authorization": "Bearer " + os.environ.get("RESEND_API_KEY", "").strip(), "content-type": "application/json",
        "user-agent": "psw-tracker"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read() or b"{}")


@app.get("/api/mail/status")
def mail_status(request: Request):
    u = need_user(request)
    with db() as c:
        mail_table(c)
        r = c.execute("SELECT email,refresh,sig FROM mail_accounts WHERE user_id=?", (u["id"],)).fetchone()
    return {"configured": mail_on(), "connected": bool(mail_on() and r and r["email"] and r["refresh"]),
            "email": (r["email"] if r else "") or u["email"] or "", "sig": r["sig"] if r else "", "domain": MAIL_DOMAIN}


@app.post("/api/mail/connect")
async def mail_connect(request: Request):
    u = need_user(request)
    if not mail_on():
        err(404, "mail_off")
    b = await request.json()
    email, pw = str(b.get("email") or "").strip().lower(), str(b.get("password") or "")
    if not EMAIL_RE.match(email) or not email.endswith("@" + MAIL_DOMAIN):
        err(400, "bad_from")
    if not pw:
        err(400, "bad_login")
    import imaplib
    try:
        m = imap_open(email, pw)
    except imaplib.IMAP4.error as e:  # the mail server's own words go back too (wrong password, too many tries, access turned off, ...)
        print(f"mail connect {email}: {IMAP_HOST} said {e}", flush=True)
        return JSONResponse({"code": "bad_login", "said": str(e)[:200]}, status_code=400)
    except Exception as e:
        print(f"mail connect {email}: {IMAP_HOST} unreachable: {e!r}", flush=True)
        err(502, "imap_unreachable")
    try:
        box = imap_sent_box(m)
    finally:
        try:
            m.logout()
        except Exception:
            pass
    with db() as c:
        mail_table(c)
        c.execute("INSERT INTO mail_accounts(user_id,email,refresh,sent_box,updated) VALUES(?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET "
                  "email=excluded.email, refresh=excluded.refresh, sent_box=excluded.sent_box, updated=excluded.updated",
                  (u["id"], email, mail_box().encrypt(pw.encode()).decode(), box, time.time()))
    return {"ok": True, "email": email}


@app.post("/api/mail/disconnect")
def mail_disconnect(request: Request):
    u = need_user(request)
    with db() as c:
        mail_table(c)
        c.execute("UPDATE mail_accounts SET refresh='', email='', sent_box='' WHERE user_id=?", (u["id"],))
    return {"ok": True}


@app.post("/api/mail/signature")
async def mail_signature(request: Request):
    u = need_user(request)
    sig = str((await request.json()).get("sig", ""))[:60000]  # formatted (HTML) signature
    with db() as c:
        mail_table(c)
        c.execute("INSERT INTO mail_accounts(user_id,sig,updated) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET sig=excluded.sig",
                  (u["id"], sig, time.time()))
    return {"ok": True}


def addr_list(v):
    out = []
    for a in (v if isinstance(v, list) else re.split(r"[,;]", str(v or ""))):
        a = str(a).strip()
        if a:
            if not EMAIL_RE.match(a):
                err(400, "bad_address")
            out.append(a)
    return out[:50]


@app.post("/api/mail/send")
async def mail_send(request: Request):
    u = need_user(request)
    if not mail_on():
        err(404, "mail_off")
    b = await request.json()
    to, cc = addr_list(b.get("to")), addr_list(b.get("cc"))
    if not to:
        err(400, "no_recipient")
    atts, total = [], 0
    for a in (b.get("attachments") or [])[:20]:
        name = re.sub(r"[\\/\r\n]", " ", str(a.get("name") or "file"))[:150]
        if a.get("blob"):  # a file already stored on a lead or client
            bid = str(a["blob"])
            if not SEG.match(bid):
                err(400, "bad_id")
            with db() as c:
                r = c.execute("SELECT type FROM tracker_blobs WHERE id=?", (bid,)).fetchone()
            if not r or not (BLOBS / bid).exists():
                err(404, "not_found")
            data, typ = (BLOBS / bid).read_bytes(), r["type"]
        else:  # made in the browser (e.g. the flattened cert)
            try:
                data = base64.b64decode(str(a.get("b64") or ""), validate=True)
            except Exception:
                err(400, "bad_file")
            typ = str(a.get("type") or "application/octet-stream")[:100]
        total += len(data)
        if total > MAIL_MAX:
            err(413, "too_large")
        atts.append((name, typ, data))
    with db() as c:
        mail_table(c)
        acct = c.execute("SELECT email,refresh,sent_box FROM mail_accounts WHERE user_id=?", (u["id"],)).fetchone()
    if not acct or not acct["email"] or not acct["refresh"]:
        err(409, "mail_not_connected")
    sender = f'{u["name"]} <{acct["email"]}>' if u["name"] else acct["email"]
    subject, html = str(b.get("subject") or "")[:250], str(b.get("html") or "")[:200000]
    payload = {"from": sender, "to": to, "subject": subject, "html": html, "reply_to": acct["email"],
               "attachments": [{"filename": n, "content": base64.b64encode(d).decode(), "content_type": t} for n, t, d in atts]}
    if cc:
        payload["cc"] = cc
    try:
        resend_post(payload)
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read()).get("message", "")
        except Exception:
            msg = ""
        if e.code == 413:
            err(413, "too_large")
        if e.code == 403 and "domain" in msg.lower():
            err(502, "domain_unverified")
        err(502, "mail_rejected")
    except Exception:
        err(502, "mail_unavailable")
    # a copy in the person's own Sent folder, so it shows in Outlook like any email they sent
    from email.message import EmailMessage
    from email.policy import SMTP
    from email.utils import formatdate, make_msgid
    em = EmailMessage()
    em["From"], em["To"], em["Subject"], em["Date"] = sender, ", ".join(to), subject, formatdate(localtime=True)
    if cc:
        em["Cc"] = ", ".join(cc)
    em["Message-ID"] = make_msgid(domain=MAIL_DOMAIN)
    em.set_content("This email was sent from the PSW database.")
    em.add_alternative(html, subtype="html")
    for n, t, d in atts:
        mt, _, st = (t if "/" in t else "application/octet-stream").partition("/")
        em.add_attachment(d, maintype=mt, subtype=st, filename=n)
    copied = False
    try:
        import imaplib
        m = imap_open(acct["email"], mail_box().decrypt(acct["refresh"].encode()).decode())
        try:
            typ, _ = m.append(acct["sent_box"] or "INBOX.Sent", "\\Seen", imaplib.Time2Internaldate(time.time()), em.as_bytes(policy=SMTP))
            copied = typ == "OK"
        finally:
            m.logout()
    except Exception:
        copied = False
    with db() as c:
        mail_log_table(c)
        c.execute("INSERT INTO mail_log(user_id,user_name,at,sender,to_,cc,subject,html,files,copied) VALUES(?,?,?,?,?,?,?,?,?,?)",
                  (u["id"], u["name"] or u["username"], time.time(), sender, ", ".join(to), ", ".join(cc), subject, html,
                   json.dumps([n for n, _, _ in atts]), 1 if copied else 0))
    return {"ok": True, "sentCopy": copied}


# ---------- Sent history: every email sent from the database (not the attachments themselves, just their names)
def mail_log_table(c):
    c.execute("CREATE TABLE IF NOT EXISTS mail_log(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, user_name TEXT NOT NULL DEFAULT '', "
              "at REAL NOT NULL, sender TEXT NOT NULL DEFAULT '', to_ TEXT NOT NULL DEFAULT '', cc TEXT NOT NULL DEFAULT '', subject TEXT NOT NULL DEFAULT '', "
              "html TEXT NOT NULL DEFAULT '', files TEXT NOT NULL DEFAULT '[]', copied INTEGER NOT NULL DEFAULT 0)")


@app.get("/api/mail/history")
def mail_history(request: Request, q: str = "", all: int = 0):
    """your own sent emails, newest first; the owners can see everyone's"""
    u = need_user(request)
    every = bool(all) and u["username"] in PANEL_OWNERS and not bearer(request)
    sql, args = "SELECT id,user_name,at,sender,to_,cc,subject,files,copied FROM mail_log WHERE 1=1", []
    if not every:
        sql += " AND user_id=?"
        args.append(u["id"])
    for w in str(q or "").lower().split()[:6]:
        sql += " AND lower(to_||' '||cc||' '||subject||' '||files||' '||user_name) LIKE ?"
        args.append("%" + w.replace("%", "").replace("_", "") + "%")
    with db() as c:
        mail_log_table(c)
        rows = c.execute(sql + " ORDER BY at DESC LIMIT 500", args).fetchall()
    return {"canAll": u["username"] in PANEL_OWNERS and not bearer(request),
            "items": [{"id": r["id"], "by": r["user_name"], "at": r["at"], "from": r["sender"], "to": r["to_"], "cc": r["cc"],
                       "subject": r["subject"], "files": json.loads(r["files"] or "[]"), "sentCopy": bool(r["copied"])} for r in rows]}


@app.get("/api/mail/history/{mid}")
def mail_history_one(mid: int, request: Request):
    u = need_user(request)
    with db() as c:
        mail_log_table(c)
        r = c.execute("SELECT user_id,html FROM mail_log WHERE id=?", (mid,)).fetchone()
    if not r or (r["user_id"] != u["id"] and (u["username"] not in PANEL_OWNERS or bearer(request))):
        err(404, "not_found")
    return {"html": r["html"]}


@app.get("/healthz")
def health():
    return Response("ok")



@app.get("/")
def index(request: Request):
    if not current_user(request):
        return RedirectResponse("/login", status_code=303)
    return FileResponse(STATIC / "index.html", headers=NO_STORE)


@app.get("/{name}")
def static_file(request: Request, name: str):
    if name in ("claude-shim.js", "psw-logo.png"):  # public, used by sign-in pages
        pass
    elif not current_user(request):
        err(401, "not_signed_in")
    f = STATIC / name
    if not re.match(r"^[A-Za-z0-9_.\-]+$", name) or name.startswith(".") or not f.is_file():
        err(404, "not_found")
    return FileResponse(f, headers={"Cache-Control": "no-cache"})

