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
            "owner": u["username"] in PANEL_OWNERS and not bearer(request), "secrets": can_secrets(u), "delete": may_delete(u)}


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
        rows = c.execute("SELECT username,name,email,role,active,created,secrets,can_delete FROM users ORDER BY active DESC, name COLLATE NOCASE").fetchall()
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
# siteLinks records hold each company's and GA's portal user name and password; only owners and people set to Yes see them.
SITE_COL = "siteLinks"
SECRET_KEYS = ("user", "pass")


def can_secrets(u):
    return u["username"] in PANEL_OWNERS or bool(u["secrets"])


def hide_secrets(data):
    return {k: v for k, v in data.items() if k not in SECRET_KEYS}


# ---------- tracker module: documents ----------
# Paths under private/<username>/ belong to that one person: nobody else, no admin and no data key can read or change them.
BINDER_OWNERS = {x.strip() for x in os.environ.get("PSW_BINDER_OWNERS", "alex").split(",") if x.strip()}


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
        hide = path == SITE_COL and not can_secrets(u)
        return {"v": version(c), "docs": [{"id": r["id"], "data": hide_secrets(json.loads(r["data"])) if hide else json.loads(r["data"])} for r in rows]}


@app.post("/api/tracker/col")
async def col_add(request: Request):
    need_module("tracker"); u = need_user(request)
    body = await request.json()
    path = body.get("path", "")
    guard(request, u, split_path(path, "col"))
    data = body.get("data")
    if path == SITE_COL and isinstance(data, dict) and not can_secrets(u):
        data = hide_secrets(data)
    data = clean_data(data)
    i = new_id()
    with db() as c:
        c.execute("INSERT INTO tracker_docs(path,parent,id,data,updated,updated_by) VALUES(?,?,?,?,?,?)",
                  (f"{path}/{i}", path, i, data, time.time(), u["id"]))
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
    if data and "/".join(segs[:-1]) == SITE_COL and not can_secrets(u):
        data = hide_secrets(data)
    return {"exists": bool(r), "data": data}


@app.put("/api/tracker/doc")
async def doc_set(request: Request):
    need_module("tracker"); u = need_user(request)
    body = await request.json()
    path = body.get("path", "")
    segs = split_path(path, "doc")
    guard(request, u, segs)
    data = body.get("data")
    keep = "/".join(segs[:-1]) == SITE_COL and isinstance(data, dict) and not can_secrets(u)
    with db() as c:
        if keep:  # someone set to No can't see or change the saved user name and password, so keep what is there
            old = c.execute("SELECT data FROM tracker_docs WHERE path=?", (path,)).fetchone()
            data = {**hide_secrets(data), **{k: v for k, v in (json.loads(old["data"]) if old else {}).items() if k in SECRET_KEYS}}
        data = clean_data(data)
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
    if path.rsplit("/", 1)[0] == SITE_COL and not can_secrets(u):
        patch = hide_secrets(patch)
    with db() as c:
        r = c.execute("SELECT data FROM tracker_docs WHERE path=?", (path,)).fetchone()
        if not r:
            err(404, "not_found")
        cur = json.loads(r["data"])
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
    need_module("tracker"); need_data_admin(request)
    with db() as c:
        docs = {r["path"]: json.loads(r["data"]) for r in c.execute("SELECT path,data FROM tracker_docs WHERE path NOT LIKE 'private/%' ORDER BY path")}
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
        err(429 if e.code == 429 else 502, "rate_limited" if e.code == 429 else "unavailable")
    except Exception:
        err(502, "unavailable")
    text = "".join(b.get("text", "") for b in out.get("content", []) if b.get("type") == "text")
    return {"text": text, "truncated": out.get("stop_reason") == "max_tokens"}


# ---------- pages and supporting files ----------
NO_STORE = {"Cache-Control": "no-store"}


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

