"""Admin commands for the PSW tracker. Run on the server as:  sudo psw <command>

  psw invite USERNAME "Full Name" [--admin]    make a sign-up link; they set their own password (7 days, one use)
  psw adduser USERNAME "Full Name" [--admin]   add a person (asks for their password)
  psw passwd USERNAME                          set a new password for someone
  psw disable USERNAME / psw enable USERNAME   turn a login off or back on
  psw users                                    list everyone
  psw apikey                                   make Claude's data key (shown once; replaces any older key)
  psw apikey off                               turn Claude's data key off
  psw backup                                   copy the database into the dated backups folder
  psw import EXPORT.json [FILES_FOLDER]        load leads/tasks/files exported from the Claude tracker
"""
import getpass
import json
import shutil
import sqlite3
import sys
import time
from datetime import datetime

import app

KEEP_BACKUPS = 60


def ask_pw():
    while True:
        a = getpass.getpass("Password (8+ characters): ")
        if len(a) < 8:
            print("Too short.")
            continue
        if getpass.getpass("Same password again: ") != a:
            print("They didn't match.")
            continue
        return a


def adduser(username, name, admin=False):
    username = username.strip().lower()
    pw = ask_pw()
    with app.db() as c:
        c.execute("INSERT INTO users(id,username,name,pw,role,active,created) VALUES(?,?,?,?,?,1,?)",
                  (app.new_id(), username, name, app.hash_pw(pw), "admin" if admin else "user", time.time()))
    print(f"Added {name} ({username}).")


def invite(username, name, admin=False, days=7):
    """One-time link; also works as a password reset for someone who already has a login."""
    import hashlib
    import os
    import secrets
    username = username.strip().lower()
    t = secrets.token_urlsafe(24)
    with app.db() as c:
        c.execute("DELETE FROM invites WHERE username=? AND used IS NULL", (username,))
        c.execute("INSERT INTO invites(token_hash,username,name,role,expires,used) VALUES(?,?,?,?,?,NULL)",
                  (hashlib.sha256(t.encode()).hexdigest(), username, name, "admin" if admin else "user", time.time() + days * 86400))
    base = os.environ.get("PSW_PUBLIC_URL", "").rstrip("/") or "https://YOUR-SITE"
    print(f"Send this to {name}. It works once and expires in {days} days:")
    print(f"{base}/invite?t={t}")


def passwd(username):
    pw = ask_pw()
    with app.db() as c:
        n = c.execute("UPDATE users SET pw=? WHERE username=?", (app.hash_pw(pw), username.lower())).rowcount
        c.execute("DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE username=?)", (username.lower(),))
    print("Password changed." if n else "No such user.")


def set_active(username, on):
    with app.db() as c:
        n = c.execute("UPDATE users SET active=? WHERE username=?", (1 if on else 0, username.lower())).rowcount
        if not on:
            c.execute("DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE username=?)", (username.lower(),))
    print(("Enabled " if on else "Disabled ") + username if n else "No such user.")


def users():
    with app.db() as c:
        for r in c.execute("SELECT username,name,role,active FROM users ORDER BY username"):
            print(f"{r['username']:<16} {r['name']:<24} {r['role']:<6} {'on' if r['active'] else 'OFF'}")


def apikey(off=False):
    """Key for the "claude" login: tracker data only (read, edit, export, backup). No admin, no web sign-in."""
    import hashlib
    import secrets
    with app.db() as c:
        u = c.execute("SELECT id FROM users WHERE username='claude'").fetchone()
        if off:
            if u:
                c.execute("UPDATE api_keys SET active=0 WHERE user_id=?", (u["id"],))
            print("Claude's data key is off.")
            return
        if not u:
            c.execute("INSERT INTO users(id,username,name,pw,role,active,created) VALUES(?,?,?,?,?,1,?)",
                      (app.new_id(), "claude", "Claude", "!", "user", time.time()))
            u = c.execute("SELECT id FROM users WHERE username='claude'").fetchone()
        c.execute("UPDATE api_keys SET active=0 WHERE user_id=?", (u["id"],))
        key = "pswk_" + secrets.token_urlsafe(32)
        c.execute("INSERT INTO api_keys(token_hash,user_id,created,active) VALUES(?,?,?,1)",
                  (hashlib.sha256(key.encode()).hexdigest(), u["id"], time.time()))
    print("Claude's data key (shown only this once; any older key is now off):")
    print(key)
    print("Put it in your Claude cloud environment as PSW_API_TOKEN. Never paste it into a chat.")


def backup(quiet=False):
    """SQLite's own backup (safe while the app is writing), into backups/tracker-YYYY-MM-DD_HHMMSS.db."""
    if not app.DB_PATH.exists():
        return None
    folder = app.DATA / "backups"
    folder.mkdir(parents=True, exist_ok=True)
    dest = folder / f"tracker-{datetime.now():%Y-%m-%d_%H%M%S}.db"
    src = sqlite3.connect(app.DB_PATH)
    out = sqlite3.connect(dest)
    with out:
        src.backup(out)
    src.close(); out.close()
    old = sorted(folder.glob("tracker-*.db"))[:-KEEP_BACKUPS]
    for f in old:
        f.unlink()
    if not quiet:
        print("Backed up to", dest)
    return dest


def do_import(path, files_dir=None):
    """EXPORT.json: {"docs": {"leads/ID": {...}, "leads/ID/contacts/ID": {...}, "tasks/ID": {...}},
                     "blobs": {"BLOBID": {"type": "application/pdf"}}}; files named BLOBID in FILES_FOLDER."""
    backup()
    data = json.loads(open(path, encoding="utf-8").read())
    now = time.time()
    nd = nb = 0
    with app.db() as c:
        for p, d in data.get("docs", {}).items():
            segs = p.split("/")
            c.execute("INSERT OR REPLACE INTO tracker_docs(path,parent,id,data,updated,updated_by) VALUES(?,?,?,?,?,NULL)",
                      (p, "/".join(segs[:-1]), segs[-1], json.dumps(d, separators=(",", ":")), now))
            nd += 1
        if files_dir:
            for bid, meta in data.get("blobs", {}).items():
                src = app.Path(files_dir) / bid
                if not src.exists():
                    print("missing file", bid)
                    continue
                shutil.copyfile(src, app.BLOBS / bid)
                c.execute("INSERT OR REPLACE INTO tracker_blobs(id,type,size,created,created_by) VALUES(?,?,?,?,NULL)",
                          (bid, meta.get("type", "application/pdf"), src.stat().st_size, now))
                nb += 1
        app.bump(c)
    print(f"Imported {nd} records and {nb} files.")


def main(a):
    app.init_db()
    if not a or a[0] in ("-h", "--help", "help"):
        print(__doc__)
    elif a[0] == "init":
        pass
    elif a[0] == "invite" and len(a) >= 3:
        invite(a[1], a[2], "--admin" in a)
    elif a[0] == "adduser" and len(a) >= 3:
        adduser(a[1], a[2], "--admin" in a)
    elif a[0] == "passwd" and len(a) == 2:
        passwd(a[1])
    elif a[0] in ("disable", "enable") and len(a) == 2:
        set_active(a[1], a[0] == "enable")
    elif a[0] == "apikey":
        apikey(len(a) > 1 and a[1] == "off")
    elif a[0] == "users":
        users()
    elif a[0] == "backup":
        backup("--quiet" in a)
    elif a[0] == "import" and len(a) >= 2:
        do_import(a[1], a[2] if len(a) > 2 else None)
    else:
        print(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
