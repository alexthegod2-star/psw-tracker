"""Claude's helper for the tracker data API on the droplet. Needs network access to the site and
PSW_API_TOKEN (made with  sudo psw apikey) in the environment. PSW_URL defaults to the droplet site.

  python3 psw-api.py export > tracker.json      every record + file list
  python3 psw-api.py backup                     database backup on the server (do this before bulk edits)
  python3 psw-api.py get leads/ID               one record
  python3 psw-api.py list leads                 one collection (leads, tasks, leads/ID/contacts)
  python3 psw-api.py patch leads/ID '{"phone":"555-1234"}'
  python3 psw-api.py put leads/ID '{...}'       replace a record
  python3 psw-api.py add tasks '{...}'          new record, prints its id
  python3 psw-api.py delete leads/ID
  python3 psw-api.py file BLOBID out.pdf        download an attached file
"""
import json
import os
import sys
import urllib.parse
import urllib.request

URL = os.environ.get("PSW_URL", "https://165-227-56-252.sslip.io").rstrip("/")
TOKEN = os.environ.get("PSW_API_TOKEN", "")


def call(method, path, body=None, raw=False):
    req = urllib.request.Request(URL + path, method=method,
                                 data=None if body is None else json.dumps(body).encode(),
                                 headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read() if raw else json.loads(r.read())


def main(a):
    if not TOKEN:
        sys.exit("PSW_API_TOKEN is not set in this environment.")
    q = lambda p: urllib.parse.quote(p, safe="")
    cmd = a[0] if a else ""
    if cmd == "export":
        out = call("GET", "/api/tracker/export")
    elif cmd == "backup":
        out = call("POST", "/api/tracker/backup")
    elif cmd == "get":
        out = call("GET", "/api/tracker/doc?path=" + q(a[1]))
    elif cmd == "list":
        out = call("GET", "/api/tracker/col?path=" + q(a[1]))
    elif cmd in ("patch", "put"):
        out = call("PATCH" if cmd == "patch" else "PUT", "/api/tracker/doc", {"path": a[1], "data": json.loads(a[2])})
    elif cmd == "add":
        out = call("POST", "/api/tracker/col", {"path": a[1], "data": json.loads(a[2])})
    elif cmd == "delete":
        out = call("DELETE", "/api/tracker/doc?path=" + q(a[1]))
    elif cmd == "file":
        open(a[2], "wb").write(call("GET", "/_blob/" + a[1], raw=True))
        out = {"saved": a[2]}
    else:
        sys.exit(__doc__)
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main(sys.argv[1:])
