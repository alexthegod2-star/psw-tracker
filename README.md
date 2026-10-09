# PSW Lead & Task Tracker server

The self-hosted tracker at https://165-227-56-252.sslip.io (FastAPI + SQLite behind Caddy).

- `psw-tracker/` is the app. `lead-tracker.html` is the page; `make_index.py` wraps it with `static/claude-shim.js`.
- Merging to `main` runs `.github/workflows/deploy.yml`, which sends `psw-tracker/` to the server. There `psw-deploy` runs `install.sh`, which backs up the database first and keeps data, `.env` and logins.
- One-time server setup for deploys: `sudo bash psw-tracker/deploy/setup-deploy.sh` (prints the three repo secrets).
- No client data belongs in this repo.
