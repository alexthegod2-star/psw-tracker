#!/usr/bin/env bash
# Installs or updates the PSW tracker. Run from the unpacked folder:  sudo bash install.sh
# Safe to run again for updates: it backs up the database first and keeps your data, .env and logins.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "Run it with sudo:  sudo bash install.sh"; exit 1; }
SRC="$(cd "$(dirname "$0")" && pwd)"
APP=/opt/psw-tracker
DATA=/var/lib/psw-tracker
IP="$(curl -fsS --max-time 3 http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address 2>/dev/null || hostname -I | awk '{print $1}')"
HOST="${PSW_HOST:-${IP//./-}.sslip.io}"

echo "== Installing packages"
# wait for the server's automatic security updates to let go of apt instead of failing the deploy
apt-get -o DPkg::Lock::Timeout=600 update -qq
DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -qq python3-venv sqlite3 caddy >/dev/null

echo "== App user and folders"
id psw >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin psw
mkdir -p "$APP" "$DATA/blobs" "$DATA/backups"
if [ -f "$DATA/tracker.db" ] && [ -x "$APP/venv/bin/python" ]; then
  echo "== Backing up the database before updating"
  (cd "$APP" && sudo -u psw "$APP/venv/bin/python" manage.py backup)
fi

echo "== Copying the app"
rm -rf "$APP/static"
cp -r "$SRC/app.py" "$SRC/manage.py" "$SRC/make_index.py" "$SRC/requirements.txt" "$SRC/static" "$APP/"
if [ -f "$SRC/lead-tracker.html" ]; then cp "$SRC/lead-tracker.html" "$APP/"; fi
if [ ! -f "$APP/.env" ]; then
  cat > "$APP/.env" <<EOF
PSW_DATA=$DATA
PSW_MODULES=tracker
# To let Quick fill read pasted text and pictures with Claude, add your Anthropic API key:
# ANTHROPIC_API_KEY=
EOF
fi
grep -q '^PSW_PUBLIC_URL=' "$APP/.env" || echo "PSW_PUBLIC_URL=https://$HOST" >> "$APP/.env"
chown -R root:psw "$APP"; chmod 640 "$APP/.env"
chown -R psw:psw "$DATA"; chmod 750 "$DATA"

echo "== Python packages"
[ -x "$APP/venv/bin/python" ] || python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install -q --upgrade pip
"$APP/venv/bin/pip" install -q -r "$APP/requirements.txt"
(cd "$APP" && sudo -u psw "$APP/venv/bin/python" manage.py init)

echo "== Admin command (psw)"
cat > /usr/local/bin/psw <<EOF
#!/bin/sh
cd $APP && exec sudo -u psw $APP/venv/bin/python manage.py "\$@"
EOF
chmod 755 /usr/local/bin/psw

echo "== Always-on service"
cat > /etc/systemd/system/psw-tracker.service <<EOF
[Unit]
Description=PSW Lead & Task Tracker
After=network.target

[Service]
User=psw
Group=psw
WorkingDirectory=$APP
ExecStart=$APP/venv/bin/uvicorn app:app --host 127.0.0.1 --port 8000 --proxy-headers --forwarded-allow-ips 127.0.0.1
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/psw-backup.service <<EOF
[Unit]
Description=PSW tracker daily database backup
[Service]
Type=oneshot
User=psw
WorkingDirectory=$APP
ExecStart=$APP/venv/bin/python manage.py backup --quiet
EOF
cat > /etc/systemd/system/psw-backup.timer <<EOF
[Unit]
Description=PSW tracker daily database backup
[Timer]
OnCalendar=*-*-* 03:30
Persistent=true
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now psw-backup.timer >/dev/null
systemctl enable psw-tracker >/dev/null
systemctl restart psw-tracker

echo "== HTTPS (Caddy) for $HOST"
cat > /etc/caddy/Caddyfile <<EOF
$HOST {
  encode gzip
  request_body {
    max_size 25MB
  }
  reverse_proxy 127.0.0.1:8000
}
EOF
systemctl enable caddy >/dev/null
systemctl reload caddy 2>/dev/null || systemctl restart caddy
ufw allow 80/tcp >/dev/null
ufw allow 443/tcp >/dev/null

sleep 2
if curl -fsS http://127.0.0.1:8000/healthz >/dev/null; then echo "== App is running"; else echo "!! App did not start. Run: sudo journalctl -u psw-tracker -n 50"; exit 1; fi
echo
echo "Done. Open https://$HOST"
echo "Make a sign-up link:  sudo psw invite paul \"Paul M\""
