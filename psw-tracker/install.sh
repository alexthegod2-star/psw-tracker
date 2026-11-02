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
# Claude reading: the deploy step sends the repo secret ANTHROPIC_API_KEY as .claude-key; it replaces the key in .env
if [ -s "$SRC/.claude-key" ]; then
  KEY="$(tr -d '[:space:]' < "$SRC/.claude-key")"; rm -f "$SRC/.claude-key"
  if [[ "$KEY" =~ ^sk-ant-[A-Za-z0-9_-]+$ ]]; then
    sed -i '/^ANTHROPIC_API_KEY=/d' "$APP/.env"; echo "ANTHROPIC_API_KEY=$KEY" >> "$APP/.env"; echo "== Claude reading key set"
  else echo "!! The ANTHROPIC_API_KEY secret doesn't look like an Anthropic key (sk-ant-...), so it was not used"; fi
fi
# Email sending: the deploy step sends the repo secret RESEND_API_KEY as .resend-key; it replaces the key in .env
if [ -s "$SRC/.resend-key" ]; then
  KEY="$(tr -d '[:space:]' < "$SRC/.resend-key")"; rm -f "$SRC/.resend-key"
  if [[ "$KEY" =~ ^re_[A-Za-z0-9_-]+$ ]]; then
    sed -i '/^RESEND_API_KEY=/d' "$APP/.env"; echo "RESEND_API_KEY=$KEY" >> "$APP/.env"; echo "== Email sending key set"
  else echo "!! The RESEND_API_KEY secret doesn't look like a Resend key (re_...), so it was not used"; fi
fi
# Texting: the deploy step sends the repo secret SIMPLETEXTING_API_KEY as .text-key; it replaces the key in .env
if [ -s "$SRC/.text-key" ]; then
  KEY="$(tr -d '[:space:]' < "$SRC/.text-key")"; rm -f "$SRC/.text-key"
  if [[ "$KEY" =~ ^[A-Za-z0-9_.-]{16,}$ ]]; then
    sed -i '/^SIMPLETEXTING_API_KEY=/d' "$APP/.env"; echo "SIMPLETEXTING_API_KEY=$KEY" >> "$APP/.env"; echo "== Texting key set"
  else echo "!! The SIMPLETEXTING_API_KEY secret doesn't look like a SimpleTexting API token, so it was not used"; fi
fi
# Telegram: the deploy step sends the repo secret TELEGRAM_BOT_TOKEN as .tg-key; it replaces the token in .env
if [ -s "$SRC/.tg-key" ]; then
  KEY="$(tr -d '[:space:]' < "$SRC/.tg-key")"; rm -f "$SRC/.tg-key"
  if [[ "$KEY" =~ ^[0-9]{5,}:[A-Za-z0-9_-]{30,}$ ]]; then
    sed -i '/^TELEGRAM_BOT_TOKEN=/d' "$APP/.env"; echo "TELEGRAM_BOT_TOKEN=$KEY" >> "$APP/.env"; echo "== Telegram bot token set"
  else echo "!! The TELEGRAM_BOT_TOKEN secret doesn't look like a Telegram bot token (123456:ABC...), so it was not used"; fi
fi
# DocuSign: the deploy step sends the integration key and user ID as .ds-id, and the RSA private key as .ds-key
if [ -s "$SRC/.ds-id" ]; then
  IK="$(sed -n 1p "$SRC/.ds-id" | tr -d '[:space:]')"; UID_="$(sed -n 2p "$SRC/.ds-id" | tr -d '[:space:]')"; rm -f "$SRC/.ds-id"
  G='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
  if [[ "$IK" =~ $G && "$UID_" =~ $G ]]; then
    sed -i '/^DOCUSIGN_INTEGRATION_KEY=/d;/^DOCUSIGN_USER_ID=/d' "$APP/.env"
    echo "DOCUSIGN_INTEGRATION_KEY=$IK" >> "$APP/.env"; echo "DOCUSIGN_USER_ID=$UID_" >> "$APP/.env"; echo "== DocuSign integration key and user ID set"
  else echo "!! DOCUSIGN_INTEGRATION_KEY and DOCUSIGN_USER_ID should each look like 1a2b3c4d-1a2b-1a2b-1a2b-1a2b3c4d5e6f, so they were not used"; fi
fi
if [ -s "$SRC/.ds-key" ]; then
  # a key copied from a web page can lose its line breaks; put them back
  if python3 -c '
import re, sys
k = open(sys.argv[1]).read().replace("\r", "")
m = re.search(r"-----BEGIN ([A-Z ]*PRIVATE KEY)-----(.*?)-----END \1-----", k, re.S)
if not m:
    sys.exit(1)
body = re.sub(r"\s+", "", m.group(2))
open(sys.argv[2], "w").write(f"-----BEGIN {m.group(1)}-----\n" + "\n".join(body[i:i + 64] for i in range(0, len(body), 64)) + f"\n-----END {m.group(1)}-----\n")
' "$SRC/.ds-key" "$APP/docusign-key.pem"
  then echo "== DocuSign private key set"; else echo "!! DOCUSIGN_PRIVATE_KEY has no -----BEGIN RSA PRIVATE KEY----- / -----END lines, so it was not used"; fi
  rm -f "$SRC/.ds-key"
fi
chown -R root:psw "$APP"; chmod 640 "$APP/.env"; if [ -f "$APP/docusign-key.pem" ]; then chmod 640 "$APP/docusign-key.pem"; fi
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
