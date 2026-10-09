#!/usr/bin/env bash
# One-time setup so GitHub can install tracker updates. Run on the server:  sudo bash psw-tracker/deploy/setup-deploy.sh
# Makes a "deploy" login whose key can do exactly one thing: hand an update to psw-deploy (which runs install.sh).
# Prints two values to paste into the GitHub repo's Actions secrets. Running it again makes a new key (old one stops working).
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "Run it with sudo:  sudo bash $0"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
IP="$(curl -fsS --max-time 3 http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address 2>/dev/null || hostname -I | awk '{print $1}')"

install -o root -g root -m 755 "$HERE/psw-deploy" /usr/local/sbin/psw-deploy
id deploy >/dev/null 2>&1 || useradd --create-home --shell /bin/sh deploy
passwd -l deploy >/dev/null

echo 'deploy ALL=(root) NOPASSWD: /usr/local/sbin/psw-deploy' > /etc/sudoers.d/psw-deploy.tmp
chmod 440 /etc/sudoers.d/psw-deploy.tmp
visudo -cf /etc/sudoers.d/psw-deploy.tmp >/dev/null
mv /etc/sudoers.d/psw-deploy.tmp /etc/sudoers.d/psw-deploy

K="$(mktemp -d)"
ssh-keygen -q -t ed25519 -N '' -C "github-deploy-psw-tracker" -f "$K/key"
install -d -o deploy -g deploy -m 700 /home/deploy/.ssh
echo "command=\"sudo /usr/local/sbin/psw-deploy\",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty $(cat "$K/key.pub")" > /home/deploy/.ssh/authorized_keys
chown deploy:deploy /home/deploy/.ssh/authorized_keys; chmod 600 /home/deploy/.ssh/authorized_keys

echo
echo "In GitHub: your repo > Settings > Secrets and variables > Actions > New repository secret."
echo "Make these three. Paste them only into GitHub, never into a chat."
echo
echo "---- Name: DEPLOY_HOST    Value:"
echo "$IP"
echo
echo "---- Name: DEPLOY_KNOWN_HOSTS    Value (one line):"
echo "$IP $(cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub)"
echo
echo "---- Name: DEPLOY_KEY    Value (every line, from BEGIN to END):"
cat "$K/key"
rm -rf "$K"
echo
echo "Done. The key above is not kept on this server; run this again if you ever need a new one."
