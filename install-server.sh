#!/usr/bin/env bash
# Sentinel for Ubuntu Server: the dashboard (served by nginx) plus the agent that feeds it live data.
# Usage:  sudo ./install-server.sh [port]        (default port 8080; re-run any time to update)
#         sudo ./install-server.sh --uninstall
set -euo pipefail

SITE=/etc/nginx/sites-available/sentinel
ROOT=/var/www/sentinel
AGENT_DIR=/opt/sentinel
UNIT=/etc/systemd/system/sentinel-agent.service
TOKEN_FILE=/etc/sentinel/token
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/web"
AGENT_SRC="$HERE/agent/sentinel_agent.py"

if [[ $EUID -ne 0 ]]; then exec sudo bash "$0" "$@"; fi

if [[ "${1:-}" == "--uninstall" ]]; then
  systemctl disable --now sentinel-agent >/dev/null 2>&1 || true
  rm -f "$UNIT" /etc/nginx/sites-enabled/sentinel "$SITE"
  systemctl daemon-reload || true
  rm -rf "$ROOT" "$AGENT_DIR" /etc/sentinel /var/lib/sentinel
  nginx -t >/dev/null 2>&1 && systemctl reload nginx || true
  echo "Sentinel removed. nginx itself was left installed."
  echo "Any addresses Sentinel blocked are still in ufw; list them with: sudo ufw status numbered"
  exit 0
fi

# Re-running without a port keeps the port already in use
PORT="${1:-}"
if [[ -z "$PORT" && -f "$SITE" ]]; then
  PORT="$(grep -m1 -oE 'listen [0-9]+' "$SITE" | grep -oE '[0-9]+' || true)"
fi
PORT="${PORT:-8080}"
[[ "$PORT" =~ ^[0-9]+$ ]] || { echo "Port must be a number, for example 8088."; exit 1; }
[[ -f "$SRC/index.html" ]] || { echo "Can't find web/index.html next to this script. Run it from the unzipped Sentinel folder."; exit 1; }
[[ -f "$AGENT_SRC" ]] || { echo "Can't find agent/sentinel_agent.py next to this script."; exit 1; }

port_busy() { ss -ltnH "( sport = :$1 )" 2>/dev/null | grep -q . ; }
current_port=""
[[ -f "$SITE" ]] && current_port="$(grep -m1 -oE 'listen [0-9]+' "$SITE" | grep -oE '[0-9]+' || true)"
if [[ "$current_port" != "$PORT" ]] && port_busy "$PORT"; then
  echo "Port $PORT is already used by another program:"
  ss -ltnpH "( sport = :$PORT )" 2>/dev/null || true
  echo "Pick a free port, for example:  sudo ./install-server.sh 8088"
  exit 1
fi

FRESH=0
NEED=()
command -v nginx >/dev/null || { NEED+=(nginx); FRESH=1; }
command -v python3 >/dev/null || NEED+=(python3)
if (( ${#NEED[@]} )); then
  echo "==> Installing ${NEED[*]}"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq "${NEED[@]}" >/dev/null
fi

# arp-scan finds devices on your home network even when they ignore ping (optional but recommended)
if ! command -v arp-scan >/dev/null; then
  echo "==> Installing arp-scan (finds devices on your home network)"
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq arp-scan >/dev/null 2>&1 || echo "    Couldn't install arp-scan; Sentinel will use ping instead."
fi

echo "==> Copying the dashboard to $ROOT"
rm -rf "$ROOT"
install -d "$ROOT"
cp -r "$SRC"/. "$ROOT"/
chown -R www-data:www-data "$ROOT"
find "$ROOT" -type d -exec chmod 755 {} +
find "$ROOT" -type f -exec chmod 644 {} +

echo "==> Installing the Sentinel agent"
install -d -m 755 "$AGENT_DIR"
install -m 755 "$AGENT_SRC" "$AGENT_DIR/sentinel_agent.py"
install -d -m 700 /etc/sentinel /var/lib/sentinel
if [[ ! -s "$TOKEN_FILE" ]]; then
  python3 -c 'import secrets; print(secrets.token_urlsafe(12))' > "$TOKEN_FILE"
fi
chmod 600 "$TOKEN_FILE"
cat > "$UNIT" <<UNITFILE
[Unit]
Description=Sentinel agent (feeds live security data to the Sentinel dashboard)
After=network-online.target systemd-journald.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $AGENT_DIR/sentinel_agent.py
Restart=always
RestartSec=5
# Runs as root so it can read the system log and all sockets, and add ufw rules when you block an address.
# It only listens on 127.0.0.1; nginx forwards /api/ to it.
Environment=PYTHONUNBUFFERED=1
PrivateTmp=true
ProtectHome=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNITFILE
systemctl daemon-reload
systemctl enable sentinel-agent >/dev/null 2>&1
systemctl restart sentinel-agent

echo "==> Configuring nginx on port $PORT"
cat > "$SITE" <<NGINX
server {
    listen $PORT;
    listen [::]:$PORT;
    server_name _;
    root $ROOT;
    index index.html;

    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options SAMEORIGIN always;
    add_header Referrer-Policy same-origin always;
    add_header Cache-Control "no-cache" always;

    location / {
        try_files \$uri \$uri/ /index.html;
    }
    location /api/ {
        proxy_pass http://127.0.0.1:8765;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_read_timeout 15s;
        client_max_body_size 16k;
    }
    location ~ \.webmanifest\$ {
        types { }
        default_type application/manifest+json;
    }
}
NGINX
ln -sf "$SITE" /etc/nginx/sites-enabled/sentinel
# nginx's stock welcome page listens on port 80, which is often taken on a server
if [[ -L /etc/nginx/sites-enabled/default ]] && { [[ $FRESH -eq 1 ]] || port_busy 80; }; then
  if [[ $FRESH -eq 1 ]] || ! systemctl is-active --quiet nginx; then
    echo "==> Turning off nginx's default welcome page (port 80)"
    rm -f /etc/nginx/sites-enabled/default
  fi
fi
nginx -t
systemctl enable nginx >/dev/null 2>&1 || true
if ! systemctl restart nginx; then
  echo
  echo "nginx could not start. The last log lines usually name the cause:"
  journalctl -u nginx --no-pager -n 12 2>/dev/null || true
  exit 1
fi

if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  echo "==> Allowing port $PORT through the firewall (ufw)"
  ufw allow "$PORT"/tcp >/dev/null
fi

# pfSense can send its firewall log here (UDP 5140). Only the router is allowed to send.
GW="$(ip route 2>/dev/null | awk '/^default/ {print $3; exit}')"
if [[ -n "$GW" ]] && command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  echo "==> Allowing your router ($GW) to send its firewall log to Sentinel (UDP 5140)"
  ufw allow from "$GW" to any port 5140 proto udp comment 'Sentinel pfSense log' >/dev/null || true
fi
# SSH key Sentinel can use to add blocks in pfSense (only if you paste it into pfSense yourself)
if [[ ! -f /etc/sentinel/pfsense_key ]] && command -v ssh-keygen >/dev/null; then
  ssh-keygen -q -t ed25519 -N "" -C "sentinel@$(hostname)" -f /etc/sentinel/pfsense_key
  chmod 600 /etc/sentinel/pfsense_key
fi

# Check the agent answers through nginx
ok=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if curl -fsS "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1; then ok=1; break; fi
  sleep 1
done

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo
if [[ $ok -eq 1 ]]; then
  echo "Sentinel is running with live data."
else
  echo "The dashboard is running, but the agent isn't answering yet."
  echo "Check it with: systemctl status sentinel-agent"
fi
echo "  Open:        http://${IP:-<server-ip>}:$PORT"
echo "  Access key:  $(cat "$TOKEN_FILE")"
echo "  (The dashboard asks for this key the first time you block an address or change an alert."
echo "   To see it again: sudo cat $TOKEN_FILE)"
if ! command -v ufw >/dev/null || ! ufw status | grep -q "Status: active"; then
  echo
  echo "Note: the ufw firewall is off, so blocking addresses won't take effect yet. To turn it on safely:"
  echo "  sudo ufw allow OpenSSH && sudo ufw allow $PORT/tcp && sudo ufw enable"
fi
