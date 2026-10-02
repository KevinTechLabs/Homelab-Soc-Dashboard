# Homelab SOC Dashboard

A self-hosted **security operations center (SOC) dashboard and network threat monitor** for a home lab. The dashboard is called **Sentinel**. It runs on an Ubuntu server, watches the server and the whole home network in real time, maps detections to **MITRE ATT&CK**, pulls in **pfSense** firewall logs, and sends alerts to **Discord**.

![Overview](docs/screenshots/overview.png)

> Screenshots show the built-in demo mode with example data. No real addresses or hosts are shown.

## Highlights

- **Live detection engine** in plain Python 3 (standard library only). It reads the systemd journal, `/proc`, ufw and socket tables, with no agents to install on other machines.
- **MITRE ATT&CK mapping** for every alert, plus an ATT&CK tactic heat map on the dashboard.
- **pfSense integration:** router firewall logs over syslog, device discovery in every VLAN from DHCP events, and optional network-wide blocking through pfSense `easyrule`.
- **Network visibility:** device discovery (arp-scan, ping, pfSense DHCP), vendor lookup, risky-port checks per device, ARP-spoofing detection, and the Tailscale device list.
- **Private-address aware:** phones that rotate their private Wi-Fi address come back looking like new devices. Sentinel suggests merging them with the device you already named, but only if both addresses are private, they share a network name and zone, and they were never online at the same time. Nothing merges until you confirm. A two-tap button removes every offline device you haven't marked as yours.
- **Response actions:** block and unblock attackers (ufw on the server, or pfSense for the whole network), optional auto-block, alert acknowledge, escalate and close, and a one-click clear of the hostile-sources list (blocked addresses stay).
- **Wazuh SIEM integration:** pulls Wazuh alerts (rule, agent, MITRE mapping, deep link), agent health and vulnerability counts through Wazuh's indexer and server APIs, using read-only accounts and certificate pinning. Alerts when a watched device's agent stops reporting (T1562.001); agents on machines you switch off just log a line.
- **Discord notifications:** rate-limited alerts for high and critical events, plus a daily summary in your time zone.
- **Runs anywhere you look:** a responsive web app (installable on phone and PC), a Windows app-window launcher, and an optional Electron desktop build.
- **Secure by default:** the API listens on localhost behind nginx, actions need an access key, and the webhook is never sent to the browser.

## Screenshots

| Network map | Devices |
|---|---|
| ![Network](docs/screenshots/network.png) | ![Devices](docs/screenshots/devices.png) |

| Alerts | Respond |
|---|---|
| ![Alerts](docs/screenshots/alerts.png) | ![Respond](docs/screenshots/respond.png) |

![Wazuh SIEM and vulnerabilities on the Overview](docs/screenshots/wazuh.png)

<p align="center"><img src="docs/screenshots/mobile.png" width="300" alt="Mobile view"></p>

## Architecture

```text
 Phone / PC browser ──HTTP──► nginx :8088 ──/api/──► sentinel_agent.py (127.0.0.1:8765)
                               │  static dashboard        │
                               └─ web/index.html          ├─ journalctl (sshd, sudo, su, kernel/ufw)
                                                          ├─ /proc (CPU, memory, disk, sockets, traffic)
                                                          ├─ systemctl, ufw, sshd settings
                                                          ├─ arp-scan / ping sweep, port checks
                                                          ├─ tailscale status --json
                                                          ├─ UDP 5140 ◄── pfSense syslog (firewall + DHCP)
                                                          ├─ HTTPS (pinned) ──► Wazuh indexer :9200 + API :55000 (read-only, optional)
                                                          ├─ SSH ──► pfSense easyrule (optional)
                                                          └─ HTTPS ──► Discord webhook, ip-api.com (geo)
```

State lives in `/var/lib/sentinel/state.json`, and the access key in `/etc/sentinel/token`.

## Detections

| Detection | Severity | ATT&CK technique | Tactic |
|---|---|---|---|
| SSH brute-force attempt | high / critical | T1110.001 | Credential Access |
| Password spray across accounts | high | T1110.003 | Credential Access |
| Login succeeded after repeated failures | critical | T1078 | Initial Access |
| Direct root login over SSH | high | T1078.003 | Initial Access |
| Sign-in from a new address | low / medium | T1078 | Initial Access |
| Repeated sudo password failures | medium | T1548.003 | Privilege Escalation |
| Port scan (server firewall) | medium | T1046 | Discovery |
| Port scan stopped at the router (pfSense) | low | T1046 | Discovery |
| New service listening on the network | medium | T1543 | Persistence |
| Service stopped or failed | medium / high | T1489 | Impact |
| Sustained high CPU | low | T1496 | Impact |
| Disk almost full | medium | T1499 | Impact |
| New device joined the network | medium | T1200 | Initial Access |
| Router hardware address changed (ARP spoofing) | critical | T1557.002 | Credential Access |
| Risky service on a device (Telnet, TR-069, FTP, VNC, RDP, ADB, ...) | high / medium | T1021, T1133 | Lateral Movement / Initial Access |
| New device joined the Tailscale network | high | T1078 | Initial Access |
| Watched device went offline | medium | — | Impact |
| Wazuh agent stopped reporting | medium | T1562.001 | Defense Evasion |
| Any Wazuh alert level 7+ (Sysmon, auth, FIM, vulnerability, ...) | mapped from Wazuh level | from the Wazuh rule | from the Wazuh rule |

Noise control: repeated events are grouped per source and hour. Router log lines are rolled up per attacker every 5 minutes. Late reply packets (TCP without SYN, UDP from DNS/QUIC/NTP servers) and one-off drops aren't counted as hostile sources.

## Install (Ubuntu Server)

```bash
git clone https://github.com/KevinTechLabs/Homelab-Soc-Dashboard.git
cd Homelab-Soc-Dashboard
sudo ./install-server.sh 8088
```

The installer:
- installs nginx, python3 and arp-scan if needed
- sets up the `sentinel-agent` systemd service
- configures nginx on the chosen port
- opens that port in ufw
- allows the router to send logs to UDP 5140
- prints the dashboard address and your **access key**

Open `http://SERVER-IP:8088` from your PC or phone. Managing alerts (acknowledge, escalate, close) needs no key. Actions that change something, like blocking an address, notifications or the pfSense link, ask for the access key once per browser; to see it again, run `sudo cat /etc/sentinel/token`.

Re-run the installer to update. To remove Sentinel, run `sudo ./install-server.sh --uninstall`.

> Keep the dashboard on your home network or behind a VPN such as Tailscale. Don't port-forward it.

### Network zones (optional)

If your network uses VLANs, give each subnet a friendly name. The Devices tab and network map show these labels:

```bash
sudo cp examples/zones.example.json /etc/sentinel/zones.json   # then edit it with your subnets
sudo systemctl restart sentinel-agent
```

## Wazuh SIEM (optional)

If Wazuh runs on the same server, Sentinel shows its alerts, agents and vulnerabilities alongside its own detections. Create two **read-only** accounts in Wazuh:

1. **Indexer management → Security → Internal users:** create `sentinel`, then map it to the `readall` role.
2. **Server management → Security → Users:** create `sentinel-api` with the `readonly` role.
3. On the server:
   ```bash
   sudo python3 /opt/sentinel/sentinel_agent.py --wazuh-setup   # prompts for both passwords (hidden)
   sudo systemctl restart sentinel-agent
   ```

Design notes:
- Credentials live only in `/etc/sentinel/wazuh.json` (mode 600) and never reach the browser.
- Wazuh uses self-signed certificates, so the setup records each certificate's SHA-256 fingerprint and every request is checked against it (trust on first use). A changed certificate stops the integration instead of silently trusting it.
- Alerts are read incrementally with a persisted cursor and de-duplicated by document ID, then grouped per rule, agent and hour so a noisy rule becomes one alert with a count.
- Both accounts are read-only: Sentinel can see Wazuh but can't change it.

## Discord alerts

In the dashboard, go to **Respond → Discord notifications**:
1. In Discord, open **Server Settings → Integrations → Webhooks → New Webhook**, pick the channel, and copy the URL.
2. Paste it into the dashboard and tap **Connect**. The webhook is verified with Discord before it's saved.
3. Choose **high and critical** or **critical only**, and optionally turn on the **daily summary** at a time of your choice.

At most 6 alert messages post per 5 minutes. When more fire in that time, the next message says how many were held back. The webhook is stored only on the server.

## pfSense integration

**Firewall and DHCP logs (recommended):** in pfSense, go to **Status → System Logs → Settings → Remote Logging**. Set the remote server to `SERVER-IP:5140` and tick **Firewall Events** and **DHCP Events**. You get:
- everything the router blocks, rolled up per attacker
- port scans stopped at the router
- attackers shown in green on the map
- devices from **every VLAN**, labeled with their zone

**Network-wide blocking (optional):** turn on SSH in pfSense with **Public Key Only**, then paste the dashboard's public key into **System → User Manager → admin → Authorized SSH Keys**. **Block** on an internet address then runs `easyrule block wan <address>`, protecting every device. This gives the server the ability to change your router's firewall, so skip it if that trade-off isn't right for you.

## Other ways to open the dashboard

- **Windows app window:** run `Install Shortcuts.bat` for Desktop and Start-menu shortcuts that open the dashboard in its own Edge app window.
- **Desktop app (Electron):** `npm install`, then `npm start`, or `npm run build:win` for an installer and portable `.exe`.
- **Installable web app:** the `web/` folder has a manifest, icons and a service worker. Host it over HTTPS to install it on a phone or PC.

If the dashboard can't reach the agent, it runs in **demo mode** with simulated data and says so in a banner.

## Project layout

| Path | Purpose |
|---|---|
| `agent/sentinel_agent.py` | Detection engine and JSON API (Python 3, standard library only) |
| `web/index.html` | The whole dashboard (single file, no build step) |
| `web/manifest.webmanifest`, `web/sw.js`, `web/icons/` | Installable web-app support |
| `install-server.sh` | Ubuntu installer and updater (nginx + systemd) |
| `examples/zones.example.json` | Example VLAN zone names |
| `main.js`, `package.json` | Optional Electron desktop shell |
| `Start Sentinel.bat`, `Install Shortcuts.bat` | Windows app-window launcher |

## Tech

Python 3 (stdlib `http.server`, `subprocess`, `socket`), vanilla JavaScript and Canvas (no framework), nginx, systemd, ufw, journald, pfSense syslog/easyrule, the Discord webhook API, the Wazuh indexer and server REST APIs, and the Tailscale CLI.

## Related

The home-lab network this dashboard monitors, including VLAN zones, pfSense rules, Suricata, pfBlockerNG and Pi-hole, is documented in [Desk-Pi-Rack](https://github.com/KevinTechLabs/Desk-Pi-Rack).
