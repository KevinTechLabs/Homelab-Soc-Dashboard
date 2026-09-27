#!/usr/bin/env python3
"""
Sentinel agent - watches this Ubuntu server and feeds the Sentinel dashboard.

Reads:  the systemd journal (sshd, sudo, su, kernel/ufw), /proc (CPU, memory,
        network, sockets), systemctl, ufw and sshd settings.
Serves: GET  /api/state      one JSON snapshot for the dashboard
        POST /api/alert      {"id": "...", "action": "ack|escalate|close|reopen"}
        POST /api/block      {"ip": "..."}   (adds a ufw deny rule)
        POST /api/unblock    {"ip": "..."}
        POST /api/settings   {"autoblock": bool, "notify": {...}}
        POST /api/notify-test post a test message to your Discord channel
        POST /api/device     {"mac": "...", "action": "rename|known|watch|scan|forget", ...}
        POST /api/lan-sweep  look for devices on the home network now
        POST /api/pfsense    {"action": "save|test|key|disconnect", ...}  pfSense router link
POST requests need the access key from /etc/sentinel/token in the X-Sentinel-Key header.

Standard library only. Listens on 127.0.0.1:8765; nginx forwards /api/ to it.
"""
import collections
import hmac
import ipaddress
import json
import os
import platform
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "1.5.3"
BIND_HOST = os.environ.get("SENTINEL_BIND", "127.0.0.1")
BIND_PORT = int(os.environ.get("SENTINEL_PORT", "8765"))
STATE_DIR = os.environ.get("SENTINEL_STATE_DIR", "/var/lib/sentinel")
STATE_FILE = os.path.join(STATE_DIR, "state.json")
TOKEN_FILE = os.environ.get("SENTINEL_TOKEN_FILE", "/etc/sentinel/token")
WEB_ROOT = os.environ.get("SENTINEL_WEB_ROOT")  # optional: serve the dashboard without nginx
JOURNAL_CMD = os.environ.get("SENTINEL_JOURNAL_CMD")  # testing hook: JSON list replacing journalctl

START_MS = int(time.time() * 1000)
HOST = socket.gethostname()
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
LOCK = threading.RLock()


def now_ms():
    return int(time.time() * 1000)


def run(cmd, timeout=10):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:  # missing binary, timeout
        return 127, "", str(e)


LAN_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                                 "169.254.0.0/16", "127.0.0.0/8", "fc00::/7", "fe80::/10", "::1/128")]


def is_private(ip):
    """True for home/office network, VPN (Tailscale/CGNAT), link-local and loopback addresses."""
    try:
        a = ipaddress.ip_address(ip)
        if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
            a = a.ipv4_mapped
        return any(a in n for n in LAN_NETS if n.version == a.version)
    except ValueError:
        return False


def is_loopback(ip):
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def norm_ip(ip):
    try:
        a = ipaddress.ip_address(ip)
        if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
            return str(a.ipv4_mapped)
        return str(a)
    except ValueError:
        return None


# --------------------------------------------------------------------------- state
PF_DEFAULTS = {"enabled": False, "host": "", "user": "admin", "iface": "wan", "port": 5140}
# Network zones (VLANs) shown as labels on the Devices tab. Anything else shows as its /24 network.
# Set your own in /etc/sentinel/zones.json, e.g. {"10.20.1.0/24": "Main LAN", "10.20.10.0/24": "Trusted"}
ZONES_FILE = os.environ.get("SENTINEL_ZONES_FILE", "/etc/sentinel/zones.json")
DEFAULT_ZONES = [("10.20.1.0/24", "Main LAN"), ("10.20.10.0/24", "Trusted"), ("10.20.30.0/24", "Gaming & IoT"),
                 ("10.20.40.0/24", "Lab"), ("10.20.50.0/24", "Guest"), ("10.20.99.0/24", "Management")]


def load_zones():
    try:
        with open(ZONES_FILE) as f:
            data = json.load(f)
        items = data.items() if isinstance(data, dict) else [(z["cidr"], z["name"]) for z in data]
        zones = [(str(ipaddress.ip_network(c, strict=False)), str(n)[:32]) for c, n in items]
        if zones:
            return zones
    except FileNotFoundError:
        pass
    except Exception as ex:
        print("sentinel: ignoring %s (%s); using the default zones" % (ZONES_FILE, ex), file=sys.stderr)
    return DEFAULT_ZONES


ZONES = load_zones()
ZONE_NETS = [(ipaddress.ip_network(n), name) for n, name in ZONES]


def zone_of(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    for net, name in ZONE_NETS:
        if a in net:
            return name
    if a.version == 4:
        return str(ipaddress.ip_network("%s/24" % ip, strict=False))
    return ""


PF_KEY = os.environ.get("SENTINEL_PF_KEY", "/etc/sentinel/pfsense_key")
PF_KNOWN = os.path.join(os.path.dirname(PF_KEY), "pfsense_known_hosts")
SSH_BIN = os.environ.get("SENTINEL_SSH", "ssh")
NOTIFY_DEFAULTS = {"enabled": False, "minSev": "high", "summary": False, "summaryHour": 8,
                   "tz": "", "webhook": "", "webhookName": "", "click": "", "lastSummary": ""}


class Store:
    def __init__(self):
        self.alerts = collections.OrderedDict()   # key -> alert
        self.by_id = {}
        self.seq = 1000
        self.events = collections.deque(maxlen=400)
        self.evseq = 0
        self.counts = collections.deque(maxlen=300000)  # (t, kind), kept 25 h for hourly totals and the daily summary
        self.sources = {}          # ip -> info
        self.known_logins = {}     # user -> [ip]
        self.baseline_ports = None
        self.settings = {"autoblock": False, "notify": dict(NOTIFY_DEFAULTS)}
        self.notify_status = ""
        self.settings["devices"] = {"notifyNew": True}
        self.devices = {}          # mac -> home-network device
        self.tailnet = {}          # node key -> Tailscale device
        self.geo = {}              # ip -> location of an attacking address
        self.gateway_mac = ""
        self.lan = {}
        self.settings["pfsense"] = dict(PF_DEFAULTS)
        self.pf = {"lastLog": 0, "sshOk": None, "sshMsg": "", "edgeBlocked": set(), "lastCheck": 0, "recent": {},
                   "nbrOk": None, "nbrMsg": "", "nbrLast": 0, "nbrCount": 0, "nbrSeen": False, "dhcpLast": 0}
        self.learning = True       # first run: learn existing logins/ports quietly
        self.dirty = False
        # rolling windows (not persisted)
        self.fails = collections.defaultdict(collections.deque)      # ip -> (t, user)
        self.fw_ports = collections.defaultdict(collections.deque)   # ip -> (t, port)
        self.sudo_fails = collections.defaultdict(collections.deque) # user -> t
        # live system data
        self.metrics = {}
        self.rx = collections.deque(maxlen=150)
        self.tx = collections.deque(maxlen=150)
        self.iface = None
        self.net = {"established": 0, "peers": [], "listening": [], "protocols": {}}
        self.new_conns = collections.deque()
        self.services = []
        self.checks = []
        self.ufw_state = "unknown"
        self.blocked = set()
        self.my_ips = set()

    # ---- persistence
    def load(self):
        try:
            with open(STATE_FILE) as f:
                d = json.load(f)
        except FileNotFoundError:
            return
        except Exception as e:
            print("sentinel: could not read state:", e, file=sys.stderr)
            return
        self.learning = False
        self.seq = d.get("seq", self.seq)
        for a in d.get("alerts", []):
            self.alerts[a["key"]] = a
            self.by_id[a["id"]] = a
        self.known_logins = d.get("known_logins", {})
        dst = (d.get("settings") or {}).get("devices")
        if isinstance(dst, dict):
            self.settings["devices"].update(dst)
        self.devices = d.get("devices", {})
        t0 = now_ms()
        for dv in self.devices.values():
            # devices learned from the router's DHCP log stay online until they've been quiet for 3 hours;
            # the server's own sweep re-checks the rest within 5 minutes of starting
            recent = dv.get("via") == "router" and dv.get("online") and t0 - dv.get("last", 0) < 3 * 3600000
            dv["online"] = bool(recent)
            dv["missed"] = 0 if recent else 2
        self.tailnet = d.get("tailnet", {})
        self.geo = d.get("geo", {})
        self.gateway_mac = d.get("gateway_mac", "")
        pst = (d.get("settings") or {}).get("pfsense")
        if isinstance(pst, dict):
            self.settings["pfsense"].update({k: v for k, v in pst.items() if k in PF_DEFAULTS})
        self.pf["edgeBlocked"] = set(d.get("pf_blocked", []))
        self.pf["sshOk"] = d.get("pf_ssh_ok")
        self.pf["nbrSeen"] = bool(d.get("pf_nbr_seen"))
        self.pf["dhcpLast"] = int(d.get("pf_dhcp_last") or 0)
        self.pf["lastLog"] = int(d.get("pf_last_log") or 0)
        bp = d.get("baseline_ports")
        self.baseline_ports = set(bp) if bp is not None else None
        st = d.get("settings", {})
        self.settings["autoblock"] = bool(st.get("autoblock", False))
        self.settings["notify"].update({k: v for k, v in st.get("notify", {}).items() if k in NOTIFY_DEFAULTS})
        cutoff = now_ms() - 7 * 86400000
        for s in d.get("sources", []):
            if s.get("last", 0) > cutoff and not (s.get("lan") and not s.get("fails")) and not not_a_host(s.get("ip", "")):
                s["users"] = set(s.get("users", []))
                s["ports"] = set(s.get("ports", []))
                self.sources[s["ip"]] = s

    def save(self):
        d = {
            "version": VERSION,
            "seq": self.seq,
            "alerts": list(self.alerts.values())[-300:],
            "known_logins": self.known_logins,
            "baseline_ports": sorted(self.baseline_ports) if self.baseline_ports is not None else None,
            "devices": {k: {kk: vv for kk, vv in v.items() if kk not in ("scanNow",)} for k, v in self.devices.items()},
            "tailnet": self.tailnet,
            "geo": dict(list(self.geo.items())[-3000:]),
            "gateway_mac": self.gateway_mac,
            "pf_blocked": sorted(self.pf["edgeBlocked"]),
            "pf_ssh_ok": self.pf.get("sshOk"),
            "pf_nbr_seen": self.pf.get("nbrSeen", False),
            "pf_dhcp_last": self.pf.get("dhcpLast", 0),
            "pf_last_log": self.pf.get("lastLog", 0),
            "settings": self.settings,
            "sources": [dict(s, users=sorted(s["users"])[:50], ports=sorted(s["ports"])[:50])
                        for s in self.sources.values()],
        }
        os.makedirs(STATE_DIR, exist_ok=True)
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(d, f)
        os.replace(tmp, STATE_FILE)
        self.dirty = False


S = Store()


def add_event(t, act, text, kind, hot=False):
    S.evseq += 1
    S.events.append({"id": S.evseq, "t": t, "act": act, "text": text, "hot": hot})
    S.counts.append((t, kind))


def source(ip, t):
    s = S.sources.get(ip)
    if not s:
        s = {"ip": ip, "first": t, "last": t, "fails": 0, "blocks": 0, "users": set(),
             "ports": set(), "lan": is_private(ip), "why": ""}
        S.sources[ip] = s
    s["last"] = max(s["last"], t)
    S.dirty = True
    return s


def upsert_alert(key, sev, title, tech, tac, det, t, src=None, user=None, count=None):
    a = S.alerts.get(key)
    if a:
        if count is not None:
            a["count"] = count
        a["last"] = max(a["last"], t)
        a["det"] = det
        if SEV_RANK[sev] < SEV_RANK[a["sev"]]:
            a["sev"] = sev
            a["log"].append([t, "Severity raised to " + sev])
            if a["status"] == "closed":
                a["status"] = "new"
                a["log"].append([t, "Reopened by new activity"])
            maybe_autoblock(a)
            maybe_notify(a, t)
        S.dirty = True
        return a
    S.seq += 1
    a = {"id": "SEN-%d" % S.seq, "key": key, "time": t, "last": t, "sev": sev, "t": title,
         "tech": tech, "tac": tac, "det": det, "host": HOST, "src": src or "—", "user": user or "—",
         "status": "new", "owner": None, "ackAt": None, "count": count or 1,
         "log": [[t, "Detected by Sentinel agent"]]}
    S.alerts[key] = a
    S.by_id[a["id"]] = a
    while len(S.alerts) > 300:
        k, old = S.alerts.popitem(last=False)
        S.by_id.pop(old["id"], None)
    S.dirty = True
    maybe_autoblock(a)
    maybe_notify(a, t)
    return a


def hour(t):
    return int(t // 3600000)


# --------------------------------------------------------------------------- journal parsing
RX_FAIL = re.compile(r"Failed (\S+) for (invalid user )?(\S*) from (\S+) port (\d+)")
RX_INVALID = re.compile(r"Invalid user (\S*) from (\S+)")
RX_OK = re.compile(r"Accepted (\S+) for (\S+) from (\S+) port (\d+)")
RX_UFW = re.compile(r"\[UFW (?:LIMIT )?BLOCK\].*?SRC=(\S+) DST=(\S+).*?PROTO=(\S+)(?:.*?DPT=(\d+))?")
RX_SUDO_CMD = re.compile(r"^\s*(\S+) : .*?COMMAND=(.*)$")
RX_SUDO_FAIL1 = re.compile(r"^\s*(\S+) : (\d+) incorrect password attempts?")
RX_SUDO_FAIL2 = re.compile(r"pam_unix\((?:sudo|su|su-l):auth\): authentication failure;.*?ruser=(\S*)")


def prune(dq, cutoff):
    while dq and dq[0][0] < cutoff:
        dq.popleft()


def on_ssh_fail(t, ip, user, invalid, count_it, backfill):
    s = source(ip, t)
    s["fails"] += 1
    if user:
        s["users"].add(user)
    s["why"] = "SSH login failures"
    add_event(t, "FAIL", "SSH login failed for %s%s from %s" % ("invalid user " if invalid else "", user or "?", ip), "fail", hot=True)
    if not count_it:
        return
    dq = S.fails[ip]
    dq.append((t, user))
    prune(dq, t - 30 * 60000)
    n60 = sum(1 for x in dq if x[0] > t - 60000)
    n5 = sum(1 for x in dq if x[0] > t - 300000)
    if n60 >= 5 or n5 >= 10:
        sev = "critical" if n5 >= 40 else "high"
        upsert_alert("bf:%s:%d" % (ip, hour(t)), sev, "SSH brute-force attempt", "T1110.001",
                     "Credential Access", "%d failed SSH logins in 5 minutes from %s" % (n5, ip),
                     t, src=ip, user=user, count=s["fails"])
    users5 = {u for (tt, u) in dq if tt > t - 300000 and u}
    if len(users5) >= 4:
        upsert_alert("sp:%s:%d" % (ip, hour(t)), "high", "Password spray across accounts", "T1110.003",
                     "Credential Access", "%d different usernames tried from %s in 5 minutes (%s)"
                     % (len(users5), ip, ", ".join(sorted(users5)[:6])), t, src=ip, count=len(users5))


def on_ssh_ok(t, ip, user, method, backfill):
    add_event(t, "ALLOW", "SSH login accepted for %s from %s (%s)" % (user, ip, method), "login")
    dq = S.fails.get(ip)
    recent = sum(1 for x in dq if x[0] > t - 30 * 60000) if dq else 0
    if recent >= 3:
        upsert_alert("sf:%s:%s:%d" % (ip, user, hour(t)), "critical", "Login succeeded after repeated failures",
                     "T1078", "Initial Access", "%s signed in from %s after %d failed attempts" % (user, ip, recent),
                     t, src=ip, user=user)
    if user == "root":
        upsert_alert("root:%s:%d" % (ip, t // 86400000), "high", "Direct root login over SSH", "T1078.003",
                     "Privilege Escalation", "root signed in over SSH from %s using %s" % (ip, method), t, src=ip, user=user)
    known = S.known_logins.setdefault(user, [])
    if ip not in known:
        if not (S.learning and backfill):
            upsert_alert("new:%s:%s" % (user, ip), "medium" if not is_private(ip) else "low",
                         "Sign-in from a new address", "T1078", "Initial Access",
                         "%s signed in from %s for the first time (%s)" % (user, ip, method), t, src=ip, user=user)
        known.append(ip)
        del known[:-50]
        S.dirty = True


def on_sudo_fail(t, user):
    add_event(t, "FAIL", "sudo/su password failure for %s" % (user or "?"), "fail", hot=True)
    dq = S.sudo_fails[user]
    dq.append((t,))
    prune(dq, t - 600000)
    if len(dq) >= 3:
        upsert_alert("sudo:%s:%d" % (user, hour(t)), "medium", "Repeated sudo password failures", "T1548.003",
                     "Privilege Escalation", "%d failed sudo/su password attempts by %s in 10 minutes" % (len(dq), user),
                     t, user=user, count=len(dq))


def is_broadcast(ip):
    """Multicast/broadcast destinations (UPnP, mDNS, DHCP...) are routine home-network chatter."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.is_multicast or ip == "255.255.255.255":
        return True
    return a.version == 4 and ip.endswith(".255")


def on_ufw(t, src, dst, proto, dpt):
    src = norm_ip(src) or src
    if src in S.my_ips or is_broadcast(norm_ip(dst) or dst):
        return
    s = source(src, t)
    s["blocks"] += 1
    if dpt:
        s["ports"].add(int(dpt))
    if not s["why"]:
        s["why"] = "Blocked by firewall"
    add_event(t, "DROP", "%s → %s%s %s blocked by firewall" % (src, dst, ":" + dpt if dpt else "", proto), "drop")
    if dpt:
        dq = S.fw_ports[src]
        dq.append((t, int(dpt)))
        prune(dq, t - 120000)
        ports = {p for (_, p) in dq}
        if len(ports) >= 10:
            s["why"] = "Port scanning"
            upsert_alert("scan:%s:%d" % (src, hour(t)), "medium", "Port scan detected", "T1046", "Discovery",
                         "%s probed %d different ports in 2 minutes" % (src, len(ports)), t, src=src, count=len(ports))


def handle_entry(e):
    msg = e.get("MESSAGE")
    if isinstance(msg, list):
        try:
            msg = bytes(msg).decode("utf-8", "replace")
        except Exception:
            return
    if not msg:
        return
    ident = e.get("SYSLOG_IDENTIFIER", "")
    try:
        t = int(int(e.get("__REALTIME_TIMESTAMP", "0")) / 1000) or now_ms()
    except ValueError:
        t = now_ms()
    backfill = t < START_MS - 2000
    if ident.startswith("sshd"):
        m = RX_FAIL.search(msg)
        if m:
            ip = norm_ip(m.group(4))
            if ip:
                # "Failed ... for invalid user" follows an "Invalid user" line we already counted
                on_ssh_fail(t, ip, m.group(3), bool(m.group(2)), not m.group(2), backfill)
            return
        m = RX_INVALID.search(msg)
        if m:
            ip = norm_ip(m.group(2))
            if ip:
                on_ssh_fail(t, ip, m.group(1), True, True, backfill)
            return
        m = RX_OK.search(msg)
        if m:
            ip = norm_ip(m.group(3))
            if ip:
                on_ssh_ok(t, ip, m.group(2), m.group(1), backfill)
            return
    elif ident in ("sudo", "su"):
        m = RX_SUDO_FAIL1.search(msg)
        if m:
            on_sudo_fail(t, m.group(1))
            return
        m = RX_SUDO_FAIL2.search(msg)
        if m:
            on_sudo_fail(t, m.group(1) or e.get("_UID", "?"))
            return
        m = RX_SUDO_CMD.search(msg)
        if m:
            add_event(t, "INFO", "sudo by %s: %s" % (m.group(1), m.group(2)[:140]), "sudo")
    elif ident == "kernel" and "UFW" in msg:
        m = RX_UFW.search(msg)
        if m:
            on_ufw(t, m.group(1), m.group(2), m.group(3), m.group(4))


def journal_loop():
    first = True
    while True:
        if JOURNAL_CMD:
            cmd = json.loads(JOURNAL_CMD)
        else:
            if not shutil.which("journalctl"):
                with LOCK:
                    add_event(now_ms(), "INFO", "journalctl not found; login and firewall monitoring is off", "system")
                return
            cmd = ["journalctl", "-f", "-o", "json", "--no-pager", "-n", "3000" if first else "0",
                   "SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session", "SYSLOG_IDENTIFIER=sudo",
                   "SYSLOG_IDENTIFIER=su", "SYSLOG_IDENTIFIER=kernel"]
        first = False
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
            for line in p.stdout:
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                with LOCK:
                    try:
                        handle_entry(e)
                    except Exception as ex:
                        print("sentinel: parse error:", ex, file=sys.stderr)
            p.wait()
        except Exception as ex:
            print("sentinel: journal reader stopped:", ex, file=sys.stderr)
        if JOURNAL_CMD:
            return
        time.sleep(5)


# --------------------------------------------------------------------------- system sampling
def read_cpu():
    with open("/proc/stat") as f:
        v = list(map(int, f.readline().split()[1:9]))
    return v[3] + v[4], sum(v)


def read_mem():
    m = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, _, rest = line.partition(":")
            m[k] = int(rest.split()[0])
    total = m.get("MemTotal", 1)
    avail = m.get("MemAvailable", m.get("MemFree", 0))
    return total, total - avail


def default_iface():
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                p = line.split()
                if p[1] == "00000000" and p[7] == "00000000":
                    return p[0]
    except Exception:
        pass
    return None


def net_bytes(iface):
    with open("/proc/net/dev") as f:
        for line in f:
            name, _, rest = line.partition(":")
            if name.strip() == iface:
                p = rest.split()
                return int(p[0]), int(p[8])
    return None


def my_addresses():
    ips = {"127.0.0.1", "::1"}
    rc, out, _ = run(["hostname", "-I"])
    if rc == 0:
        ips.update(x for x in out.split() if x)
    return ips


def hex_addr(h, v6):
    ip_hex, port_hex = h.split(":")
    port = int(port_hex, 16)
    b = bytes.fromhex(ip_hex)
    if v6:
        b = b"".join(b[i:i + 4][::-1] for i in range(0, 16, 4))
        ip = socket.inet_ntop(socket.AF_INET6, b)
    else:
        ip = socket.inet_ntop(socket.AF_INET, b[::-1])
    return norm_ip(ip) or ip, port


def read_sockets():
    out = []
    for path, v6 in (("/proc/net/tcp", False), ("/proc/net/tcp6", True)):
        try:
            with open(path) as f:
                lines = f.readlines()[1:]
        except Exception:
            continue
        for line in lines:
            p = line.split()
            if len(p) < 10 or p[3] not in ("01", "0A"):
                continue
            try:
                lip, lp = hex_addr(p[1], v6)
                rip, rp = hex_addr(p[2], v6)
            except Exception:
                continue
            out.append((p[3], lip, lp, rip, rp, p[9]))
    return out


def socket_procs(inodes):
    want, found = set(inodes), {}
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            fds = os.listdir("/proc/%s/fd" % pid)
        except Exception:
            continue
        for fd in fds:
            try:
                link = os.readlink("/proc/%s/fd/%s" % (pid, fd))
            except Exception:
                continue
            if link.startswith("socket:["):
                ino = link[8:-1]
                if ino in want and ino not in found:
                    try:
                        with open("/proc/%s/comm" % pid) as f:
                            found[ino] = f.read().strip()
                    except Exception:
                        found[ino] = "?"
        if len(found) == len(want):
            break
    return found


PORT_NAMES = {22: "SSH", 80: "HTTP", 443: "HTTPS", 53: "DNS", 25: "SMTP", 587: "SMTP", 465: "SMTP",
              993: "IMAP", 143: "IMAP", 445: "SMB", 139: "SMB", 3389: "RDP", 5900: "VNC", 11434: "Ollama",
              3000: "Web app", 8080: "Web app", 8000: "Web app", 8088: "Sentinel", 9090: "Web app",
              7860: "Web app", 8888: "Jupyter", 5432: "Postgres", 3306: "MySQL", 6379: "Redis",
              27017: "MongoDB", 2375: "Docker", 2376: "Docker", 51820: "WireGuard", 41641: "Tailscale",
              123: "NTP", 9100: "Metrics"}


def port_name(p):
    return PORT_NAMES.get(p, "Other")


WATCH = [("ssh", "Remote login (SSH)"), ("nginx", "Web server"), ("ufw", "Firewall"),
         ("fail2ban", "Brute-force blocker"), ("docker", "Containers"), ("containerd", "Container runtime"),
         ("ollama", "Local AI models"), ("open-webui", "AI web interface"), ("tailscaled", "Tailscale VPN"),
         ("cron", "Scheduled jobs"), ("systemd-journald", "System log"), ("systemd-resolved", "DNS resolver"),
         ("systemd-timesyncd", "Clock sync"), ("chrony", "Clock sync"), ("unattended-upgrades", "Automatic updates"),
         ("smbd", "File sharing"), ("postgresql", "Database"), ("mysql", "Database"), ("redis-server", "Cache"),
         ("apache2", "Web server"), ("caddy", "Web server"), ("sentinel-agent", "Sentinel agent")]


def unit_files():
    rc, out, _ = run(["systemctl", "list-unit-files", "--type=service,socket", "--no-legend", "--no-pager"])
    return {l.split()[0] for l in out.splitlines() if l.strip()} if rc == 0 else set()


_units = {"at": 0, "set": set()}
_svc_prev = {}


def sample_services():
    if time.time() - _units["at"] > 300:
        _units["set"], _units["at"] = unit_files(), time.time()
    files = _units["set"]
    names = [n for n, _ in WATCH if n + ".service" in files or (n == "ssh" and "ssh.socket" in files)]
    if not names:
        return []
    q = []
    for n in names:
        q.append(n + ".service")
        if n == "ssh":
            q.append("ssh.socket")
    rc, out, _ = run(["systemctl", "is-active"] + q)
    states = dict(zip(q, out.split()))
    desc = dict(WATCH)
    res = []
    for n in names:
        st = states.get(n + ".service", "unknown")
        if n == "ssh" and states.get("ssh.socket") == "active":
            st = "active"
        res.append({"name": n, "state": st, "desc": desc[n]})
    t = now_ms()
    for r in res:
        prev = _svc_prev.get(r["name"])
        if prev == "active" and r["state"] in ("inactive", "failed"):
            upsert_alert("svc:%s:%d" % (r["name"], hour(t)), "high" if r["state"] == "failed" else "medium",
                         "Service stopped: " + r["name"], "T1489", "Impact",
                         "%s (%s) changed from running to %s" % (r["name"], r["desc"], r["state"]), t)
            add_event(t, "ALERT", "Service %s is now %s" % (r["name"], r["state"]), "system", hot=True)
        _svc_prev[r["name"]] = r["state"]
    return res


def sshd_settings():
    cfg = {}
    rc, out, _ = run(["sshd", "-T"])
    if rc == 0:
        for line in out.splitlines():
            k, _, v = line.partition(" ")
            cfg[k.lower()] = v.strip().lower()
        return cfg
    files = ["/etc/ssh/sshd_config"]
    d = "/etc/ssh/sshd_config.d"
    if os.path.isdir(d):
        files = [os.path.join(d, x) for x in sorted(os.listdir(d)) if x.endswith(".conf")] + files
    for fn in files:
        try:
            with open(fn) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.lower().startswith("match "):
                        break
                    k, _, v = line.partition(" ")
                    cfg.setdefault(k.lower(), v.strip().lower())  # first value wins in sshd
        except Exception:
            pass
    return cfg


def ufw_status():
    if not shutil.which("ufw"):
        return "missing", set()
    rc, out, _ = run(["ufw", "status"])
    if rc != 0:
        return "unknown", set()
    state = "active" if "Status: active" in out else "inactive"
    blocked = set()
    for line in out.splitlines():
        m = re.match(r"^Anywhere(?: \(v6\))?\s+DENY(?: IN)?\s+([0-9A-Fa-f:.]+)(?:/\d+)?\b", line.strip())
        if m:
            ip = norm_ip(m.group(1))
            if ip:
                blocked.add(ip)
    return state, blocked


def run_checks():
    res = []
    st = S.ufw_state
    res.append({"id": "ufw", "name": "Firewall (ufw) is on", "ok": st == "active",
                "detail": {"active": "Unsolicited traffic is blocked",
                           "inactive": "Installed but turned off",
                           "missing": "ufw is not installed"}.get(st, "Could not read firewall status")})
    cfg = sshd_settings()
    if cfg:
        pa = cfg.get("passwordauthentication", "yes")
        res.append({"id": "sshpw", "name": "SSH password logins are off", "ok": pa == "no",
                    "detail": "Keys only" if pa == "no" else "Passwords are accepted, so brute force can work"})
        prl = cfg.get("permitrootlogin", "prohibit-password")
        ok = prl in ("no", "prohibit-password", "without-password", "forced-commands-only")
        res.append({"id": "sshroot", "name": "Root can't log in with a password", "ok": ok,
                    "detail": "PermitRootLogin " + prl})
    rc, out, _ = run(["systemctl", "is-active", "fail2ban"])
    f2b = out.strip() == "active"
    res.append({"id": "f2b", "name": "fail2ban is running", "ok": f2b,
                "detail": "Bans addresses after failed logins" if f2b else "Not running (sudo apt install fail2ban)"})
    auto = False
    try:
        with open("/etc/apt/apt.conf.d/20auto-upgrades") as f:
            auto = 'Unattended-Upgrade "1"' in f.read()
    except Exception:
        pass
    res.append({"id": "auto", "name": "Automatic security updates", "ok": auto,
                "detail": "Enabled" if auto else "Off (sudo dpkg-reconfigure unattended-upgrades)"})
    upd = None
    try:
        with open("/var/lib/update-notifier/updates-available") as f:
            txt = f.read()
        m = re.search(r"(\d+) updates? can be applied", txt)
        upd = int(m.group(1)) if m else 0
    except Exception:
        pass
    if upd is not None:
        res.append({"id": "upd", "name": "System is up to date", "ok": upd == 0,
                    "detail": "No pending updates" if upd == 0 else "%d updates waiting (sudo apt upgrade)" % upd})
    reboot = os.path.exists("/var/run/reboot-required")
    res.append({"id": "reboot", "name": "No reboot pending", "ok": not reboot,
                "detail": "Reboot to finish installing updates" if reboot else "Running the latest installed kernel"})
    return res


def sampler_loop():
    idle0, tot0 = read_cpu()
    iface = default_iface()
    nb0 = net_bytes(iface) if iface else None
    t0 = time.time()
    tick = 0
    cpu_hot = 0
    seen_conns = set()
    listen_procs = {}
    while True:
        time.sleep(2)
        tick += 1
        try:
            idle1, tot1 = read_cpu()
            cpu = 100.0 * (1 - (idle1 - idle0) / max(1, tot1 - tot0))
            idle0, tot0 = idle1, tot1
            mt, mu = read_mem()
            du = shutil.disk_usage("/")
            load = os.getloadavg()
            with open("/proc/uptime") as f:
                up = float(f.read().split()[0])
            t1 = time.time()
            if tick % 30 == 1:
                iface = default_iface() or iface
            nb1 = net_bytes(iface) if iface else None
            rx = tx = 0.0
            if nb0 and nb1:
                dt = max(0.1, t1 - t0)
                rx = max(0, nb1[0] - nb0[0]) * 8 / dt / 1e6
                tx = max(0, nb1[1] - nb0[1]) * 8 / dt / 1e6
            nb0, t0 = nb1, t1

            socks = read_sockets() if tick % 2 == 0 or tick == 1 else None
            services = sample_services() if tick % 15 == 1 else None
            if tick % 15 == 1:
                ufw = ufw_status()
                myips = my_addresses()
            with LOCK:
                t = now_ms()
                S.metrics = {"cpu": round(cpu, 1), "memUsed": mu * 1024, "memTotal": mt * 1024,
                             "diskUsed": du.used, "diskTotal": du.total, "load": [round(x, 2) for x in load],
                             "cores": os.cpu_count() or 1, "uptime": int(up)}
                S.iface = iface
                S.rx.append(round(rx, 3))
                S.tx.append(round(tx, 3))
                if tick % 15 == 1:
                    S.ufw_state, S.blocked = ufw
                    S.my_ips = myips
                if services is not None:
                    S.services = services
                cpu_hot = cpu_hot + 1 if cpu > 90 else 0
                if cpu_hot == 90:  # about 3 minutes
                    upsert_alert("cpu:%d" % hour(t), "low", "Sustained high CPU usage", "T1496", "Impact",
                                 "CPU above 90%% for 3 minutes (load %.2f)" % load[0], t)
                if tick % 15 == 1 and du.total and du.used / du.total > 0.9:
                    upsert_alert("disk:%d" % (t // 86400000), "medium", "Disk almost full", "T1499", "Impact",
                                 "/ is %d%% full" % round(du.used / du.total * 100), t)
                if socks is not None:
                    listen = [s for s in socks if s[0] == "0A"]
                    est = [s for s in socks if s[0] == "01"]
                    if tick % 15 == 1 or not listen_procs:
                        listen_procs = None  # refresh below, outside the lock is nicer but data is small
                    lports = {s[2] for s in listen}
                    peers, protos, cur = [], collections.Counter(), set()
                    for st, lip, lp, rip, rp, ino in est:
                        if is_loopback(rip) or is_loopback(lip):
                            continue
                        inbound = lp in lports
                        svc = port_name(lp if inbound else rp)
                        protos[svc] += 1
                        cur.add((lip, lp, rip, rp))
                        peers.append({"ip": rip, "port": rp, "lport": lp, "dir": "in" if inbound else "out",
                                      "svc": svc, "lan": is_private(rip)})
                    for c in cur - seen_conns:
                        S.new_conns.append(t)
                    seen_conns = cur
                    while S.new_conns and S.new_conns[0] < t - 60000:
                        S.new_conns.popleft()
                    S.net["established"] = len(peers)
                    S.net["peers"] = peers[:60]
                    S.net["protocols"] = dict(protos)
                    S.net["_listen"] = listen
            if socks is not None and (listen_procs is None):
                listen = [s for s in socks if s[0] == "0A"]
                listen_procs = socket_procs([s[5] for s in listen])
                with LOCK:
                    rows, seen = [], set()
                    for st, lip, lp, rip, rp, ino in listen:
                        exposed = not is_loopback(lip)
                        k = (lp, exposed)
                        if k in seen:
                            continue
                        seen.add(k)
                        rows.append({"port": lp, "addr": lip, "proc": listen_procs.get(ino, "?"),
                                     "exposed": exposed, "svc": port_name(lp)})
                    rows.sort(key=lambda r: (not r["exposed"], r["port"]))
                    S.net["listening"] = rows
                    exposed_now = {r["port"] for r in rows if r["exposed"]}
                    if S.baseline_ports is None:
                        S.baseline_ports = set(exposed_now)
                        S.dirty = True
                    else:
                        for r in rows:
                            if r["exposed"] and r["port"] not in S.baseline_ports:
                                upsert_alert("port:%d" % r["port"], "medium", "New service listening on the network",
                                             "T1543", "Persistence",
                                             "%s started listening on port %d (%s)" % (r["proc"], r["port"], r["addr"]),
                                             now_ms())
                                add_event(now_ms(), "ALERT", "New listening port %d (%s)" % (r["port"], r["proc"]), "system", hot=True)
                                S.baseline_ports.add(r["port"])
                                S.dirty = True
            if tick % 150 == 1:
                checks = run_checks()
                with LOCK:
                    S.checks = checks
        except Exception as ex:
            print("sentinel: sampler error:", ex, file=sys.stderr)


def saver_loop():
    while True:
        time.sleep(10)
        with LOCK:
            try:
                cutoff = now_ms() - 25 * 3600000
                while S.counts and S.counts[0][0] < cutoff:
                    S.counts.popleft()
                if S.learning and time.time() * 1000 - START_MS > 60000:
                    S.learning = False
                if S.dirty:
                    S.save()
            except Exception as ex:
                print("sentinel: could not save state:", ex, file=sys.stderr)


# --------------------------------------------------------------------------- actions
def ufw_block(ip):
    if S.ufw_state == "missing":
        return False, "ufw isn't installed, so Sentinel can't block addresses."
    rc, out, err = run(["ufw", "prepend", "deny", "from", ip, "to", "any", "comment", "Sentinel"])
    if rc != 0:
        rc, out, err = run(["ufw", "deny", "from", ip, "to", "any", "comment", "Sentinel"])
    if rc != 0:
        return False, (err or out).strip() or "ufw refused the rule"
    S.blocked.add(ip)
    note = "" if S.ufw_state == "active" else " The rule is saved, but ufw is off, so it won't take effect until you turn ufw on."
    return True, "%s blocked.%s" % (ip, note)


def ufw_unblock(ip):
    rc, out, err = run(["ufw", "delete", "deny", "from", ip, "to", "any"])
    if rc != 0:
        return False, (err or out).strip() or "ufw couldn't remove the rule"
    S.blocked.discard(ip)
    return True, "%s unblocked." % ip


def maybe_autoblock(a):
    if not S.settings.get("autoblock"):
        return
    ip = a.get("src")
    if a["key"].split(":")[0] not in ("bf", "sp", "scan") or not ip or ip == "—":
        return
    if is_private(ip) or ip in S.blocked or ip in S.pf["edgeBlocked"] or ip in S.my_ips:
        return
    if S.ufw_state != "active" and not pf_ready():
        return
    AUTO_Q.append((ip, a["key"]))
    AUTO_EVT.set()


AUTO_Q = collections.deque(maxlen=50)
AUTO_EVT = threading.Event()


def autoblock_loop():
    """Blocking can take a few seconds (SSH to pfSense), so it runs here, outside the lock."""
    while True:
        AUTO_EVT.wait(30)
        AUTO_EVT.clear()
        while AUTO_Q:
            ip, key = AUTO_Q.popleft()
            if ip in S.blocked or ip in S.pf["edgeBlocked"]:
                continue
            ok, msg = block_ip(ip)
            t = now_ms()
            with LOCK:
                a = S.alerts.get(key)
                if a:
                    a["log"].append([t, ("Automatically blocked: " + msg) if ok else ("Auto-block failed: " + msg)])
                add_event(t, "DROP" if ok else "INFO", ("Auto-blocked %s" % ip) if ok else ("Auto-block failed for %s" % ip), "system")
                S.dirty = True


# --------------------------------------------------------------------------- pfSense router
def pf_host():
    return S.settings["pfsense"].get("host") or gateway_ip() or ""


def pf_ready():
    return bool(S.settings["pfsense"].get("enabled") and S.pf.get("sshOk"))


def pf_pubkey(create=True):
    pub = PF_KEY + ".pub"
    if not os.path.exists(pub) and create:
        os.makedirs(os.path.dirname(PF_KEY), exist_ok=True)
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "sentinel@" + HOST, "-f", PF_KEY])
        try:
            os.chmod(PF_KEY, 0o600)
        except Exception:
            pass
    try:
        with open(pub) as f:
            return f.read().strip()
    except Exception:
        return ""


def pf_ssh(cmd, timeout=25):
    pf = S.settings["pfsense"]
    host = pf_host()
    if not host:
        return 1, "", "Sentinel couldn't work out your router's address. Enter it on the pfSense card."
    if not os.path.exists(PF_KEY):
        return 1, "", "No SSH key yet."
    return run([SSH_BIN, "-i", PF_KEY, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
                "-o", "UserKnownHostsFile=" + PF_KNOWN, "-o", "ConnectTimeout=8", "-o", "LogLevel=ERROR",
                "%s@%s" % (pf.get("user") or "admin", host), cmd], timeout)


def pf_explain(rc, out, err):
    text = (err or "") + (out or "")
    low = text.lower()
    if "permission denied" in low:
        return "pfSense didn't accept Sentinel's key. Paste it into System → User Manager → admin → Authorized SSH Keys and save."
    if "connection refused" in low:
        return "SSH is turned off on pfSense. Turn it on in System → Advanced → Admin Access → Secure Shell."
    if "timed out" in low or "no route" in low or "could not resolve" in low:
        return "Couldn't reach pfSense at %s. Check the router address on this card." % pf_host()
    if "enter an option" in low:
        return "pfSense showed its console menu instead of running Sentinel's command. Send a screenshot of this to get it fixed."
    if "not found" in low and "easyrule" in low:
        return "Logged in to pfSense, but its easyrule command wasn't found."
    return (text.strip().splitlines() or ["pfSense didn't answer (code %d)." % rc])[-1][:200]


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}\b")


def pf_check():
    """Log in to pfSense and read which addresses easyrule is blocking on the WAN."""
    iface = S.settings["pfsense"].get("iface") or "wan"
    rc, out, err = pf_ssh("easyrule showblock %s" % iface)
    ok = rc == 0 and "enter an option" not in (out or "").lower()
    with LOCK:
        S.pf["sshOk"] = ok
        S.pf["lastCheck"] = now_ms()
        S.pf["sshMsg"] = "Connected. Blocks apply to your whole network." if ok else pf_explain(rc, out, err)
        if ok:
            found = set()
            for tok in IP_RE.findall(out or ""):
                ip = norm_ip(tok)
                if ip and not is_private(ip):
                    found.add(ip)
            S.pf["edgeBlocked"] = found
        S.dirty = True
    return ok, S.pf["sshMsg"]


PF_NBR_CMD = ("arp -an; echo \"@@WAN@@ $(route -n get default 2>/dev/null | awk '/interface:/{print $2}')\"; "
              "echo @@ISC@@; cat /var/dhcpd/var/db/dhcpd.leases 2>/dev/null; "
              "echo @@KEA@@; cat /var/lib/kea/dhcp4.leases 2>/dev/null; echo @@END@@")
RX_ARP = re.compile(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5}) on (\S+)(.*)")
RX_MAC = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")


def norm_mac(m):
    return ":".join(x.zfill(2) for x in (m or "").lower().split(":"))


def parse_router_neighbors(out, t):
    """pfSense's ARP table (who is online in every zone) plus its DHCP leases (device names).
    Returns {ip: (mac, hostname, iface)} for devices, leaving out the router's own addresses and its WAN side."""
    arp_part, _, rest = out.partition("@@WAN@@")
    wan_line, _, rest = rest.partition("@@ISC@@")
    isc, _, kea = rest.partition("@@KEA@@")
    kea = kea.partition("@@END@@")[0]
    wan_if = wan_line.strip().split()[0] if wan_line.strip() else ""
    names = {}
    for m in re.finditer(r"lease (\d+\.\d+\.\d+\.\d+) \{(.*?)\n\}", isc, re.S):
        body = m.group(2)
        hw = re.search(r"hardware ethernet ([0-9a-fA-F:]+);", body)
        if hw:
            hn = re.search(r'client-hostname "([^"]*)";', body)
            names[norm_mac(hw.group(1))] = hn.group(1) if hn else names.get(norm_mac(hw.group(1)), "")
    lines = kea.strip().splitlines()
    if lines and lines[0].startswith("address,"):
        idx = {k: i for i, k in enumerate(lines[0].split(","))}
        for ln in lines[1:]:
            p = ln.split(",")
            try:
                mac = norm_mac(p[idx["hwaddr"]])
                host = p[idx["hostname"]].rstrip(".") if "hostname" in idx else ""
                if "expire" in idx and p[idx["expire"]].isdigit() and int(p[idx["expire"]]) < t / 1000:
                    continue
            except (IndexError, KeyError):
                continue
            if RX_MAC.match(mac):
                names[mac] = host.replace("&#x2c", ",")[:63] or names.get(mac, "")
    found = {}
    for line in arp_part.splitlines():
        m = RX_ARP.search(line)
        if not m or "permanent" in m.group(4) or "incomplete" in line:
            continue
        ip, mac, iface = m.group(1), norm_mac(m.group(2)), m.group(3)
        if (wan_if and iface == wan_if) or mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            continue
        found[ip] = (mac, names.get(mac, ""), iface)
    return found, bool(arp_part.strip()) and "@@WAN@@" in out


def pf_neighbors():
    """Read every device pfSense can see, in all zones. Returns (ok, {ip: (mac, host, iface)})."""
    rc, out, err = pf_ssh(PF_NBR_CMD, timeout=30)
    t = now_ms()
    ok = rc == 0 and "@@END@@" in (out or "")
    found = {}
    if ok:
        found, ok = parse_router_neighbors(out, t)
    with LOCK:
        S.pf["nbrOk"] = ok
        if ok:
            S.pf["nbrLast"], S.pf["nbrCount"], S.pf["nbrMsg"] = t, len(found), ""
        else:
            S.pf["nbrMsg"] = pf_explain(rc, out, err) if rc != 0 else "pfSense answered, but its device list couldn't be read."
    return ok, found


RX_DHCP_ISC = re.compile(r"DHCPACK on (\d+\.\d+\.\d+\.\d+) to ([0-9a-fA-F:]{11,17})(?: \(([^)]*)\))? via (\S+)")
RX_DHCP_KEA = re.compile(r"hwtype=\d+ ([0-9a-fA-F:]{11,17})\].*?lease (\d+\.\d+\.\d+\.\d+) has been allocated")


def pf_dhcp(msg, t):
    """A DHCP event from pfSense's log: a device just joined or renewed its address in some zone."""
    m = RX_DHCP_ISC.search(msg)
    if m:
        ip, mac, host, iface = m.group(1), norm_mac(m.group(2)), m.group(3) or "", m.group(4)
    else:
        m = RX_DHCP_KEA.search(msg)
        if not m:
            return False
        mac, ip, host, iface = norm_mac(m.group(1)), m.group(2), "", ""
    if not RX_MAC.match(mac):
        return True
    S.pf["dhcpLast"] = t
    load_oui()
    dev_seen(ip, mac, "", host, t, first=False, via="lan" if local_ip(ip) else "router", iface=iface)
    S.dirty = True
    return True


def pf_block(ip):
    iface = S.settings["pfsense"].get("iface") or "wan"
    rc, out, err = pf_ssh("easyrule block %s %s" % (iface, ip))
    if rc != 0 or "error" in (out or "").lower() or "invalid" in (out or "").lower():
        return False, pf_explain(rc, out, err)
    with LOCK:
        S.pf["edgeBlocked"].add(ip)
        S.dirty = True
    return True, "%s blocked at the router for your whole network." % ip


def pf_unblock(ip):
    iface = S.settings["pfsense"].get("iface") or "wan"
    rc, out, err = pf_ssh("easyrule unblock %s %s" % (iface, ip))
    if rc != 0:
        return False, pf_explain(rc, out, err)
    with LOCK:
        S.pf["edgeBlocked"].discard(ip)
        S.dirty = True
    return True, "%s unblocked at the router." % ip


def block_ip(ip):
    """Internet addresses go to pfSense when it's connected (protects every device); otherwise this server's ufw."""
    if not is_private(ip) and pf_ready():
        ok, msg = pf_block(ip)
        if ok:
            return True, msg
        ok2, msg2 = ufw_block(ip)
        return ok2, ("pfSense didn't take the block (%s) so %s was blocked on this server only." % (msg.rstrip("."), ip)) if ok2 else msg2
    return ufw_block(ip)


def unblock_ip(ip):
    done, errs = [], []
    if ip in S.pf["edgeBlocked"]:
        ok, msg = pf_unblock(ip)
        (done if ok else errs).append(msg)
    if ip in S.blocked or not done:
        ok, msg = ufw_unblock(ip)
        if ok or ip in S.blocked:
            (done if ok else errs).append(msg)
    if done:
        return True, " ".join(done)
    return False, " ".join(errs) or "%s wasn't blocked." % ip


def not_a_host(ip):
    """0.0.0.0 (devices asking DHCP for an address), broadcast, multicast and reserved addresses aren't attackers."""
    try:
        a = ipaddress.ip_address(ip)
        return a.is_unspecified or a.is_multicast or a.is_reserved or a.is_link_local or str(a) == "255.255.255.255"
    except ValueError:
        return True


STRAY_UDP_SPORTS ={"53", "123", "443", "853", "3478", "5349", "19302"}


def is_stray(proto, rest):
    """A blocked packet that is a late reply to one of our own connections, not an attack:
    TCP without SYN (ACK/FIN/RST after the router dropped the connection) or UDP coming
    back from a DNS/NTP/QUIC/STUN server port. These show up after state resets and are harmless."""
    p = proto.lower()
    try:
        if p == "tcp":
            flags = rest[3] if len(rest) > 3 else ""
            return bool(flags) and "S" not in flags
        if p == "udp":
            return len(rest) > 0 and rest[0] in STRAY_UDP_SPORTS
    except Exception:
        return False
    return False


def pf_filterlog(msg, t):
    """Parse one pfSense filterlog line (CSV) and record router-level blocks."""
    m = re.search(r"filterlog(?:\[\d+\])?:?\s*(?:\d+\s+-\s+-\s+|-\s+-\s+)?(\d+,.*)$", msg.strip())
    if not m:
        return False
    f = m.group(1).split(",")
    try:
        iface, action, ver = f[4], f[6], f[8]
        if ver == "4":
            proto, src, dst, rest = f[16], f[18], f[19], f[20:]
        elif ver == "6":
            proto, src, dst, rest = f[12], f[15], f[16], f[17:]
        else:
            return True
    except IndexError:
        return True
    S.pf["lastLog"] = t
    S.counts.append((t, "pflog"))
    if action != "block":
        return True
    src = norm_ip(src) or src
    if is_private(src) or src in S.my_ips or not_a_host(src):
        return True
    if is_stray(proto, rest):
        S.counts.append((t, "stray"))
        return True
    dport = rest[1] if proto.lower() in ("tcp", "udp") and len(rest) > 1 and rest[1].isdigit() else ""
    S.counts.append((t, "drop"))
    s = source(src, t)
    s["blocks"] += 1
    s["edge"] = s.get("edge", 0) + 1
    if dport:
        s["ports"].add(int(dport))
    if not s["why"]:
        s["why"] = "Stopped at the router"
    # one log line per attacker per 5 minutes, with a running count, so the router doesn't drown the log
    r = S.pf["recent"].get(src)
    if r and t - r["first"] < 300000:
        r["n"] += 1
        r["ports"].add(dport or proto)
        r["ev"]["t"] = t
        r["ev"]["text"] = "Router blocked %s ×%d (%s) on %s" % (src, r["n"], ", ".join(sorted(r["ports"], key=str)[:6]), iface)
    else:
        S.evseq += 1
        ev = {"id": S.evseq, "t": t, "act": "DROP", "text": "Router blocked %s → %s%s %s (%s)" % (src, dst, ":" + dport if dport else "", proto.upper(), iface), "hot": False}
        S.events.append(ev)
        S.pf["recent"][src] = {"first": t, "n": 1, "ports": {dport or proto}, "ev": ev}
        if len(S.pf["recent"]) > 500:
            for k in sorted(S.pf["recent"], key=lambda k: S.pf["recent"][k]["first"])[:250]:
                S.pf["recent"].pop(k, None)
    if dport:
        dq = S.fw_ports[src]
        dq.append((t, int(dport)))
        prune(dq, t - 120000)
        ports = {p for (_, p) in dq}
        if len(ports) >= 25:
            s["why"] = "Port scanning (stopped at the router)"
            upsert_alert("pfscan:%s:%d" % (src, hour(t)), "low", "Port scan stopped at the router", "T1046", "Discovery",
                         "%s probed %d ports on your network in 2 minutes. pfSense blocked all of them" % (src, len(ports)),
                         t, src=src, count=len(ports))
    S.dirty = True
    return True


def syslog_loop():
    port = int(S.settings["pfsense"].get("port") or 5140)
    try:
        sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sk.bind(("0.0.0.0", port))
    except Exception as ex:
        print("sentinel: can't listen for pfSense logs on UDP %d: %s" % (port, ex), file=sys.stderr)
        return
    while True:
        try:
            data, addr = sk.recvfrom(16384)
            host = pf_host()
            if host and addr[0] != host and addr[0] not in S.my_ips:
                continue
            text = data.decode("utf-8", "replace")
            with LOCK:
                for line in text.splitlines():
                    if not pf_filterlog(line, now_ms()) and ("DHCPACK" in line or "DHCP4_LEASE_ALLOC" in line):
                        pf_dhcp(line, now_ms())
        except Exception as ex:
            print("sentinel: pfSense log error:", ex, file=sys.stderr)


def pf_loop():
    time.sleep(20)
    while True:
        try:
            if S.settings["pfsense"].get("enabled") and os.path.exists(PF_KEY):
                pf_check()
        except Exception as ex:
            print("sentinel: pfSense check error:", ex, file=sys.stderr)
        time.sleep(600)


def valid_ip(ip):
    ip = norm_ip(str(ip or "").strip())
    return ip


# --------------------------------------------------------------------------- Discord notifications
NOTIFY_Q = collections.deque(maxlen=100)
NOTIFY_EVT = threading.Event()
SEV_COLOR = {"critical": 0xFF5C63, "high": 0xFF8C42, "medium": 0xE9C84A, "low": 0x8AA7C7}
SEV_ICON = {"critical": "\U0001F6A8", "high": "⚠️"}
RX_WEBHOOK = re.compile(r"^https://(?:(?:ptb|canary)\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+$")
UA = "DiscordBot (https://github.com/sentinel-agent, %s)" % VERSION
_sent = collections.deque()
_held = [0]


def enqueue(embed, force=False):
    NOTIFY_Q.append((embed, force))
    NOTIFY_EVT.set()


def iso(t_ms):
    return datetime.fromtimestamp(t_ms / 1000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def maybe_notify(a, t, always=False):
    """Post an alert to Discord if it's serious enough. always=True posts regardless of severity
    (new devices and watched devices going offline, which you asked Sentinel to tell you about)."""
    n = S.settings.get("notify") or {}
    if not n.get("enabled") or not n.get("webhook"):
        return
    if t < START_MS - 5000:  # history replayed from the journal at startup
        return
    limit = "critical" if n.get("minSev") == "critical" else "high"
    qualifies = SEV_RANK[a["sev"]] <= SEV_RANK[limit]
    if always and qualifies:
        return  # upsert_alert already posted it through the normal path
    if not always and not qualifies:
        return
    fields = []
    if a.get("src") and a["src"] != "—":
        fields.append({"name": "Source", "value": a["src"], "inline": True})
    if a.get("user") and a["user"] != "—":
        fields.append({"name": "User", "value": a["user"], "inline": True})
    fields.append({"name": "MITRE ATT&CK", "value": "%s · %s" % (a["tech"], a["tac"]), "inline": True})
    embed = {"title": ("%s %s: %s" % (SEV_ICON.get(a["sev"], "\U0001F4E1"), a["sev"].upper(), a["t"])).strip(),
             "description": a["det"] + ".", "color": SEV_COLOR[a["sev"]], "fields": fields,
             "footer": {"text": "%s · %s" % (HOST, a["id"])}, "timestamp": iso(a["last"])}
    if a.get("src") and a["src"] != "—" and not is_private(a["src"]):
        embed["_ip"] = a["src"]
    enqueue(embed)


def discord_request(url, payload=None):
    if os.environ.get("SENTINEL_DISCORD_BASE"):  # testing hook: send to a local stand-in for discord.com
        url = re.sub(r"^https://[^/]+", os.environ["SENTINEL_DISCORD_BASE"], url)
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET",
                                 headers={"Content-Type": "application/json", "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=15) as r:
        body = r.read()
        return json.loads(body) if body else {}


def discord_send(n, embed):
    embed = dict(embed)
    if n.get("click") and "url" not in embed:
        embed["url"] = n["click"]
    discord_request(n["webhook"], {"username": "Sentinel", "embeds": [embed],
                                   "allowed_mentions": {"parse": []}})


def describe_error(ex):
    if isinstance(ex, urllib.error.HTTPError):
        if ex.code in (401, 404):
            return "Discord says this webhook doesn't exist anymore. Paste a new webhook link."
        if ex.code == 429:
            return "Discord is rate-limiting messages. Try again in a minute."
        return "Discord answered with error %d." % ex.code
    return "Couldn't reach Discord (%s). Check the server's internet connection." % getattr(ex, "reason", ex)


def notifier_loop():
    while True:
        NOTIFY_EVT.wait(30)
        NOTIFY_EVT.clear()
        while NOTIFY_Q:
            embed, force = NOTIFY_Q.popleft()
            embed = dict(embed)
            ip = embed.pop("_ip", None)
            if ip:
                with LOCK:
                    g = S.geo.get(ip)
                if not g:
                    try:
                        g = geo_parse((geo_lookup([ip]) or [{}])[0])
                        if g:
                            with LOCK:
                                S.geo[ip] = g
                    except Exception:
                        g = None
                if g:
                    embed["fields"] = embed.get("fields", []) + [{"name": "Location", "value": geo_text(g), "inline": False}]
            now = time.time()
            while _sent and _sent[0] < now - 300:
                _sent.popleft()
            if not force and len(_sent) >= 6:  # at most 6 alert messages per 5 minutes
                _held[0] += 1
                continue
            if not force and _held[0]:
                embed["description"] += "\n\n*+%d more alerts were held back so the channel isn't flooded. Open Sentinel to see them.*" % _held[0]
                _held[0] = 0
            with LOCK:
                n = dict(S.settings.get("notify") or {})
            if not n.get("webhook"):
                continue
            try:
                discord_send(n, embed)
                if not force:
                    _sent.append(now)
                status = "Last message sent at %s" % time.strftime("%H:%M")
            except Exception as ex:
                status = "Last message failed: " + describe_error(ex)
            with LOCK:
                S.notify_status = status
            time.sleep(1)  # stay well inside Discord's webhook rate limit


def user_tz(n):
    tzname = n.get("tz") or ""
    if tzname:
        try:
            from zoneinfo import ZoneInfo
            return ZoneInfo(tzname)
        except Exception:
            pass
    return None


def summary_embed(t):
    day = t - 86400000
    new = [a for a in S.alerts.values() if a["time"] > day]
    by = collections.Counter(a["sev"] for a in new)
    c = collections.Counter(k for (tt, k) in S.counts if tt > day)
    open_ = [a for a in S.alerts.values() if a["status"] != "closed"]
    urgent = [a for a in open_ if a["sev"] in ("critical", "high")]
    bad = [ck["name"] for ck in S.checks if not ck.get("ok")]
    down = [sv["name"] for sv in S.services if sv["state"] in ("inactive", "failed")]
    top = sorted((s for s in S.sources.values() if s["last"] > day and not s["lan"]),
                 key=lambda s: s["fails"] + s["blocks"], reverse=True)[:3]
    fields = [
        {"name": "New alerts", "value": ", ".join("%d %s" % (by[s], s) for s in ("critical", "high", "medium", "low") if by[s]) or "None", "inline": True},
        {"name": "Open alerts", "value": "%d%s" % (len(open_), " (%d critical/high)" % len(urgent) if urgent else ""), "inline": True},
        {"name": "Failed logins", "value": str(c["fail"]), "inline": True},
        {"name": "Firewall blocks", "value": str(c["drop"]), "inline": True},
        {"name": "Your logins", "value": str(c["login"]), "inline": True},
    ]
    m = S.metrics
    if m.get("diskTotal"):
        fields.append({"name": "Disk", "value": "%d%% full" % round(m["diskUsed"] / m["diskTotal"] * 100), "inline": True})
    if top:
        fields.append({"name": "Most active attackers", "value": "\n".join(
            "`%s` %d hits%s" % (s["ip"], s["fails"] + s["blocks"], " (blocked)" if s["ip"] in S.blocked else "") for s in top), "inline": False})
    fields.append({"name": "Security checks", "value": "All passing" if not bad else "\n".join("❗ " + b for b in bad), "inline": False})
    fields.append({"name": "Services", "value": "All running" if not down else "Not running: " + ", ".join(down), "inline": False})
    issues = len(urgent) + len(bad) + len(down)
    calm = issues == 0
    return {"title": "\U0001F6E1️ Daily summary: %s" % ("all quiet" if calm else "%d thing%s need%s a look" % (issues, "" if issues == 1 else "s", "s" if issues == 1 else "")),
            "description": "The last 24 hours on **%s**." % HOST, "color": 0x3FD18E if calm else 0xE9C84A,
            "fields": fields, "footer": {"text": "%s · up %d days" % (HOST, m.get("uptime", 0) // 86400)},
            "timestamp": iso(t)}


def summary_loop():
    while True:
        time.sleep(30)
        try:
            with LOCK:
                n = S.settings.get("notify") or {}
                if not n.get("summary") or not n.get("webhook"):
                    continue
                tz = user_tz(n)
                now = datetime.now(tz) if tz else datetime.now()
                today = now.strftime("%Y-%m-%d")
                if now.hour != int(n.get("summaryHour", 8)) or n.get("lastSummary") == today:
                    continue
                n["lastSummary"] = today
                S.dirty = True
                embed = summary_embed(now_ms())
            enqueue(embed, force=True)
        except Exception as ex:
            print("sentinel: summary error:", ex, file=sys.stderr)


def update_notify(body):
    """Apply notification settings. The webhook itself is checked with Discord before this runs."""
    n = S.settings["notify"]
    if "enabled" in body:
        n["enabled"] = bool(body["enabled"])
    if body.get("minSev") in ("critical", "high"):
        n["minSev"] = body["minSev"]
    if "summary" in body:
        n["summary"] = bool(body["summary"])
    if "summaryHour" in body:
        h = int(body["summaryHour"])
        if 0 <= h <= 23:
            if h != n.get("summaryHour"):
                n["lastSummary"] = ""
            n["summaryHour"] = h
    tzname = str(body.get("tz") or "")[:64]
    if tzname:
        try:
            from zoneinfo import ZoneInfo
            ZoneInfo(tzname)
            n["tz"] = tzname
        except Exception:
            pass
    click = str(body.get("click") or "")
    if click.startswith(("http://", "https://")) and len(click) < 300:
        n["click"] = click
    S.dirty = True


# --------------------------------------------------------------------------- attacker locations
def geo_lookup(ips):
    """Look up country/city/network owner for public attacker addresses (ip-api.com, free, no key)."""
    req = urllib.request.Request("http://ip-api.com/batch?fields=status,query,country,countryCode,city,isp,org,as",
                                 data=json.dumps(ips[:100]).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "Sentinel/" + VERSION})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def geo_parse(r):
    if not r or r.get("status") != "success":
        return None
    return {"cc": r.get("countryCode", ""), "country": r.get("country", ""), "city": r.get("city", ""),
            "org": r.get("org") or r.get("isp") or "", "as": (r.get("as") or "").split(" ")[0]}


def flag(cc):
    return "".join(chr(0x1F1E6 + ord(c) - 65) for c in cc.upper()) if len(cc) == 2 and cc.isalpha() else ""


def geo_text(g):
    place = ", ".join(x for x in (g.get("city"), g.get("country")) if x)
    return ("%s %s%s" % (flag(g.get("cc", "")), place, " · " + g["org"] if g.get("org") else "")).strip()


def geo_loop():
    while True:
        time.sleep(20)
        with LOCK:
            want = [sv["ip"] for sv in S.sources.values() if not sv["lan"] and sv["ip"] not in S.geo][:100]
        if not want:
            continue
        try:
            res = geo_lookup(want)
        except Exception:
            time.sleep(120)
            continue
        with LOCK:
            for r in res:
                g = geo_parse(r)
                S.geo[r.get("query")] = g or {"cc": "", "country": "", "city": "", "org": "", "as": ""}
            S.dirty = True
        time.sleep(5)  # ip-api allows 15 batch requests a minute


# --------------------------------------------------------------------------- home network devices
# port -> (level, what it is, what to do, ATT&CK technique)
RISK_PORTS = {
    23: ("high", "Telnet is open", "Telnet sends passwords in plain text and is the favourite way in for botnets like Mirai. Turn it off in the device's settings or update its firmware. If you can't, consider replacing the device.", "T1021"),
    2323: ("high", "Telnet (alternate port) is open", "Often a hidden service on cheap cameras and smart plugs. Update the firmware, and if it stays open, keep the device off your main network.", "T1021"),
    7547: ("high", "Remote management (TR-069) is open", "This is a router/modem management port that attackers scan for. Check for a firmware update or ask your internet provider.", "T1133"),
    21: ("medium", "FTP file transfer is open", "FTP sends passwords in plain text. Turn it off if you don't use it, or switch to SFTP.", "T1021"),
    5900: ("medium", "Screen sharing (VNC) is open", "Make sure it has a strong password, or turn it off when you're not using it.", "T1021.005"),
    3389: ("medium", "Remote Desktop is open", "Fine for your own PC on your home network. Use a strong password and keep Windows updated.", "T1021.001"),
    1883: ("medium", "Smart-home messaging (MQTT) is open without encryption", "Make sure your MQTT broker requires a username and password.", "T1071"),
    5555: ("medium", "Android debugging (ADB) is open", "Anyone on your network can control this device. Turn off 'ADB debugging' or 'Network debugging' in its developer settings.", "T1021"),
    554: ("low", "Camera video stream (RTSP) is open", "Normal for cameras. Make sure the camera doesn't use its default password.", "T1125"),
    445: ("low", "File sharing (SMB) is open", "Normal for PCs and NAS drives. Make sure guest access is off and it isn't forwarded from your router.", "T1021.002"),
    139: ("low", "Old-style file sharing (NetBIOS) is open", "Normal for Windows PCs. Turn off SMBv1 if the device offers it.", "T1021.002"),
    80: ("info", "Web admin page (not encrypted)", "If this is a router, camera or printer, change the default admin password.", ""),
    443: ("info", "Web page (encrypted)", "", ""),
    8080: ("info", "Web admin page", "If this is a device's admin page, change the default password.", ""),
    8443: ("info", "Web admin page (encrypted)", "", ""),
    22: ("info", "SSH remote login", "Make sure it uses keys or a strong password.", ""),
    53: ("info", "DNS", "", ""),
    631: ("info", "Printing (IPP)", "", ""),
    9100: ("info", "Printing (raw)", "", ""),
    8123: ("info", "Home Assistant", "", ""),
    32400: ("info", "Plex media server", "", ""),
    5000: ("info", "Web app / NAS admin", "", ""),
    1900: ("info", "UPnP", "", ""),
    62078: ("info", "Apple device sync", "", ""),
    8008: ("info", "Chromecast / Google Cast", "", ""),
}
SCAN_PORTS = sorted(RISK_PORTS)
LEVEL_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}
OUI = {}
_oui = {"loaded": False}
DEV_EVT = threading.Event()
SCAN_EVT = threading.Event()


def load_oui():
    if _oui["loaded"]:
        return
    _oui["loaded"] = True
    for path in ("/usr/share/arp-scan/ieee-oui.txt", "/usr/share/ieee-data/oui.txt", "/usr/share/nmap/nmap-mac-prefixes"):
        try:
            f = open(path, errors="replace")
        except OSError:
            continue
        with f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "(hex)" in line:
                    k, _, v = line.partition("(hex)")
                    k = k.strip().replace("-", "")
                else:
                    parts = re.split(r"\s+", line, 1)
                    if len(parts) < 2:
                        continue
                    k, v = parts[0].replace(":", "").replace("-", ""), parts[1]
                if len(k) == 6:
                    OUI.setdefault(k.upper(), v.strip())
        if OUI:
            return


def vendor_of(mac):
    h = mac.replace(":", "").upper()
    if len(h) >= 2 and int(h[1], 16) & 2:
        return "Private address (phone, tablet or laptop)"
    return OUI.get(h[:6], "")


def iface_cidr(iface):
    rc, out, _ = run(["ip", "-o", "-4", "addr", "show", "dev", iface])
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", out or "")
    if m:
        return m.group(1)
    try:  # no iproute2: ask the kernel directly
        import fcntl
        import struct
        sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        req = struct.pack("256s", iface[:15].encode())
        addr = socket.inet_ntoa(fcntl.ioctl(sk.fileno(), 0x8915, req)[20:24])   # SIOCGIFADDR
        mask = socket.inet_ntoa(fcntl.ioctl(sk.fileno(), 0x891b, req)[20:24])   # SIOCGIFNETMASK
        sk.close()
        return "%s/%s" % (addr, mask)
    except Exception:
        return None


def lan_network(iface):
    cidr = iface_cidr(iface)
    if not cidr:
        return None, None
    itf = ipaddress.ip_interface(cidr)
    net = itf.network if itf.network.prefixlen >= 22 else ipaddress.ip_network("%s/24" % itf.ip, strict=False)
    return itf, net


def gateway_ip():
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                p = line.split()
                if p[1] == "00000000" and p[7] == "00000000":
                    return socket.inet_ntoa(bytes.fromhex(p[2])[::-1])
    except Exception:
        pass
    return None


def read_arp(iface):
    found = {}
    try:
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                p = line.split()
                if len(p) >= 6 and p[2] == "0x2" and p[5] == iface and p[3] != "00:00:00:00:00:00":
                    found[p[0]] = (p[3].lower(), "")
    except Exception:
        pass
    return found


def sweep(iface, net):
    """Find devices on the home network. arp-scan is best (finds devices that ignore ping);
    otherwise ping every address and read the kernel's ARP table."""
    found, scanner = {}, "ping"
    if shutil.which("arp-scan"):
        rc, out, _ = run(["arp-scan", "-I", iface, "-x", "-g", "-r", "2", str(net)], timeout=90)
        if rc == 0:
            scanner = "arp-scan"
            for line in out.splitlines():
                p = line.split("\t")
                if len(p) >= 2 and re.match(r"^\d+\.\d+\.\d+\.\d+$", p[0]):
                    found[p[0]] = (p[1].lower(), p[2].strip() if len(p) > 2 else "")
    if scanner == "ping":
        hosts = [str(h) for h in list(net.hosts())[:1024]]
        with ThreadPoolExecutor(64) as ex:
            list(ex.map(lambda ip: run(["ping", "-c1", "-W1", "-n", ip], timeout=4), hosts))
    for ip, v in read_arp(iface).items():
        found.setdefault(ip, v)
    return found, scanner


def reverse_names(ips):
    def one(ip):
        try:
            return ip, socket.gethostbyaddr(ip)[0]
        except Exception:
            return ip, ""
    out = {}
    with ThreadPoolExecutor(16) as ex:
        futs = [ex.submit(one, ip) for ip in ips]
        for f in futs:
            try:
                ip, name = f.result(timeout=4)
                if name and name != ip:
                    out[ip] = name
            except Exception:
                pass
    return out


def dev_label(d):
    if d.get("name"):
        return d["name"]
    if d.get("self"):
        return HOST + " (this server)"
    if d.get("gateway"):
        return "Router"
    h = d.get("host") or ""
    if h:
        return re.sub(r"\.(lan|home|local|localdomain|home\.arpa)$", "", h)
    v = d.get("vendor") or ""
    return (v + " device") if v and not v.startswith("Private") else ("Unknown device" if not v else "Phone or laptop")


def local_ip(ip):
    """True when ip is on the same network as this server, so Sentinel can reach it directly."""
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(S.lan.get("subnet"))
    except Exception:
        return True


def dev_seen(ip, mac, vend, host, t, first, gw=None, itf=None, via="lan", iface=""):
    """Record that a device is on the network (caller holds LOCK). Raises the new-device alert when needed."""
    d = S.devices.get(mac)
    is_new = d is None
    if is_new:
        d = {"mac": mac, "ip": ip, "name": "", "host": "", "vendor": "", "first": t, "last": t,
             "known": False, "watch": False, "ports": [], "findings": [], "lastScan": 0,
             "online": True, "missed": 0}
        S.devices[mac] = d
    if d["ip"] != ip and not is_new:
        was = d.get("zone") or zone_of(d["ip"])
        now_z = zone_of(ip)
        where = (" (%s → %s)" % (was, now_z)) if was and now_z and was != now_z else ""
        add_event(t, "INFO", "%s moved from %s to %s%s" % (dev_label(d), d["ip"], ip, where), "system")
        if where:  # different zone: the old port check no longer applies
            d["ports"], d["findings"], d["lastScan"] = [], [], 0
            d.get("alerted", {}).clear()
    d["ip"] = ip
    d["zone"] = zone_of(ip)
    d["via"] = via
    if iface:
        d["iface"] = iface
    d["vendor"] = vend or d.get("vendor") or vendor_of(mac)
    if host:
        d["host"] = host
    if ip in S.my_ips or (itf and ip == str(itf.ip)):
        d["self"] = True
        d["known"] = True
    gw_changed = False
    if via == "lan" and gw and ip == gw:
        d["gateway"] = True
        for other in S.devices.values():
            if other is not d:
                other.pop("gateway", None)
        if S.gateway_mac and S.gateway_mac != mac:
            gw_changed = True
            upsert_alert("gwmac:%s:%d" % (mac, hour(t)), "critical", "Your router's hardware address changed",
                         "T1557.002", "Credential Access",
                         "The router at %s now answers from %s instead of %s. If you didn't replace the router, another device may be intercepting your traffic (ARP spoofing)"
                         % (gw, mac, S.gateway_mac), t, src=ip)
        S.gateway_mac = mac
    if not d.get("online") and not is_new and d.get("watch"):
        add_event(t, "ALLOW", "%s is back online (%s)" % (dev_label(d), ip), "system")
    d["last"], d["online"], d["missed"] = t, True, 0
    if is_new:
        if first:
            d["baseline"] = True  # was already here when Sentinel started watching
        elif not gw_changed:  # a new router address already raised a critical alert
            zone = (" in %s" % d["zone"]) if d.get("zone") else ""
            add_event(t, "ALERT", "New device on your network%s: %s (%s, %s)" % (zone, dev_label(d), ip, mac), "system", hot=True)
            a = upsert_alert("newdev:%s" % mac, "medium", "New device joined your network", "T1200", "Initial Access",
                             "%s appeared at %s%s (hardware address %s, maker: %s)" % (dev_label(d), ip, zone, mac, d["vendor"] or "unknown"),
                             t, src=ip)
            if S.settings["devices"].get("notifyNew", True):
                maybe_notify(a, t, always=True)
    return d


ROUTER_ONLY_STALE = 3 * 3600000   # devices known only from DHCP events count as offline after 3 h of silence


def devices_loop():
    time.sleep(15)
    first = not S.devices
    while True:
        try:
            iface = default_iface()
            itf, net = lan_network(iface) if iface else (None, None)
            if net:
                load_oui()
                found, scanner = sweep(iface, net)
                try:
                    with open("/sys/class/net/%s/address" % iface) as f:
                        found[str(itf.ip)] = (f.read().strip().lower(), "")
                except Exception:
                    pass
                router, pf_round = {}, False
                if pf_ready():
                    try:
                        pf_round, router = pf_neighbors()
                    except Exception as ex:
                        print("sentinel: pfSense device list error:", ex, file=sys.stderr)
                names = reverse_names(list(found))
                gw = gateway_ip()
                t = now_ms()
                with LOCK:
                    S.lan = {"iface": iface, "subnet": str(net), "scanner": scanner, "lastSweep": t, "gateway": gw}
                    seen = set()
                    for ip, (mac, vend) in found.items():
                        seen.add(mac)
                        dev_seen(ip, mac, vend, names.get(ip, ""), t, first, gw=gw, itf=itf)
                    pf_first = pf_round and not S.pf.get("nbrSeen")
                    for ip, (mac, host, rif) in router.items():
                        if mac in seen:
                            d = S.devices.get(mac)
                            if d is not None:
                                if host and not d.get("host"):
                                    d["host"] = host
                                d["iface"] = rif
                            continue
                        seen.add(mac)
                        if ip == gw or ip in S.my_ips:
                            continue
                        dev_seen(ip, mac, "", host, t, first or pf_first, via="lan" if local_ip(ip) else "router", iface=rif)
                    if pf_round:
                        S.pf["nbrSeen"] = True
                    for mac, d in S.devices.items():
                        if mac in seen:
                            continue
                        if d.get("via") == "router" and not pf_round:
                            # pfSense's list isn't available: fall back to how recently a DHCP event mentioned it
                            if not (d.get("online") and t - d.get("last", 0) > ROUTER_ONLY_STALE):
                                continue
                            d["missed"] = 2
                        else:
                            d["missed"] = d.get("missed", 0) + 1
                        if d.get("online") and d["missed"] >= 2:
                            d["online"] = False
                            if d.get("watch"):
                                add_event(t, "ALERT", "%s went offline (last seen at %s)" % (dev_label(d), d["ip"]), "system", hot=True)
                                a = upsert_alert("off:%s:%d" % (mac, hour(t)), "medium", "Watched device went offline: " + dev_label(d),
                                                 "—", "Impact", "%s (%s) hasn't answered for about 10 minutes" % (dev_label(d), d["ip"]), t)
                                maybe_notify(a, t, always=True)
                    S.dirty = True
                first = False
                SCAN_EVT.set()
        except Exception as ex:
            print("sentinel: device sweep error:", ex, file=sys.stderr)
        DEV_EVT.wait(300)
        DEV_EVT.clear()


def scan_host(ip):
    def probe(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.8)
        try:
            return port if s.connect_ex((ip, port)) == 0 else None
        except Exception:
            return None
        finally:
            s.close()
    with ThreadPoolExecutor(12) as ex:
        return sorted(p for p in ex.map(probe, SCAN_PORTS) if p)


def portscan_loop():
    """Check each device for risky open services: new devices right away, the rest every 6 hours."""
    time.sleep(30)
    while True:
        try:
            t = now_ms()
            with LOCK:
                todo = [(d["mac"], d["ip"]) for d in S.devices.values()
                        if d.get("online") and not d.get("self") and local_ip(d["ip"]) and (d.get("scanNow") or t - d.get("lastScan", 0) > 6 * 3600000)]
            for mac, ip in todo[:25]:
                ports = scan_host(ip)
                t = now_ms()
                with LOCK:
                    d = S.devices.get(mac)
                    if not d:
                        continue
                    before = set(d.get("ports", []))
                    d["ports"], d["lastScan"] = ports, t
                    d.pop("scanNow", None)
                    d["findings"] = sorted(({"port": pt, "level": RISK_PORTS[pt][0], "title": RISK_PORTS[pt][1],
                                            "advice": RISK_PORTS[pt][2]} for pt in ports),
                                           key=lambda f: (LEVEL_RANK[f["level"]], f["port"]))
                    for pt in ports:
                        lvl, title, advice, tech = RISK_PORTS[pt]
                        if lvl in ("high", "medium") and (pt not in before or not d.get("alerted", {}).get(str(pt))):
                            d.setdefault("alerted", {})[str(pt)] = t
                            upsert_alert("devport:%s:%d" % (mac, pt), lvl, "%s on %s" % (title, dev_label(d)), tech,
                                         "Initial Access", "%s (%s) has port %d open. %s" % (dev_label(d), ip, pt, advice), t, src=ip)
                    for pt in before - set(ports):
                        d.get("alerted", {}).pop(str(pt), None)
                    S.dirty = True
                time.sleep(1)
        except Exception as ex:
            print("sentinel: port check error:", ex, file=sys.stderr)
        SCAN_EVT.wait(600)
        SCAN_EVT.clear()


def tailscale_loop():
    first = not S.tailnet
    while True:
        try:
            if shutil.which("tailscale"):
                rc, out, _ = run(["tailscale", "status", "--json"], timeout=15)
                if rc == 0:
                    data = json.loads(out)
                    me = data.get("Self") or {}
                    peers = [me] + list((data.get("Peer") or {}).values())
                    t = now_ms()
                    with LOCK:
                        for p in peers:
                            if not p:
                                continue
                            pid = p.get("PublicKey") or p.get("ID") or p.get("HostName")
                            info = {"id": pid, "name": p.get("HostName") or "?", "dns": (p.get("DNSName") or "").rstrip("."),
                                    "os": p.get("OS", ""), "ips": p.get("TailscaleIPs") or [],
                                    "online": bool(p.get("Online")) or p is me, "self": p is me,
                                    "lastSeen": p.get("LastSeen", "")}
                            e = S.tailnet.get(pid)
                            if e:
                                if e.get("online") != info["online"]:
                                    add_event(t, "INFO", "Tailscale: %s is %s" % (info["name"], "online" if info["online"] else "offline"), "system")
                                e.update(info)
                            else:
                                info["first"] = t
                                S.tailnet[pid] = info
                                if not first:
                                    a = upsert_alert("ts:%s" % pid, "high", "New device joined your Tailscale network", "T1078",
                                                     "Initial Access", "%s (%s) was added to your tailnet. If you didn't add it, remove it in the Tailscale admin console right away"
                                                     % (info["name"], info["os"] or "unknown system"), t)
                        S.dirty = True
                    first = False
        except Exception as ex:
            print("sentinel: tailscale error:", ex, file=sys.stderr)
        time.sleep(60)


# --------------------------------------------------------------------------- snapshot
def zone_summary():
    z = collections.OrderedDict()
    order = {name: i for i, (_, name) in enumerate(ZONES)}
    for d in S.devices.values():
        name = d.get("zone") or zone_of(d.get("ip", "")) or "Other"
        e = z.setdefault(name, {"name": name, "devices": 0, "online": 0})
        e["devices"] += 1
        e["online"] += 1 if d.get("online") else 0
    return sorted(z.values(), key=lambda e: (order.get(e["name"], 99), e["name"]))


def snapshot():
    t = now_ms()
    counts = collections.Counter(k for (tt, k) in S.counts if tt > t - 3600000)
    alerts = sorted(S.alerts.values(), key=lambda a: a["last"], reverse=True)[:200]
    # Home-network devices only count as hostile if they actually failed logins
    def noise(s):
        # one or two packets stopped at the router and nothing else: background noise, not a hostile source
        return (s["fails"] == 0 and s.get("edge", 0) >= s["blocks"] and s["blocks"] < 3
                and s["ip"] not in S.blocked and s["ip"] not in S.pf["edgeBlocked"])
    srcs = sorted((s for s in S.sources.values() if not (s["lan"] and s["fails"] == 0) and not noise(s)),
                  key=lambda s: s["last"], reverse=True)[:40]
    sources = [{"ip": s["ip"], "first": s["first"], "last": s["last"], "fails": s["fails"], "blocks": s["blocks"],
                "users": sorted(s["users"])[:8], "nusers": len(s["users"]), "ports": sorted(s["ports"])[:12],
                "lan": s["lan"], "why": s["why"] or "Suspicious activity",
                "blocked": s["ip"] in S.blocked or s["ip"] in S.pf["edgeBlocked"],
                "blockedAt": "router" if s["ip"] in S.pf["edgeBlocked"] else ("server" if s["ip"] in S.blocked else ""),
                "edgeOnly": s["fails"] == 0 and s.get("edge", 0) >= s["blocks"] and s["blocks"] > 0}
               for s in srcs]
    os_name = platform.platform()
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    os_name = line.split("=", 1)[1].strip().strip('"')
    except Exception:
        pass
    net = {k: v for k, v in S.net.items() if not k.startswith("_")}
    net["newPerMin"] = len(S.new_conns)
    return {
        "mode": "live", "version": VERSION, "now": t,
        "host": {"name": HOST, "os": os_name, "kernel": platform.release(),
                 "ips": sorted(i for i in S.my_ips if not is_loopback(i))},
        "metrics": S.metrics,
        "traffic": {"iface": S.iface, "interval": 2, "rx": list(S.rx), "tx": list(S.tx)},
        "kpi": {"events1h": sum(counts.values()), "fails1h": counts.get("fail", 0),
                "drops1h": counts.get("drop", 0), "logins1h": counts.get("login", 0)},
        "alerts": alerts,
        "events": list(S.events)[-150:][::-1],
        "sources": sources,
        "services": S.services, "checks": S.checks, "net": net,
        "settings": {"autoblock": S.settings["autoblock"],
                     "devices": S.settings["devices"],
                     "notify": dict({k: v for k, v in S.settings["notify"].items() if k not in ("lastSummary", "webhook")},
                                    webhookSet=bool(S.settings["notify"].get("webhook")))},
        "notifyStatus": S.notify_status,
        "firewall": {"ufw": S.ufw_state, "blocked": sorted(S.blocked | S.pf["edgeBlocked"]),
                     "routerBlocked": sorted(S.pf["edgeBlocked"])},
        "pfsense": dict(S.settings["pfsense"], hostEffective=pf_host(), sshOk=S.pf.get("sshOk"), sshMsg=S.pf.get("sshMsg", ""),
                        lastLog=S.pf.get("lastLog", 0), logs1h=counts.get("pflog", 0), keyReady=os.path.exists(PF_KEY + ".pub"),
                        pubkey=pf_pubkey(create=False), nbrOk=S.pf.get("nbrOk"), nbrMsg=S.pf.get("nbrMsg", ""),
                        nbrLast=S.pf.get("nbrLast", 0), nbrCount=S.pf.get("nbrCount", 0), dhcpLast=S.pf.get("dhcpLast", 0)),
        "learning": S.learning,
        "lan": S.lan,
        "devices": sorted((dict({k: v for k, v in d.items() if k not in ("missed", "alerted")},
                                zone=d.get("zone") or zone_of(d.get("ip", "")), reach=local_ip(d.get("ip", "")))
                           for d in S.devices.values()),
                          key=lambda d: (not d.get("online"), d.get("ip", ""))),
        "zones": zone_summary(),
        "tailnet": sorted(S.tailnet.values(), key=lambda x: (not x.get("self"), not x.get("online"), x.get("name", ""))),
        "geo": {ip: S.geo[ip] for ip in {s["ip"] for s in sources} | {a["src"] for a in alerts} if ip in S.geo},
    }


# --------------------------------------------------------------------------- HTTP
def load_token():
    try:
        with open(TOKEN_FILE) as f:
            tok = f.read().strip()
            if tok:
                return tok
    except FileNotFoundError:
        pass
    tok = secrets.token_urlsafe(12)
    try:
        os.makedirs(os.path.dirname(TOKEN_FILE), exist_ok=True)
        with open(TOKEN_FILE, "w") as f:
            f.write(tok + "\n")
        os.chmod(TOKEN_FILE, 0o600)
    except Exception as ex:
        print("sentinel: could not write token file:", ex, file=sys.stderr)
    return tok


TOKEN = None
MIME = {".html": "text/html; charset=utf-8", ".js": "text/javascript", ".png": "image/png",
        ".ico": "image/x-icon", ".webmanifest": "application/manifest+json", ".json": "application/json",
        ".svg": "image/svg+xml", ".css": "text/css"}


class Handler(BaseHTTPRequestHandler):
    server_version = "Sentinel/" + VERSION
    sys_version = ""

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/api/state":
            with LOCK:
                snap = snapshot()
            return self._send(200, snap)
        if path == "/api/health":
            return self._send(200, {"ok": True, "version": VERSION})
        if WEB_ROOT and not path.startswith("/api/"):
            rel = os.path.normpath(path.lstrip("/")) if path not in ("", "/") else "index.html"
            full = os.path.realpath(os.path.join(WEB_ROOT, rel))
            if not full.startswith(os.path.realpath(WEB_ROOT)) or not os.path.isfile(full):
                full = os.path.join(WEB_ROOT, "index.html")
            with open(full, "rb") as f:
                return self._send(200, f.read(), MIME.get(os.path.splitext(full)[1], "application/octet-stream"))
        self._send(404, {"error": "Not found"})

    def do_POST(self):
        key = self.headers.get("X-Sentinel-Key", "")
        if not hmac.compare_digest(key.encode(), TOKEN.encode()):
            return self._send(401, {"error": "Enter the access key shown when you installed Sentinel."})
        try:
            n = int(self.headers.get("Content-Length", "0"))
            if n > 10000:
                raise ValueError
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return self._send(400, {"error": "Bad request"})
        requester = norm_ip(self.headers.get("X-Real-IP") or self.client_address[0])
        path = self.path.split("?")[0]
        if path == "/api/notify-test":
            with LOCK:
                n = dict(S.settings["notify"])
            if not n.get("webhook"):
                return self._send(400, {"error": "Paste your Discord webhook link first."})
            try:
                discord_send(n, {"title": "\u2705 Sentinel is connected", "color": 0x45C6E6,
                                 "description": "High and critical alerts and your daily summary from **%s** will post here." % HOST,
                                 "footer": {"text": HOST}, "timestamp": iso(now_ms())})
            except Exception as ex:
                msg = describe_error(ex)
                with LOCK:
                    S.notify_status = "Last message failed: " + msg
                return self._send(502, {"error": msg})
            with LOCK:
                S.notify_status = "Test sent at %s" % time.strftime("%H:%M")
            return self._send(200, {"ok": True, "message": "Test sent. Check your Discord channel."})
        if path in ("/api/block", "/api/unblock"):
            ip = valid_ip(body.get("ip"))
            if not ip:
                return self._send(400, {"error": "That isn't a valid IP address."})
            if path == "/api/block":
                if is_loopback(ip) or ip in S.my_ips:
                    return self._send(400, {"error": "Sentinel won't block this server's own address."})
                if ip == requester:
                    return self._send(400, {"error": "That's the address you're connecting from, so blocking it would lock you out."})
                if pf_host() and ip == pf_host():
                    return self._send(400, {"error": "That's your router. Blocking it would cut this server off the network."})
                ok, msg = block_ip(ip)
            else:
                ok, msg = unblock_ip(ip)
            if ok:
                t = now_ms()
                with LOCK:
                    add_event(t, "DROP" if path == "/api/block" else "INFO", msg.split(" The rule")[0] + " (from dashboard)", "system")
                    for a in S.alerts.values():
                        if a.get("src") == ip and a["status"] != "closed":
                            a["log"].append([t, msg.split(" The rule")[0]])
                    S.dirty = True
            return self._send(200 if ok else 500, {"ok": ok, "message": msg} if ok else {"error": msg})
        if path == "/api/pfsense":
            act = body.get("action")
            pf = S.settings["pfsense"]
            if act == "key":
                key = pf_pubkey(create=True)
                return self._send(200 if key else 500, {"ok": bool(key), "message": "Key ready. Copy it into pfSense."} if key else {"error": "Couldn't create an SSH key (is ssh-keygen installed?)"})
            if act == "save":
                host = str(body.get("host", pf.get("host", ""))).strip()
                user = str(body.get("user", pf.get("user", "admin"))).strip()
                iface = str(body.get("iface", pf.get("iface", "wan"))).strip()
                if host and not (norm_ip(host) or re.match(r"^[A-Za-z0-9.-]{1,253}$", host)):
                    return self._send(400, {"error": "That router address doesn't look right."})
                if not re.match(r"^[a-z_][a-z0-9_.-]{0,31}$", user):
                    return self._send(400, {"error": "That pfSense username doesn't look right."})
                if not re.match(r"^[a-z0-9_.]{1,16}$", iface):
                    return self._send(400, {"error": "That interface name doesn't look right (usually 'wan')."})
                with LOCK:
                    pf.update(host=host, user=user, iface=iface)
                    S.dirty = True
                return self._send(200, {"ok": True, "message": "pfSense settings saved"})
            if act == "test":
                pf_pubkey(create=True)
                ok, msg = pf_check()
                with LOCK:
                    pf["enabled"] = pf["enabled"] or ok
                    S.dirty = True
                if ok:
                    DEV_EVT.set()
                return self._send(200 if ok else 502, {"ok": ok, "message": msg} if ok else {"error": msg})
            if act == "disconnect":
                with LOCK:
                    pf["enabled"] = False
                    S.pf["sshOk"] = None
                    S.pf["sshMsg"] = ""
                    S.dirty = True
                return self._send(200, {"ok": True, "message": "Router blocking turned off. Existing router blocks stay in pfSense."})
            return self._send(400, {"error": "Unknown action"})
        if path == "/api/settings" and isinstance(body.get("notify"), dict) and "webhook" in body["notify"]:
            url = str(body["notify"].get("webhook") or "").strip()
            if not url:
                with LOCK:
                    S.settings["notify"].update(webhook="", webhookName="")
                    S.dirty = True
                return self._send(200, {"ok": True, "message": "Discord disconnected"})
            if not RX_WEBHOOK.match(url):
                return self._send(400, {"error": "That doesn't look like a Discord webhook link. It should start with https://discord.com/api/webhooks/"})
            try:
                info = discord_request(url)
            except Exception as ex:
                return self._send(400, {"error": describe_error(ex)})
            with LOCK:
                S.settings["notify"].update(webhook=url, webhookName=str(info.get("name") or "Discord webhook")[:80])
                S.dirty = True
            return self._send(200, {"ok": True, "message": "Connected to %s" % (info.get("name") or "Discord")})
        with LOCK:
            t = now_ms()
            if path == "/api/alert":
                a = S.by_id.get(str(body.get("id")))
                act = body.get("action")
                if not a:
                    return self._send(404, {"error": "That alert no longer exists."})
                if act == "ack":
                    a["status"], a["owner"] = "ack", "You"
                    a["ackAt"] = a["ackAt"] or t
                    a["log"].append([t, "Acknowledged from the dashboard"])
                elif act == "escalate":
                    a["status"] = "escalated"
                    a["ackAt"] = a["ackAt"] or t
                    a["log"].append([t, "Escalated for investigation"])
                elif act == "close":
                    a["status"] = "closed"
                    a["ackAt"] = a["ackAt"] or t
                    a["log"].append([t, "Closed from the dashboard"])
                elif act == "reopen":
                    a["status"] = "new"
                    a["log"].append([t, "Reopened"])
                else:
                    return self._send(400, {"error": "Unknown action"})
                S.dirty = True
                return self._send(200, {"ok": True, "message": "%s updated" % a["id"]})
            if path == "/api/sources":
                if body.get("action") == "clear":
                    keep = S.blocked | S.pf["edgeBlocked"]
                    gone = [ip for ip in S.sources if ip not in keep]
                    for ip in gone:
                        S.sources.pop(ip, None)
                        S.pf["recent"].pop(ip, None)
                        S.fails.pop(ip, None)
                        S.fw_ports.pop(ip, None)
                    S.dirty = True
                    add_event(t, "INFO", "Hostile sources list cleared from the dashboard (%d removed)" % len(gone), "system")
                    return self._send(200, {"ok": True, "message": ("Cleared %d source%s. Blocked addresses stay listed." % (len(gone), "" if len(gone) == 1 else "s")) if gone else "Nothing to clear."})
                return self._send(400, {"error": "Unknown action"})
            if path == "/api/lan-sweep":
                DEV_EVT.set()
                return self._send(200, {"ok": True, "message": "Scanning your network. New devices show up in about a minute."})
            if path == "/api/device":
                mac = str(body.get("mac", "")).lower()
                d = S.devices.get(mac)
                if not d:
                    return self._send(404, {"error": "That device isn't in the list anymore."})
                act = body.get("action")
                label = dev_label(d)
                if act == "rename":
                    d["name"] = re.sub(r"[\x00-\x1f]", "", str(body.get("name", "")))[:40].strip()
                    msg = "Renamed to %s" % dev_label(d) if d["name"] else "Name cleared"
                elif act == "known":
                    d["known"] = bool(body.get("value"))
                    d.pop("baseline", None)
                    a = S.alerts.get("newdev:%s" % mac)
                    if a and d["known"] and a["status"] != "closed":
                        a["status"], a["ackAt"] = "closed", a["ackAt"] or t
                        a["log"].append([t, "Closed: marked as a known device"])
                    msg = "%s marked as %s" % (label, "known" if d["known"] else "not known")
                elif act == "watch":
                    d["watch"] = bool(body.get("value"))
                    msg = ("Watching %s. You'll get an alert if it goes offline." % label) if d["watch"] else "Stopped watching %s" % label
                elif act == "scan":
                    if not local_ip(d["ip"]):
                        return self._send(400, {"error": "%s is in another zone (%s), and pfSense keeps this server from reaching it. That's the separation doing its job." % (label, d.get("zone") or d["ip"])})
                    d["scanNow"] = True
                    SCAN_EVT.set()
                    msg = "Checking %s for risky services. Results in about a minute." % label
                elif act == "forget":
                    del S.devices[mac]
                    msg = "%s removed. If it's still on your network it will show up again as new." % label
                else:
                    return self._send(400, {"error": "Unknown action"})
                S.dirty = True
                return self._send(200, {"ok": True, "message": msg})
            if path == "/api/settings":
                msg = "Settings saved"
                if isinstance(body.get("devices"), dict) and "notifyNew" in body["devices"]:
                    S.settings["devices"]["notifyNew"] = bool(body["devices"]["notifyNew"])
                    msg = "New-device posts to Discord %s" % ("on" if S.settings["devices"]["notifyNew"] else "off")
                    S.dirty = True
                if "autoblock" in body:
                    S.settings["autoblock"] = bool(body["autoblock"])
                    msg = "Automatic blocking %s" % ("on" if S.settings["autoblock"] else "off")
                    S.dirty = True
                if isinstance(body.get("notify"), dict):
                    try:
                        update_notify(body["notify"])
                    except (ValueError, TypeError):
                        return self._send(400, {"error": "Those notification settings aren't valid."})
                    msg = body.get("message") or "Notification settings saved"
                return self._send(200, {"ok": True, "message": msg})
        self._send(404, {"error": "Not found"})


def main():
    global TOKEN
    TOKEN = load_token()
    S.load()
    S.my_ips = my_addresses()
    for fn in (journal_loop, sampler_loop, saver_loop, notifier_loop, summary_loop,
               geo_loop, devices_loop, portscan_loop, tailscale_loop, autoblock_loop, syslog_loop, pf_loop):
        threading.Thread(target=fn, daemon=True).start()
    srv = ThreadingHTTPServer((BIND_HOST, BIND_PORT), Handler)
    print("Sentinel agent %s listening on %s:%d" % (VERSION, BIND_HOST, BIND_PORT), flush=True)
    try:
        srv.serve_forever()
    finally:
        with LOCK:
            S.save()


if __name__ == "__main__":
    main()
