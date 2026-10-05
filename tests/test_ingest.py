"""Tests for the alert ingest endpoints (standard library only).

    python3 -m unittest discover -s tests -v

Runs the real HTTP handler on a random local port with a throwaway state
directory; nothing touches the journal, ufw, the network or Discord.
"""

import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

ROOT = pathlib.Path(__file__).resolve().parent.parent
TMP = tempfile.mkdtemp(prefix="sentinel-test-")
os.environ.update(SENTINEL_STATE_DIR=TMP, SENTINEL_TOKEN_FILE=os.path.join(TMP, "token"),
                  SENTINEL_WATCHDOG_SILENT_MIN="5")
spec = importlib.util.spec_from_file_location("sentinel_agent", ROOT / "agent" / "sentinel_agent.py")
sa = importlib.util.module_from_spec(spec)
sys.modules["sentinel_agent"] = sa
spec.loader.exec_module(sa)

KEY = "test-key-123"
INGEST_KEY = "ingest-only-456"
MIN = 60000


def am_alert(name, status="firing", fp="abc123", starts="2026-10-05T04:00:00Z", ends="0001-01-01T00:00:00Z",
             **labels):
    labels = {"alertname": name, "host": "ai-lab", **labels}
    return {"status": status, "labels": labels, "fingerprint": fp, "startsAt": starts, "endsAt": ends,
            "annotations": {"summary": "%s summary" % name}, "generatorURL": "http://prometheus:9090/graph"}


def am_payload(*alerts, status="firing"):
    return {"version": "4", "status": status, "receiver": "sentinel", "groupKey": "{}:{}",
            "commonLabels": {"host": "ai-lab"}, "alerts": list(alerts)}


class IngestTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sa.TOKEN = KEY
        sa.INGEST_TOKEN = INGEST_KEY
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), sa.Handler)
        cls.base = "http://127.0.0.1:%d" % cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        with sa.LOCK:
            sa.S.alerts.clear()
            sa.S.by_id.clear()
            sa.S.events.clear()
            sa.S.ingest = {"watchdog": {}, "silent": {}, "last": 0, "received": 0, "sources": {}}
        self.notified = []
        self._orig = sa.enqueue
        sa.enqueue = lambda embed, force=False: self.notified.append(embed)
        sa.S.settings["notify"].update(enabled=True, webhook="https://discord.com/api/webhooks/1/x", minSev="high")

    def tearDown(self):
        sa.enqueue = self._orig

    def post(self, path, body, key=KEY, header="bearer"):
        data = json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method="POST",
                                     headers={"Content-Type": "application/json"})
        if key and header == "bearer":
            req.add_header("Authorization", "Bearer " + key)
        elif key:
            req.add_header("X-Sentinel-Key", key)
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def alerts(self):
        return sorted(sa.S.alerts.values(), key=lambda a: a["time"])

    # --- auth ----------------------------------------------------------------
    def test_requires_key(self):
        self.assertEqual(self.post("/api/ingest/alertmanager", am_payload(), key=None)[0], 401)
        self.assertEqual(self.post("/api/ingest/alertmanager", am_payload(), key="wrong")[0], 401)

    def test_accepts_bearer_and_sentinel_header(self):
        self.assertEqual(self.post("/api/ingest/event", {"title": "x"}, header="bearer")[0], 200)
        self.assertEqual(self.post("/api/ingest/event", {"title": "x"}, header="x-sentinel")[0], 200)

    def test_ingest_key_works_only_on_ingest(self):
        self.assertEqual(self.post("/api/ingest/event", {"title": "x"}, key=INGEST_KEY)[0], 200)
        self.assertEqual(self.post("/api/ingest/alertmanager", am_payload(), key=INGEST_KEY)[0], 200)
        # ...and cannot block addresses, change notifications or the router
        for path, body in (("/api/block", {"ip": "203.0.113.9"}), ("/api/settings", {"autoblock": True}),
                           ("/api/pfsense", {"action": "disconnect"}), ("/api/notify-test", {})):
            self.assertEqual(self.post(path, body, key=INGEST_KEY)[0], 401, path)

    def test_bearer_does_not_unlock_with_wrong_key(self):
        self.assertEqual(self.post("/api/block", {"ip": "203.0.113.9"}, key="nope")[0], 401)

    # --- alertmanager --------------------------------------------------------
    def test_firing_alert_becomes_sentinel_alert(self):
        code, res = self.post("/api/ingest/alertmanager", am_payload(
            am_alert("EndpointDown", severity="page", env="production",
                     mitre_technique="T1499", mitre_tactic="Impact")))
        self.assertEqual((code, res["raised"]), (200, 1))
        [a] = self.alerts()
        self.assertEqual(a["t"], "EndpointDown (production)")
        self.assertEqual((a["sev"], a["tech"], a["tac"], a["host"], a["src"]), ("high", "T1499", "Impact", "ai-lab", "ai-lab"))
        self.assertEqual(a["det"], "EndpointDown summary")
        self.assertEqual(a["ext"]["from"], "Prometheus")
        self.assertEqual(a["ext"]["labels"]["env"], "production")
        self.assertEqual(a["log"][0][1], "Raised by Alertmanager on ai-lab")
        self.assertEqual(len(self.notified), 1)
        self.assertIn("HIGH: EndpointDown (production)", self.notified[0]["title"])

    def test_repeat_notifications_do_not_duplicate(self):
        for _ in range(3):
            self.post("/api/ingest/alertmanager", am_payload(am_alert("HighErrorRatio", severity="page")))
        self.assertEqual(len(self.alerts()), 1)
        self.assertEqual(len(self.notified), 1)

    def test_resolved_closes_and_tells_discord(self):
        self.post("/api/ingest/alertmanager", am_payload(am_alert("WorkerHeartbeatStale", severity="page")))
        code, res = self.post("/api/ingest/alertmanager", am_payload(
            am_alert("WorkerHeartbeatStale", status="resolved", severity="page", ends="2026-10-05T04:12:00Z"),
            status="resolved"))
        self.assertEqual(res["resolved"], 1)
        [a] = self.alerts()
        self.assertEqual(a["status"], "closed")
        self.assertIn("cleared after 12 minutes", a["log"][-1][1])
        self.assertTrue(self.notified[-1]["title"].startswith("✅ RESOLVED"))

    def test_refiring_after_resolve_is_a_new_alert(self):
        self.post("/api/ingest/alertmanager", am_payload(am_alert("QueueBacklog", severity="warn")))
        self.post("/api/ingest/alertmanager", am_payload(am_alert("QueueBacklog", status="resolved", severity="warn")))
        self.post("/api/ingest/alertmanager", am_payload(
            am_alert("QueueBacklog", severity="warn", starts="2026-10-05T06:00:00Z")))
        statuses = [a["status"] for a in self.alerts()]
        self.assertEqual(statuses, ["closed", "new"])

    def test_alert_that_began_before_sentinel_started_still_notifies(self):
        # e.g. the network to Sentinel was down when it started firing
        self.post("/api/ingest/alertmanager", am_payload(am_alert("HostDiskAlmostFull", severity="page",
                                                                  starts="2020-01-01T00:00:00Z")))
        a = self.alerts()[0]
        self.assertEqual(a["time"], sa.rfc3339_ms("2020-01-01T00:00:00Z", 0))
        self.assertEqual(len(self.notified), 1)

    def test_warn_is_medium_and_not_sent_to_discord(self):
        self.post("/api/ingest/alertmanager", am_payload(am_alert("HostMemoryPressure", severity="warn")))
        self.assertEqual(self.alerts()[0]["sev"], "medium")
        self.assertEqual(self.notified, [])

    def test_unknown_mapping_falls_back_safely(self):
        self.post("/api/ingest/alertmanager", am_payload(
            am_alert("Odd", mitre_technique="DROP TABLE", mitre_tactic="Chaos")))
        a = self.alerts()[0]
        self.assertEqual((a["tech"], a["tac"]), ("—", "Impact"))

    def test_hostile_text_is_flattened_and_capped(self):
        al = am_alert("X" * 500)
        al["annotations"]["summary"] = "line1\nline2 " + "y" * 2000
        al["labels"]["host"] = "ai-lab; rm -rf /"
        self.post("/api/ingest/alertmanager", am_payload(al))
        a = self.alerts()[0]
        self.assertNotIn("\n", a["det"])
        self.assertLessEqual(len(a["det"]), 800)
        self.assertLessEqual(len(a["t"]), 120)
        self.assertEqual(a["src"], "ai-labrm-rf")

    def test_rejects_non_alertmanager_body(self):
        self.assertEqual(self.post("/api/ingest/alertmanager", {"hello": 1})[0], 400)
        self.assertEqual(self.post("/api/ingest/alertmanager", [1, 2])[0], 400)

    def test_large_payload_allowed_on_ingest_only(self):
        big = am_payload(*[am_alert("A%d" % i, fp="f%d" % i) for i in range(60)])
        self.assertGreater(len(json.dumps(big)), 10000)
        self.assertEqual(self.post("/api/ingest/alertmanager", big)[0], 200)
        self.assertEqual(len(self.alerts()), 60)

    # --- watchdog / dead man's switch ---------------------------------------
    def test_watchdog_is_heartbeat_not_alert(self):
        code, res = self.post("/api/ingest/alertmanager", am_payload(am_alert("Watchdog", severity="none")))
        self.assertEqual(res, {"ok": True, "raised": 0, "resolved": 0, "heartbeats": 1})
        self.assertEqual(self.alerts(), [])
        self.assertIn("ai-lab", sa.S.ingest["watchdog"])

    def test_silence_raises_then_heartbeat_closes(self):
        self.post("/api/ingest/alertmanager", am_payload(am_alert("Watchdog")))
        last = sa.S.ingest["watchdog"]["ai-lab"]
        with sa.LOCK:
            sa.START_MS = last - 10 * MIN
            self.assertEqual(sa.watchdog_check(last + 4 * MIN), [])          # still inside the window
            raised = sa.watchdog_check(last + 6 * MIN)
            self.assertEqual(len(raised), 1)
            self.assertEqual(sa.watchdog_check(last + 7 * MIN), [])          # raised once, not every minute
        [a] = self.alerts()
        self.assertEqual((a["t"], a["sev"], a["tech"]), ("Monitoring on ai-lab stopped reporting", "high", "T1562.006"))
        self.assertEqual(len(self.notified), 1)
        self.post("/api/ingest/alertmanager", am_payload(am_alert("Watchdog")))
        self.assertEqual(self.alerts()[0]["status"], "closed")
        self.assertIn("reporting again", self.alerts()[0]["log"][-1][1])

    def test_resolved_watchdog_raises_immediately(self):
        # Prometheus died: Alertmanager keeps the Watchdog until it expires, then sends it resolved.
        self.post("/api/ingest/alertmanager", am_payload(am_alert("Watchdog")))
        code, res = self.post("/api/ingest/alertmanager", am_payload(am_alert("Watchdog", status="resolved"),
                                                                     status="resolved"))
        self.assertEqual(res["heartbeats"], 0)            # not counted as a heartbeat
        [a] = self.alerts()
        self.assertEqual(a["t"], "Monitoring on ai-lab stopped reporting")
        self.assertIn("stopped evaluating alert rules", a["det"])
        with sa.LOCK:
            self.assertEqual(sa.watchdog_check(sa.now_ms() + 60 * MIN), [])   # not raised twice
        self.post("/api/ingest/alertmanager", am_payload(am_alert("Watchdog")))
        self.assertEqual(self.alerts()[0]["status"], "closed")

    def test_watchdog_grace_after_sentinel_restart(self):
        with sa.LOCK:
            sa.S.ingest["watchdog"]["old-box"] = 0           # heartbeat from long before startup
            sa.START_MS = 100 * MIN
            self.assertEqual(sa.watchdog_check(103 * MIN), [])  # gives the source time to check in
            self.assertEqual(len(sa.watchdog_check(106 * MIN)), 1)

    # --- one-off events --------------------------------------------------------
    def test_info_event_goes_to_feed_only(self):
        code, res = self.post("/api/ingest/event", {"source": "ai-lab", "level": "info", "kind": "GitOps",
                                                    "title": "staging deployed", "text": "staging: deployed 65cda30"})
        self.assertEqual((code, res["alert"]), (200, None))
        self.assertEqual(self.alerts(), [])
        self.assertIn("deployed 65cda30", sa.S.events[-1]["text"])

    def test_critical_event_raises_mapped_alert(self):
        code, res = self.post("/api/ingest/event", {
            "source": "ai-lab", "level": "critical", "kind": "GitOps", "key": "refused:prod:abc",
            "title": "Refused unsigned image (production)", "text": "signature verification failed",
            "technique": "T1195.002", "tactic": "Initial Access"})
        self.assertEqual(code, 200)
        a = sa.S.by_id[res["alert"]]
        self.assertEqual((a["sev"], a["tech"], a["tac"], a["ext"]["from"]), ("critical", "T1195.002", "Initial Access", "GitOps"))
        self.assertEqual(a["log"][0][1], "Reported by ai-lab")
        self.assertEqual(len(self.notified), 1)

    def test_event_validation(self):
        self.assertEqual(self.post("/api/ingest/event", {"level": "info"})[0], 400)
        self.assertEqual(self.post("/api/ingest/event", {"title": "x", "level": "apocalyptic"})[0], 400)

    # --- persistence and snapshot ----------------------------------------------
    def test_state_round_trip_and_snapshot(self):
        self.post("/api/ingest/alertmanager", am_payload(am_alert("Watchdog")))
        with sa.LOCK:
            sa.S.save()
            fresh = sa.Store()
            fresh.load()
            snap = sa.ingest_snapshot(sa.now_ms())
        self.assertIn("ai-lab", fresh.ingest["watchdog"])
        self.assertEqual(snap["sources"][0]["name"], "ai-lab")
        self.assertEqual(snap["sources"][0]["kind"], "alertmanager")


class TimestampTest(unittest.TestCase):
    def test_rfc3339(self):
        self.assertEqual(sa.rfc3339_ms("1970-01-01T00:00:01.5Z", 0), 1500)
        self.assertEqual(sa.rfc3339_ms("1970-01-01T01:00:00+01:00", 0), 0)
        self.assertEqual(sa.rfc3339_ms("2026-10-05T04:00:00.123456789Z", 0) % 1000, 123)
        self.assertEqual(sa.rfc3339_ms("0001-01-01T00:00:00Z", 42), 42)
        self.assertEqual(sa.rfc3339_ms("garbage", 7), 7)


if __name__ == "__main__":
    unittest.main()
