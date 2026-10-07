"""Unit tests for the agent's pure helpers: address classification, parsing of
untrusted input (router ARP/DHCP output, /proc socket rows, payload text) and
severity mapping. No network, journal or firewall access.

    python3 -m unittest discover -s tests -v     (or: pytest)
"""

import importlib.util
import os
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent

if "sentinel_agent" in sys.modules:  # already loaded by another test module
    sa = sys.modules["sentinel_agent"]
else:
    TMP = tempfile.mkdtemp(prefix="sentinel-test-")
    os.environ.setdefault("SENTINEL_STATE_DIR", TMP)
    os.environ.setdefault("SENTINEL_TOKEN_FILE", os.path.join(TMP, "token"))
    spec = importlib.util.spec_from_file_location("sentinel_agent", ROOT / "agent" / "sentinel_agent.py")
    sa = importlib.util.module_from_spec(spec)
    sys.modules["sentinel_agent"] = sa
    spec.loader.exec_module(sa)


class AddressTest(unittest.TestCase):
    def test_private_ranges(self):
        for ip in ("10.20.1.5", "192.168.1.1", "172.16.0.9", "100.64.1.2", "127.0.0.1", "fe80::1"):
            self.assertTrue(sa.is_private(ip), ip)

    def test_public_addresses_are_not_private(self):
        for ip in ("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"):
            self.assertFalse(sa.is_private(ip), ip)

    def test_ipv4_mapped_ipv6_is_unwrapped(self):
        self.assertTrue(sa.is_private("::ffff:192.168.1.10"))
        self.assertFalse(sa.is_private("::ffff:8.8.8.8"))
        self.assertEqual(sa.norm_ip("::ffff:10.0.0.1"), "10.0.0.1")

    def test_garbage_is_rejected_everywhere(self):
        for bad in ("", "not-an-ip", "999.1.1.1", "1.2.3"):
            self.assertFalse(sa.is_private(bad))
            self.assertFalse(sa.is_loopback(bad))
            self.assertIsNone(sa.norm_ip(bad))
            self.assertIsNone(sa.valid_ip(bad))

    def test_valid_ip_strips_whitespace(self):
        self.assertEqual(sa.valid_ip("  203.0.113.7 "), "203.0.113.7")
        self.assertIsNone(sa.valid_ip(None))

    def test_loopback(self):
        self.assertTrue(sa.is_loopback("127.0.0.1"))
        self.assertTrue(sa.is_loopback("::1"))
        self.assertFalse(sa.is_loopback("10.0.0.1"))

    def test_broadcast_and_multicast(self):
        for ip in ("255.255.255.255", "224.0.0.251", "239.255.255.250", "10.20.1.255", "ff02::fb"):
            self.assertTrue(sa.is_broadcast(ip), ip)
        self.assertFalse(sa.is_broadcast("10.20.1.25"))
        self.assertFalse(sa.is_broadcast("junk"))

    def test_not_a_host(self):
        for ip in ("0.0.0.0", "255.255.255.255", "224.0.0.1", "169.254.1.1", "garbage"):  # noqa: S104
            self.assertTrue(sa.not_a_host(ip), ip)
        self.assertFalse(sa.not_a_host("203.0.113.9"))


class ProcSocketTest(unittest.TestCase):
    def test_ipv4_row(self):
        # /proc/net/tcp stores 127.0.0.1:22 as little-endian hex
        self.assertEqual(sa.hex_addr("0100007F:0016", False), ("127.0.0.1", 22))

    def test_ipv6_row(self):
        ip, port = sa.hex_addr("00000000000000000000000001000000:01BB", True)
        self.assertEqual((ip, port), ("::1", 443))

    def test_ipv4_mapped_v6_row_is_normalised(self):
        # ::ffff:10.0.0.1 as /proc/net/tcp6 prints it
        ip, port = sa.hex_addr("0000000000000000FFFF00000100000A:1F90", True)
        self.assertEqual((ip, port), ("10.0.0.1", 8080))

    def test_port_names(self):
        self.assertEqual(sa.port_name(22), "SSH")
        self.assertEqual(sa.port_name(65000), "Other")


class UntrustedTextTest(unittest.TestCase):
    def test_clean_flattens_and_caps(self):
        self.assertEqual(sa.clean("a\n\tb   c", 100), "a b c")
        self.assertEqual(sa.clean("x" * 50, 10), "x" * 10)
        self.assertEqual(sa.clean(None, 5), "")
        self.assertEqual(sa.clean(42, 5), "42")

    def test_ext_source_keeps_safe_characters(self):
        self.assertEqual(sa.ext_source("ai-lab:9093"), "ai-lab:9093")
        self.assertEqual(sa.ext_source("<script>"), "script")
        self.assertEqual(sa.ext_source(""), "unknown")
        self.assertEqual(len(sa.ext_source("a" * 200)), 64)

    def test_ext_mapping_validates_mitre_fields(self):
        self.assertEqual(
            sa.ext_mapping({"mitre_technique": "T1110.001", "mitre_tactic": "Credential Access"}),
            ("T1110.001", "Credential Access"),
        )
        self.assertEqual(sa.ext_mapping({"mitre_technique": "drop table", "mitre_tactic": "Nope"}), ("—", "Impact"))
        self.assertEqual(sa.ext_mapping({}), ("—", "Impact"))


class MacTest(unittest.TestCase):
    def test_norm_mac_pads_and_lowercases(self):
        self.assertEqual(sa.norm_mac("A:B:C:D:E:F"), "0a:0b:0c:0d:0e:0f")
        self.assertEqual(sa.norm_mac(None), "00")

    def test_private_mac(self):
        self.assertTrue(sa.private_mac("da:a1:19:00:00:01"))  # locally administered bit set
        self.assertFalse(sa.private_mac("00:1a:2b:3c:4d:5e"))
        self.assertFalse(sa.private_mac(""))
        self.assertFalse(sa.private_mac("zz:zz"))

    def test_flag_emoji(self):
        self.assertEqual(sa.flag("us"), "\U0001f1fa\U0001f1f8")
        self.assertEqual(sa.flag("usa"), "")
        self.assertEqual(sa.flag("1a"), "")


class RouterNeighborsTest(unittest.TestCase):
    OUT = (
        "? (10.20.1.10) at aa:bb:cc:dd:ee:01 on igb1 expires in 1185 seconds [ethernet]\n"
        "? (10.20.1.1) at aa:bb:cc:dd:ee:ff on igb1 permanent [ethernet]\n"
        "? (203.0.113.1) at 11:22:33:44:55:66 on igb0 expires in 900 seconds [ethernet]\n"
        "? (10.20.30.7) at aa:bb:cc:dd:ee:02 on igb1.30 expires in 600 seconds [vlan]\n"
        "? (10.20.30.8) at (incomplete) on igb1.30 expired [vlan]\n"
        "@@WAN@@\nigb0\n"
        "@@ISC@@\n"
        'lease 10.20.1.10 {\n  hardware ethernet aa:bb:cc:dd:ee:01;\n  client-hostname "desktop";\n}\n'
        "@@KEA@@\n"
        "address,hwaddr,hostname,expire\n"
        "10.20.30.7,aa:bb:cc:dd:ee:02,tv.,9999999999\n"
        "10.20.30.9,aa:bb:cc:dd:ee:03,old-phone,1\n"
        "@@END@@\n"
    )

    def test_parses_arp_and_both_lease_formats(self):
        found, ok = sa.parse_router_neighbors(self.OUT, 2_000_000_000_000)
        self.assertTrue(ok)
        self.assertEqual(found["10.20.1.10"], ("aa:bb:cc:dd:ee:01", "desktop", "igb1"))
        self.assertEqual(found["10.20.30.7"], ("aa:bb:cc:dd:ee:02", "tv", "igb1.30"))

    def test_skips_router_wan_and_incomplete_entries(self):
        found, _ = sa.parse_router_neighbors(self.OUT, 2_000_000_000_000)
        self.assertNotIn("10.20.1.1", found)  # permanent = the router itself
        self.assertNotIn("203.0.113.1", found)  # WAN side
        self.assertNotIn("10.20.30.8", found)  # incomplete
        self.assertEqual(len(found), 2)

    def test_empty_output_is_not_ok(self):
        self.assertEqual(sa.parse_router_neighbors("", 0), ({}, False))


class FirewallLogTest(unittest.TestCase):
    def test_tcp_without_syn_is_a_stray_reply(self):
        self.assertTrue(sa.is_stray("tcp", ["443", "51000", "0", "FA"]))
        self.assertFalse(sa.is_stray("tcp", ["443", "22", "0", "S"]))
        self.assertFalse(sa.is_stray("tcp", ["443"]))

    def test_udp_from_well_known_server_port_is_stray(self):
        self.assertTrue(sa.is_stray("UDP", ["53", "40000"]))
        self.assertFalse(sa.is_stray("udp", ["40000", "53"]))
        self.assertFalse(sa.is_stray("icmp", []))


class WazuhMappingTest(unittest.TestCase):
    def test_level_to_severity(self):
        self.assertEqual([sa.wz_level_sev(n) for n in (3, 7, 12, 15)], ["low", "medium", "high", "critical"])

    def test_timestamps(self):
        self.assertEqual(sa.wz_time("2026-10-05T04:00:00.000+0000"), 1791172800000)
        self.assertEqual(sa.wz_time("2026-10-05T04:00:00Z"), 1791172800000)
        self.assertIsInstance(sa.wz_time("garbage"), int)  # falls back to now


if __name__ == "__main__":
    unittest.main()
