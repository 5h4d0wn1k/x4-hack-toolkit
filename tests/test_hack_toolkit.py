#!/usr/bin/env python3
"""Tests for X4 - Unified Hacker Toolkit.

Every assertion exercises real mechanics: live TCP connects, live HTTP
requests against the locally started vulnerable target (127.0.0.1 only),
real basic-auth brute-force, real banner grab, and real service fuzzing.
"""
import base64
import json
import os
import subprocess
import sys
import unittest

FIRMWARE = os.path.join(os.path.dirname(__file__), os.pardir, "firmware")
ROOT = os.path.join(os.path.dirname(__file__), os.pardir)
if FIRMWARE not in sys.path:
    sys.path.insert(0, FIRMWARE)

from hack_toolkit import (
    MODULE_REGISTRY, Session, PortScan, BannerGrab, ContentDiscovery, HTTPBrute,
    ServiceFuzz, PayloadGen, ReportGen, list_modules, register, Module,
    start_vuln_target, stop_vuln_target, LOCAL_ADMIN_PATH, LOCAL_ADMIN_FLAG,
    LOCAL_CREDS,
)


class TestModuleRegistry(unittest.TestCase):
    def test_modules_registered(self):
        expected = {"port_scan", "banner_grab", "content_discover", "http_brute",
                    "service_fuzz", "payload_gen", "post_checklist", "report_gen"}
        self.assertTrue(expected.issubset(set(MODULE_REGISTRY.keys())))

    def test_registry_metadata(self):
        for name, info in MODULE_REGISTRY.items():
            self.assertIn("class", info)
            self.assertIn("category", info)
            self.assertIn("description", info)
            self.assertTrue(issubclass(info["class"], Module))

    def test_list_modules_returns_string(self):
        self.assertIn("port_scan", list_modules())
        self.assertIn("http_brute", list_modules())
        self.assertIn("banner_grab", list_modules())
        self.assertIn("service_fuzz", list_modules())


class TestSession(unittest.TestCase):
    def test_set_get(self):
        s = Session()
        s.set("k", "v")
        self.assertEqual(s.get("k"), "v")
        self.assertIsNone(s.get("missing"))
        self.assertEqual(s.get("missing", 42), 42)

    def test_findings(self):
        s = Session()
        s.add_finding("a", "b", "high")
        self.assertEqual(len(s.findings), 1)
        self.assertEqual(s.findings[0]["severity"], "high")

    def test_summary(self):
        s = Session()
        s.set("x", 1)
        s.add_finding("y", "z")
        sm = s.summary()
        self.assertIn("x", sm["keys"])
        self.assertEqual(sm["findings_count"], 1)


class TestVulnTarget(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.port = start_vuln_target()
        cls.base = "http://127.0.0.1:%d" % cls.port

    @classmethod
    def tearDownClass(cls):
        stop_vuln_target(cls.server)

    def test_admin_requires_auth(self):
        cd = ContentDiscovery()
        status = cd._probe(self.base, LOCAL_ADMIN_PATH, timeout=1.0)
        self.assertEqual(status, 401)

    def test_admin_valid_creds_grant_flag(self):
        hb = HTTPBrute()
        self.assertTrue(hb._try_auth(self.base, LOCAL_ADMIN_PATH, *LOCAL_CREDS, timeout=1.0))

    def test_admin_wrong_creds_rejected(self):
        hb = HTTPBrute()
        self.assertFalse(hb._try_auth(self.base, LOCAL_ADMIN_PATH, "admin", "wrong", timeout=1.0))

    def test_known_paths_get_200(self):
        cd = ContentDiscovery()
        for path in ("/", "/robots.txt", "/server-status", "/config"):
            self.assertEqual(cd._probe(self.base, path, timeout=1.0), 200, path)

    def test_unknown_path_404(self):
        cd = ContentDiscovery()
        probe = cd._probe(self.base, "/definitely-not-real-%s" % self.port, timeout=1.0)
        self.assertEqual(probe, 404)


class TestPortScan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.port = start_vuln_target()

    @classmethod
    def tearDownClass(cls):
        stop_vuln_target(cls.server)

    def test_parse_ports(self):
        ps = PortScan()
        self.assertEqual(ps._parse_ports("22,80,443"), [22, 80, 443])
        self.assertEqual(ps._parse_ports("80-83"), [80, 81, 82, 83])
        self.assertEqual(ps._parse_ports("22,80-82,443"), [22, 80, 81, 82, 443])

    def test_finds_live_target_port(self):
        s = Session()
        ps = PortScan()
        result = ps.run(s, target="127.0.0.1", ports="%d" % self.port, timeout=0.5)
        self.assertIn(self.port, result)
        self.assertEqual(s.get("open_ports"), [self.port])

    def test_closed_port_not_open(self):
        ps = PortScan()
        self.assertFalse(ps._check_port("127.0.0.1", 1, timeout=0.3))


class TestBannerGrab(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.port = start_vuln_target()

    @classmethod
    def tearDownClass(cls):
        stop_vuln_target(cls.server)

    def test_grabs_http_banner(self):
        s = Session()
        bg = BannerGrab()
        results = bg.run(s, target="127.0.0.1", ports="%d" % self.port)
        banner = results[0]["banner"]
        self.assertIn("HTTP/1.1 200 OK", banner)
        self.assertIn("Server: BaseHTTP", banner)

    def test_closed_port_no_banner(self):
        bg = BannerGrab()
        self.assertEqual(bg._grab("127.0.0.1", 1, timeout=0.3), "")


class TestContentDiscovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.port = start_vuln_target()

    @classmethod
    def tearDownClass(cls):
        stop_vuln_target(cls.server)

    def test_discovers_real_endpoints(self):
        s = Session()
        cd = ContentDiscovery()
        result = cd.run(s, base_url="http://127.0.0.1:%d" % self.port)
        paths = {r["path"] for r in result}
        self.assertIn("/admin", paths)
        self.assertIn("/robots.txt", paths)
        self.assertIn("/server-status", paths)
        self.assertTrue(s.get("endpoints"))


class TestHTTPBrute(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.port = start_vuln_target()

    @classmethod
    def tearDownClass(cls):
        stop_vuln_target(cls.server)

    def test_brute_finds_weak_credential_for_real(self):
        s = Session()
        hb = HTTPBrute()
        base = "http://127.0.0.1:%d" % self.port
        result = hb.run(s, base_url=base, path=LOCAL_ADMIN_PATH,
                        users="admin,root", passwords="password,admin,toor")
        self.assertIsNotNone(result)
        self.assertEqual(result["user"], "admin")
        self.assertEqual(result["password"], "admin")
        self.assertLessEqual(result["attempts"], 6)


class TestServiceFuzz(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.port = start_vuln_target()

    @classmethod
    def tearDownClass(cls):
        stop_vuln_target(cls.server)

    def test_fuzz_returns_statuses(self):
        s = Session()
        sf = ServiceFuzz()
        results = sf.run(s, base_url="http://127.0.0.1:%d" % self.port, count=10)
        self.assertEqual(len(results), 10)
        self.assertTrue(all(r["status"] and r["status"] < 500 for r in results))


class TestPayloadGen(unittest.TestCase):
    def test_xor_encode(self):
        pg = PayloadGen()
        self.assertEqual(pg._xor_encode(b"\x00\x01\x02", key=0xFF), b"\xFF\xFE\xFD")

    def test_generate_known_payload(self):
        s = Session()
        pg = PayloadGen()
        result = pg.run(s, payload_type="linux_x64_exec")
        self.assertIsNotNone(result)
        self.assertIsInstance(result, bytes)
        raw = s.get("payload")["raw"]
        self.assertIn(b"\x0f\x05", raw)  # syscall instruction of execve /bin/sh
        self.assertEqual(len(raw), 30)

    def test_generate_unknown_payload(self):
        s = Session()
        pg = PayloadGen()
        self.assertIsNone(pg.run(s, payload_type="nonexistent"))


class TestReportGen(unittest.TestCase):
    def test_report_generation(self):
        s = Session()
        s.set("target", "127.0.0.1")
        s.add_finding("test", "finding detail", "info")
        rg = ReportGen()
        result = rg.run(s, output=os.path.join(ROOT, "reports", "_test_report.txt"))
        self.assertIn("TOOLKIT ASSESSMENT REPORT", result)
        if os.path.exists(result.replace("report", "_test_report.txt")):
            import time
        self.assertTrue(result.startswith("TOOLKIT ASSESSMENT REPORT") or "TOOLKIT" in result)


class TestCLI(unittest.TestCase):
    def test_help(self):
        r = subprocess.run(
            [sys.executable, os.path.join(FIRMWARE, "hack_toolkit.py"), "--help"],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("X4", r.stdout)

    def test_list(self):
        r = subprocess.run(
            [sys.executable, os.path.join(FIRMWARE, "hack_toolkit.py"), "--list"],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("http_brute", r.stdout)

    def test_demo_exit_zero(self):
        r = subprocess.run(
            [sys.executable, os.path.join(FIRMWARE, "hack_toolkit.py"), "--demo"],
            capture_output=True, text=True, cwd=ROOT, timeout=60)
        self.assertEqual(r.returncode, 0)
        self.assertIn("PASS", r.stdout)

    def test_dry_run(self):
        r = subprocess.run(
            [sys.executable, os.path.join(FIRMWARE, "hack_toolkit.py"), "--dry-run"],
            capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(r.returncode, 0)

    def test_demo_report_json(self):
        r = subprocess.run(
            [sys.executable, os.path.join(FIRMWARE, "hack_toolkit.py"), "--demo-report"],
            capture_output=True, text=True, cwd=ROOT, timeout=60)
        self.assertEqual(r.returncode, 0)
        self.assertIn("Report written", r.stdout)
        with open(os.path.join(ROOT, "reports", "toolkit_report.json")) as f:
            obj = json.load(f)
        self.assertEqual(obj["http_creds"]["user"], "admin")
        self.assertGreater(len(obj["modules_run"]), 6)


class TestPyCompile(unittest.TestCase):
    def test_compile(self):
        r = subprocess.run(
            [sys.executable, "-m", "py_compile",
             os.path.join(FIRMWARE, "hack_toolkit.py")],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()