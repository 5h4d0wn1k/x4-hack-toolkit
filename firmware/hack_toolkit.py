#!/usr/bin/env python3
"""X4 - Unified Hacker Toolkit (hack_toolkit)

Extensible Metasploit-shaped security framework with plugin registry,
shared session/report model, and bundled modules. Pure stdlib.
"""

import sys
import os
import argparse
import hashlib
import time
import socket
import struct
import threading
import random
from abc import ABC, abstractmethod

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
    """List all registered modules."""
    if not MODULE_REGISTRY:
        return "No modules registered."
    lines = []
    lines.append(f"\n{'Category':<12} {'Name':<24} {'Description'}")
    lines.append("-" * 72)
    for info in sorted(MODULE_REGISTRY.values(), key=lambda x: (x["category"], x["name"])):
        lines.append(f"  {info['category']:<12} {info['name']:<24} {info['description']}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Base Module
# ---------------------------------------------------------------------------
class Module(ABC):
    """Base class for all toolkit modules."""

    @abstractmethod
    def run(self, session, **kwargs):
        pass

    def help_text(self):
        return self.__doc__ or "No description."


# ---------------------------------------------------------------------------
# Session Model
# ---------------------------------------------------------------------------
class Session:
    """Shared session for accumulating data across modules."""

    def __init__(self):
        self.data = {}
        self.findings = []
        self.start_time = time.time()

    def set(self, key, value):
        self.data[key] = value

    def get(self, key, default=None):
        return self.data.get(key, default)

    def add_finding(self, category, detail, severity="info"):
        self.findings.append({
            "category": category, "detail": detail,
            "severity": severity, "time": time.time(),
        })

    def summary(self):
        elapsed = time.time() - self.start_time
        return {
            "keys": list(self.data.keys()),
            "findings_count": len(self.findings),
            "elapsed": f"{elapsed:.2f}s",
        }


# ---------------------------------------------------------------------------
# Module 1: Port Scan
# ---------------------------------------------------------------------------
@register("port_scan", "recon", "TCP port scanner with service detection")
class PortScan(Module):
    """Scan TCP ports on a target and detect services."""

    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt",
        8443: "HTTPS-Alt", 6379: "Redis", 27017: "MongoDB",
    }

    def run(self, session, target="127.0.0.1", ports="22,80,443", timeout=1.0, **kwargs):
        port_list = self._parse_ports(ports)
        open_ports = []
        print(f"\n[Port Scan] Target: {target}, Ports: {len(port_list)}")

        for port in port_list:
            status = self._check_port(target, port, timeout)
            svc = self.COMMON_PORTS.get(port, "unknown")
            state = "open" if status else "closed"
            if status:
                open_ports.append(port)
                print(f"  Port {port:<6} open  ({svc})")
            else:
                print(f"  Port {port:<6} closed")

        session.set("open_ports", open_ports)
        session.set("scan_target", target)
        for p in open_ports:
            session.add_finding("port", f"Port {p} open on {target}")
        print(f"  Scan complete: {len(open_ports)}/{len(port_list)} ports open")
        return open_ports

    def _check_port(self, host, port, timeout):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
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
# Module 2: Content Discovery
# ---------------------------------------------------------------------------
@register("content_discover", "recon", "Directory/endpoint brute-force discovery")
class ContentDiscovery(Module):
    """Discover hidden directories and endpoints using wordlist brute-force."""

    DEFAULT_WORDLIST = [
        "admin", "login", "api", "dashboard", "config", "backup", "test",
        "dev", "staging", ".git", ".env", "robots.txt", "sitemap.xml",
        "wp-admin", "wp-login.php", "phpmyadmin", "server-status",
        "console", "debug", "health", "metrics", "graphql", "swagger",
    ]

    def run(self, session, base_url="http://localhost", wordlist=None, **kwargs):
        words = wordlist if wordlist else self.DEFAULT_WORDLIST
        found = []
        print(f"\n[Content Discovery] Base: {base_url}, Words: {len(words)}")

        for word in words:
            path = f"/{word}"
            status = self._probe(base_url, path)
            if status in (200, 301, 302, 403):
                found.append({"path": path, "status": status})
                marker = " [FORBIDDEN]" if status == 403 else ""
                print(f"  FOUND: {path} (HTTP {status}){marker}")
                session.add_finding("content", f"Endpoint found: {path} (HTTP {status})")

        session.set("endpoints", found)
        print(f"  Discovery complete: {len(found)}/{len(words)} paths found")
        return found

    def _probe(self, base_url, path):
        # Simulated probe — returns deterministic results for demo
        seed = hashlib.md5(path.encode()).digest()[0]
        if seed < 30:
            return 200
        elif seed < 50:
            return 301
        elif seed < 60:
            return 403
        return 404


# ---------------------------------------------------------------------------
# Module 3: SSH Brute
# ---------------------------------------------------------------------------
@register("ssh_brute", "brute", "SSH credential brute-force engine")
class SSHBrute(Module):
    """Brute-force SSH credentials using a wordlist."""

    def run(self, session, target="127.0.0.1", port=22, users="root,admin",
            passwords="password,123456,admin", max_attempts=10, **kwargs):
        user_list = [u.strip() for u in str(users).split(",")]
        pass_list = [p.strip() for p in str(passwords).split(",")]
        attempts = 0
        print(f"\n[SSH Brute] Target: {target}:{port}")
        print(f"  Users: {user_list}")
        print(f"  Passwords: {pass_list[:5]}{'...' if len(pass_list) > 5 else ''}")

        for user in user_list:
            for pwd in pass_list:
                if attempts >= max_attempts:
                    break
                attempts += 1
                result = self._try_auth(target, port, user, pwd)
                if result:
                    print(f"  FOUND: {user}:{pwd}")
                    session.add_finding("ssh_brute", f"Valid credential: {user}:{pwd}", "high")
                    session.set("ssh_creds", {"user": user, "password": pwd})
                    return {"user": user, "password": pwd}
            if attempts >= max_attempts:
                break

        print(f"  Brute complete: {attempts} attempts, no credentials found")
        session.set("ssh_attempts", attempts)
        return None

    def _try_auth(self, target, port, user, pwd):
        # Simulated — deterministic based on hash
        h = hashlib.md5(f"{user}:{pwd}".encode()).digest()[0]
        return h == 0x42


# ---------------------------------------------------------------------------
# Module 4: HTTP Brute
# ---------------------------------------------------------------------------
@register("http_brute", "brute", "HTTP basic-auth brute-force engine")
class HTTPBrute(Module):
    """Brute-force HTTP basic authentication."""

    def run(self, session, target="http://localhost", users="admin,root",
            passwords="admin,password,123456", max_attempts=10, **kwargs):
        user_list = [u.strip() for u in str(users).split(",")]
        pass_list = [p.strip() for p in str(passwords).split(",")]
        attempts = 0
        print(f"\n[HTTP Brute] Target: {target}")
        print(f"  Users: {user_list}")
        print(f"  Passwords: {pass_list}")

        for user in user_list:
            for pwd in pass_list:
                if attempts >= max_attempts:
                    break
                attempts += 1
                result = self._try_auth(user, pwd)
                if result:
                    print(f"  FOUND: {user}:{pwd}")
                    session.add_finding("http_brute", f"Valid credential: {user}:{pwd}", "high")
                    return {"user": user, "password": pwd}
            if attempts >= max_attempts:
                break

        print(f"  Brute complete: {attempts} attempts, no credentials found")
        return None

    def _try_auth(self, user, pwd):
        h = hashlib.md5(f"{user}:{pwd}".encode()).digest()[0]
        return h == 0x42


# ---------------------------------------------------------------------------
# Module 5: Payload Generator
# ---------------------------------------------------------------------------
@register("payload_gen", "payload", "Payload template generator")
class PayloadGen(Module):
    """Generate common payload templates for various architectures."""

    PAYLOADS = {
        "linux_x64_reverse": {
            "shellcode": b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05",
            "description": "Linux x64 reverse shell (23 bytes)",
        },
        "linux_x64_exec": {
            "shellcode": b"\x48\x31\xc0\x50\x48\xb8\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x50\x48\x89\xe7\x50\x57\x48\x89\xe6\x48\x31\xd2\xb0\x3b\x0f\x05",
            "description": "Linux x64 execve /bin/sh (27 bytes)",
        },
        "win_x64_calc": {
            "shellcode": b"\x48\x83\xec\x28\xe8\xc0\x00\x00\x00\x48\x8d\x0d\xff\xff\xff\xff",
            "description": "Windows x64 calc.exe (placeholder)",
        },
        "shellcode_encoder": {
            "shellcode": None,
            "description": "XOR encoder (input shellcode -> encoded output)",
        },
    }

    def run(self, session, payload_type="linux_x64_exec", **kwargs):
        print(f"\n[Payload Generator]")
        if payload_type not in self.PAYLOADS:
            print(f"  Unknown payload: {payload_type}")
            print(f"  Available: {', '.join(self.PAYLOADS.keys())}")
            return None

        info = self.PAYLOADS[payload_type]
        if info["shellcode"]:
            encoded = self._xor_encode(info["shellcode"])
            print(f"  Type: {payload_type}")
            print(f"  Description: {info['description']}")
            print(f"  Raw size: {len(info['shellcode'])} bytes")
            print(f"  Encoded size: {len(encoded)} bytes")
            print(f"  Hex: {encoded[:32].hex()}...")
            session.set("payload", {"type": payload_type, "raw": info["shellcode"], "encoded": encoded})
            return encoded
        else:
            print(f"  {payload_type}: {info['description']}")
            return None

    def _xor_encode(self, data, key=0x42):
        return bytes(b ^ key for b in data)


# ---------------------------------------------------------------------------
# Module 6: Post-Exploitation Checklist
# ---------------------------------------------------------------------------
@register("post_checklist", "post", "Post-exploitation assessment checklist")
class PostChecklist(Module):
    """Run a post-exploitation checklist and report findings."""

    CHECKLIST = [
        ("System Info", "Gather OS version, kernel, architecture", "info"),
        ("User Context", "Identify current user, groups, privileges", "info"),
        ("Network Config", "Enumerate interfaces, routes, connections", "info"),
        ("File System", "Check for sensitive files, configs, keys", "medium"),
        ("Persistence", "Check for autorun, cron, scheduled tasks", "high"),
        ("Credentials", "Search for stored credentials, tokens", "high"),
        ("Lateral Movement", "Identify reachable hosts, trust relationships", "medium"),
        ("Data Exfil", "Identify valuable data locations and sizes", "medium"),
        ("Cover Tracks", "Review logging, clear evidence", "low"),
    ]

    def run(self, session, **kwargs):
        print(f"\n[Post-Exploitation Checklist]")
        print(f"  Running {len(self.CHECKLIST)} checks...")

        results = []
        for name, desc, severity in self.CHECKLIST:
            status = self._run_check(name)
            results.append({"check": name, "status": status, "severity": severity})
            icon = "+" if status else "-"
            print(f"  [{icon}] {name}: {desc}")
            if status:
                session.add_finding("post_exploit", f"{name}: completed", severity)

        completed = sum(1 for r in results if r["status"])
        print(f"  Checklist complete: {completed}/{len(results)} checks passed")
        session.set("post_checklist", results)
        return results

    def _run_check(self, name):
        return hashlib.md5(name.encode()).digest()[0] % 3 != 0


# ---------------------------------------------------------------------------
# Module 7: Report Generator
# ---------------------------------------------------------------------------
@register("report_gen", "report", "Generate markdown/text report from session")
class ReportGen(Module):
    """Generate a structured report from session data."""

    def run(self, session, output="session_report.txt", **kwargs):
        print(f"\n[Report Generator]")
        lines = []
        lines.append("=" * 60)
        lines.append("SECURITY ASSESSMENT REPORT")
        lines.append("=" * 60)
        lines.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Session data keys: {', '.join(session.data.keys())}")
        lines.append(f"Total findings: {len(session.findings)}")
        lines.append("")

        # Findings by severity
        by_sev = {"high": [], "medium": [], "low": [], "info": []}
        for f in session.findings:
            by_sev.setdefault(f["severity"], []).append(f)

        for sev in ["high", "medium", "low", "info"]:
            items = by_sev.get(sev, [])
            if items:
                lines.append(f"\n--- {sev.upper()} Findings ({len(items)}) ---")
                for item in items:
                    lines.append(f"  [{item['category']}] {item['detail']}")

        # Scan summary
        if "open_ports" in session.data:
            lines.append(f"\n--- Port Scan Summary ---")
            lines.append(f"  Target: {session.get('scan_target', 'N/A')}")
            lines.append(f"  Open ports: {session.data['open_ports']}")

        if "endpoints" in session.data:
            lines.append(f"\n--- Content Discovery ---")
            lines.append(f"  Endpoints found: {len(session.data['endpoints'])}")

        lines.append("\n" + "=" * 60)
        lines.append("END OF REPORT")
        lines.append("=" * 60)

        report_text = "\n".join(lines)
        output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", output)
        try:
            with open(output_path, "w") as f:
                f.write(report_text)
            print(f"  Report saved: {output_path}")
        except Exception as e:
            print(f"  Could not write file: {e}")
            print(f"  Report content:\n{report_text}")

        print(f"  Findings by severity: high={len(by_sev.get('high', []))}, "
              f"medium={len(by_sev.get('medium', []))}, "
              f"low={len(by_sev.get('low', []))}, "
              f"info={len(by_sev.get('info', []))}")
        return report_text


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="X4 - Unified Hacker Toolkit")
    parser.add_argument("--list", action="store_true", help="List all modules")
    parser.add_argument("--run", type=str, help="Run a module by name")
    parser.add_argument("--demo", action="store_true", default=False, help="Run demo")
    parser.add_argument("--target", type=str, default="127.0.0.1", help="Target host")
    parser.add_argument("--ports", type=str, default="22,80,443", help="Ports to scan")
    parser.add_argument("extra_args", nargs="*", help="Extra module arguments")
    args = parser.parse_args()

    if args.list:
        print("=== X4 - Unified Hacker Toolkit ===")
        print(list_modules())
        return 0

    if args.run:
        if args.run not in MODULE_REGISTRY:
            print(f"Module '{args.run}' not found. Use --list to see available modules.")
            return 1
        session = Session()
        mod_info = MODULE_REGISTRY[args.run]
        mod = mod_info["class"]()
        kwargs = {"target": args.target, "ports": args.ports}
        for extra in args.extra_args:
            if "=" in extra:
                k, v = extra.split("=", 1)
                kwargs[k] = v
        mod.run(session, **kwargs)
        return 0

    if args.demo or len(sys.argv) == 1:
        run_demo()
        return 0

    parser.print_help()
    return 0


def run_demo():
    print("=== X4 - Unified Hacker Toolkit ===")
    print(list_modules())

    session = Session()
    session.set("target", "127.0.0.1")

    print("\n--- Demo: Running port_scan module ---")
    PortScan().run(session, target="127.0.0.1", ports="22,80,443,8080", timeout=0.5)

    print("\n--- Demo: Running content_discover module ---")
    ContentDiscovery().run(session, base_url="http://localhost")

    print("\n--- Demo: Running report_gen module ---")
    ReportGen().run(session)

    summary = session.summary()
    print(f"\n[Session Summary]")
    print(f"  Data keys: {summary['keys']}")
    print(f"  Findings: {summary['findings_count']}")
    print(f"  Elapsed: {summary['elapsed']}")

    print("\n=== Demo complete ===")


if __name__ == "__main__":
    sys.exit(main())
