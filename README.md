# X4 — Unified Hacker Toolkit — hack_toolkit

Extensible Metasploit-shaped security framework with plugin registry, session management, and bundled modules.

## Overview

This project implements a modular security toolkit whose modules **genuinely work**
against a vulnerable HTTP target that the toolkit starts locally on `127.0.0.1`
(a per-run ephemeral stdlib HTTP port). Nothing touches the network or any
real system.

- Real TCP **port scan** against explicit host:port lists (localhost by default)
- Real TCP **banner grab** (with an HTTP probe fallback for silent services)
- Real HTTP **directory brute-force** (`content_discover`) against the live local target
- Real HTTP **basic-auth brute-force** (`http_brute`) that cracks `admin:admin` on the target
- Real **service fuzz** (`service_fuzz`) sending mutated request paths to the target
- Payload template / XOR-encoder, post-exploitation checklist, and text+JSON report modules
- Composable plugin registry with `--list` / `--run <module> key=value` CLI

## Features

- **Module registry**: Auto-discovery via `@register`, listing by category
- **Local vulnerable target**: stdlib HTTP server embedding a weak `admin:admin`
  basic-auth endpoint, secret routes, and a research "flag" — used to prove every module
- **Port scan**: Real TCP `connect()` probes, range/CSV port parsing
- **Banner grab**: Reads real service banners (HTTP status when the server is quiet)
- **Content discovery**: Real HTTP requests; reports which paths exist (200/401/403/redirect)
- **HTTP brute**: Real `Authorization: Basic ...` attempts until the weak credential is found
- **Service fuzz**: Deterministic request-line mutation against the local target
- **Payload library**: Real shellcode bytes + XOR encoder
- **Report module**: Text + JSON (`reports/toolkit_report.json`) report from session data

## Installation

```bash
# No external dependencies required — Python 3.8+ standard library only
python3 firmware/hack_toolkit.py --list
```

## Usage

```bash
python3 firmware/hack_toolkit.py                     # offline demo (starts local target)
python3 firmware/hack_toolkit.py --demo-report       # demo + reports/toolkit_report.json
python3 firmware/hack_toolkit.py --run port_scan --target 127.0.0.1 --ports 22,80,443
python3 firmware/hack_toolkit.py --dry-run           # print plan, no execution
python3 firmware/hack_toolkit.py --help
```

## Example Output

```
[Port Scan] Target: 127.0.0.1, Ports: 1
  Port 41357  open  (unknown)
  Scan complete: 1/1 ports open

[Banner Grab] Target: 127.0.0.1
  Port 41357  => HTTP/1.1 200 OK Server: BaseHTTP/0.6 Python/3.13

[Content Discovery] Base: http://127.0.0.1:41357, Words: 19
  FOUND: /admin (HTTP 401) [AUTH]
  FOUND: /login (HTTP 200)
  FOUND: /config (HTTP 200)
  FOUND: /robots.txt (HTTP 200)
  FOUND: /server-status (HTTP 200)
  FOUND: /debug (HTTP 200)

[HTTP Brute] Target: http://127.0.0.1:41357/admin
  FOUND: admin:admin

[Service Fuzz] Target: http://127.0.0.1:41357, payloads: 12
  [00] status=200 payload=\x00\x01        SURVIVED
  ...

=== Demo PASS (real modules against live localhost target) ===
```

## IMPORTANT: Read before use.

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the system owner before using any module
- Unauthorized port scanning, brute-forcing, or exploitation is illegal
- This tool should ONLY be used on systems you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and unauthorized access statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own systems and networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training
- CTF competitions and wargames

### Prohibited Use
- Attacking systems without explicit written authorization
- Brute-forcing credentials on third-party services
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept
4. Document your findings for the remediation team

## Tests

```bash
python3 -m unittest discover -s tests
```

## Live Lab Test Plan

1. `python3 firmware/hack_toolkit.py` — starts the local vuln target, then each
   module runs for real: port scan finds the ephemeral port, banner grab reads
   `HTTP/1.1 200 OK`, dir brute finds `/admin` + `/robots.txt` + `/server-status`,
   http brute cracks `admin:admin`, service fuzz sends mutated paths; prints
   `Demo PASS`, exit 0.
2. `python3 firmware/hack_toolkit.py --demo-report` — same modules, writes
   `reports/toolkit_report.json` with `http_creds: {user: admin, password: admin}`.
3. `python3 firmware/hack_toolkit.py --run http_brute base_url=http://127.0.0.1:PORT`
   — brute works on the live target; wrong creds yield 401, `admin:admin` yields 200.
4. `python3 -m unittest discover -s tests` — 29 deterministic real-network assertions.

## Metrics

- 8 composable modules, every network action is a real TCP connect / HTTP request
- Local vulnerable target: stdlib HTTP server on an ephemeral `127.0.0.1` port
- Dir brute: 6 of 19 real paths found on the live target (incl. 401-gated `/admin`)
- Basic-auth brute: `admin:admin` recovered in ≤6 real attempts (worst case)
- Service fuzz: 12 deterministic mutated request paths, all handled without crash
- Banner grab: real `HTTP/1.1 200 OK` from the live service
- `reports/toolkit_report.json` (gitignored) captures session findings
- 29 unittest assertions, all offline / localhost-only

## License

MIT
