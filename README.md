# X4 — Unified Hacker Toolkit — hack_toolkit

Extensible Metasploit-shaped security framework with plugin registry, session management, and bundled modules.

## Overview

This project implements a modular security toolkit framework:
- Plugin/module system with decorator-based registration and auto-discovery
- Shared session and report model for cross-module data sharing
- CLI interface with `--list` and `--run <module> [args]` commands
- Bundled modules covering recon, exploitation, post-exploitation, and reporting
- Each module follows a consistent base class with `run(session, **kwargs)` interface

## Features

- **Module registry**: Auto-discovery via `@register` decorators, listing, filtering by category
- **Session model**: Shared state object passed between modules for data accumulation
- **Report generator**: Markdown/text report from session data
- **Recon module**: TCP port scanner with service fingerprinting
- **Content discovery**: Wordlist-based directory/endpoint brute-force
- **Brute engine**: SSH/HTTP credential brute-force with wordlist support
- **Payload library**: Common payload templates and encoding helpers
- **Post-exploitation**: Checklist runner for post-access assessment
- **Report module**: Aggregate session data into structured text report

## Installation

```bash
# No external dependencies required — Python 3.8+ standard library only
python3 firmware/hack_toolkit.py --list
python3 firmware/hack_toolkit.py --run <module> [args]
```

## Usage

```bash
python3 firmware/hack_toolkit.py --list
python3 firmware/hack_toolkit.py --run port_scan --target 127.0.0.1 --ports 80,443
python3 firmware/hack_toolkit.py --run report
python3 firmware/hack_toolkit.py --demo
```

## Example Output

```
=== X4 - Unified Hacker Toolkit ===

[Bundled Modules]
  Category      Name                Description
  ---------------------------------------------------------------
  recon         port_scan           TCP port scanner with banner grab
  recon         content_discover    Directory/endpoint brute-force
  brute         ssh_brute           SSH credential brute-force
  brute         http_brute          HTTP basic-auth brute-force
  payload       payload_gen         Payload template generator
  post          post_checklist      Post-exploitation checklist runner
  report        report_gen          Markdown/text report generator

[Demo: Running port_scan against localhost]
  Port 22:   open  (SSH-2.0-OpenSSH_8.9)
  Port 80:   open  (HTTP/1.1)
  Port 443:  closed
  Scan complete: 2/100 ports open

[Demo: Session Report]
  Target: 127.0.0.1
  Open ports: 22, 80
  Findings: 2
  Report saved to session_report.txt
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

## License

MIT
