> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# X4 — Hack Toolkit

X4 is a modular **penetration testing** and **red team** framework with a plugin
registry, an embedded vulnerable HTTP lab target, and working modules for
**port scanning**, brute force, content discovery, and service fuzzing — all
expressed as real TCP/HTTP actions against a localhost-only lab.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/5h4d0wn1k/x4-hack-toolkit)](https://github.com/5h4d0wn1k/x4-hack-toolkit)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/x4-hack-toolkit)](https://github.com/5h4d0wn1k/x4-hack-toolkit)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/x4-hack-toolkit)](https://github.com/5h4d0wn1k/x4-hack-toolkit)

## Why X4

Security frameworks are always shown in demos "after" the real work is done.
X4 flips that: every module runs **for real** against a local vulnerable target
that the toolkit itself starts on an ephemeral `127.0.0.1` port — nothing
touches the network or any real system. It is a **hacking education** and
lab-training sandbox that shows how enumeration, brute forcing, and fuzzing
actually behave, while staying entirely inside your own machine. Use it only
for **authorized security testing** and defense of systems you own.

## Features

- **Module registry** — auto-discovery via `@register`, category listing, `--run <module> key=value`
- **Local vulnerable target** — stdlib HTTP server embedding a weak `admin:admin` basic-auth endpoint
- **Port scanner** — real TCP connect() probes with range/CSV parsing
- **Banner grab** — reads service banners with an HTTP probe fallback
- **Content discovery** — real HTTP dir-brute force; reports 200/401/403/redirect hits
- **HTTP brute force** — real `Authorization: Basic` attempts until credentials are found
- **Service fuzzer** — deterministic request-line mutation against the local target
- **Payload library** — shellcode samples + XOR encoder, post-exploitation checklist
- **Reports** — text and JSON session reports under `reports/`

## Quickstart

```bash
# Offline demo — starts the local lab target and runs every module
python3 firmware/hack_toolkit.py
python3 firmware/hack_toolkit.py --demo-report   # + JSON report

# List modules / run one explicitly
python3 firmware/hack_toolkit.py --list
python3 firmware/hack_toolkit.py --run port_scan --target 127.0.0.1 --ports 22,80,443

# Plan without executing
python3 firmware/hack_toolkit.py --dry-run

# Tests
python3 -m unittest discover -s tests
```

## Project structure

- `firmware/hack_toolkit.py` — core engine, module registry, and demo harness
- `tests/` — deterministic localhost-only assertions
- `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `ETHICS.md`, `SCOPE.md`, `SECURITY.md` — project standards and legal scope

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

MIT — see [LICENSE](LICENSE).

## Legal

- [ETHICS.md](ETHICS.md) · [SCOPE.md](SCOPE.md) · [SECURITY.md](SECURITY.md)