<h1 align="center">vamp-http-audit</h1>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white" alt="Python 3.9+"/>
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey" alt="Platform"/>
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License MIT"/>
  <img src="https://img.shields.io/badge/VampSecure-Labs-magenta" alt="VampSecure Labs"/>
</p>

## Overview

`vamp-http-audit` is the HTTP layer companion to `vamp-ssl-audit`. Where the TLS auditor covers the transport layer, this tool covers HTTP security headers, CORS misconfigurations, cookie flag analysis, server information disclosure, and open redirect vulnerabilities. It uses the same SSLabs-style A+–F grading system and supports the same output formats (JSON, HTML, Markdown, CSV), making it a natural fit in any automated assessment pipeline.

## Features

- SSLabs-style letter grading A+ to F based on combined HTTP security posture
- Security header analysis: CSP (directive-level deep inspection including `unsafe-inline`, `unsafe-eval`, wildcards, `frame-ancestors`), HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COEP, COOP, CORP
- CORS misconfiguration probing: attacker-origin reflection, wildcard + credentials (CRITICAL), null-origin acceptance (iframe sandbox bypass)
- Cookie security analysis: Secure, HttpOnly, SameSite flags; `__Host-` and `__Secure-` prefix enforcement
- Server information disclosure detection: `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`, `X-Generator`, debug headers
- Open redirect testing across 16 common parameters: `url`, `redirect`, `next`, `return`, `goto`, `destination`, `redir`, `target`, `link`, `forward`, `location`, `rurl`, `returl`, `redirect_uri`, `redirect_url`, `return_url`
- GraphQL endpoint detection and introspection availability check
- Concurrent multi-URL scanning with configurable worker pool (`--workers`, default 5)
- Zero third-party dependencies — only Python stdlib (`urllib`) and `rich`
- Export to Console, JSON, HTML (dark-theme with collapsible remediations), Markdown, and CSV

## Requirements

- Python 3.9 or later
- `rich >= 13.7.0`

## Installation

```bash
git clone https://github.com/belky-me/vamp-http-audit.git
cd vamp-http-audit
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

```
python3 vamp_http_audit.py --help
```

```
usage: vamp_http_audit.py [-h] [-u URL] [--file FILE]
                           [--timeout TIMEOUT] [--workers WORKERS]
                           [--json FILE] [--html FILE]
                           [--markdown FILE] [--csv FILE]
                           [--no-verify-ssl]
                           [--client CLIENT] [--engagement ENGAGEMENT]
                           [--auditor AUDITOR] [--report-scope SCOPE]
                           [--report-html FILE] [--report-pdf FILE]

vamp-http-audit — HTTP Security Headers & CORS Auditor (VampSecure Labs)
```

## Examples

```bash
# Audit a single URL
python3 vamp_http_audit.py -u https://example.com

# Audit multiple URLs in one command
python3 vamp_http_audit.py -u https://example.com -u https://api.example.com

# Audit a list of URLs from file with 10 parallel workers
python3 vamp_http_audit.py --file urls.txt --workers 10

# Export results to all formats
python3 vamp_http_audit.py -u https://example.com \
    --json results.json --html report.html --markdown report.md --csv report.csv

# Skip TLS verification for self-signed certificates
python3 vamp_http_audit.py -u https://internal.staging.local --no-verify-ssl

# Generate client-ready engagement report
python3 vamp_http_audit.py --file urls.txt \
    --client "Acme Corp" --engagement "HTTP Headers Review Q3 2026" \
    --auditor "J. Smith" --report-html client_report.html
```

## CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `-u / --url URL` | — | Target URL (repeatable for multiple targets) |
| `--file FILE` | — | Text file with one URL per line |
| `--timeout N` | 10 | Per-request timeout in seconds |
| `--workers N` | 5 | Concurrent worker threads |
| `--json FILE` | — | Export results to JSON |
| `--html FILE` | — | Export dark-theme HTML report |
| `--markdown FILE` | — | Export Markdown report |
| `--csv FILE` | — | Export CSV summary (+ `FILE.findings` detail file) |
| `--no-verify-ssl` | off | Disable TLS certificate verification |
| `--client TEXT` | — | Client name for VSL engagement report |
| `--engagement TEXT` | — | Engagement title for VSL engagement report |
| `--auditor TEXT` | — | Auditor name for VSL engagement report |
| `--report-scope TEXT` | — | Scope description for VSL engagement report |
| `--report-html FILE` | — | Export unified VSL client report (HTML) |
| `--report-pdf FILE` | — | Export unified VSL client report (PDF, requires fpdf2) |

## Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| Console | (default) | Rich-colored graded output with per-finding remediation panels |
| JSON | `--json FILE` | Machine-readable full result set |
| HTML | `--html FILE` | Dark-theme standalone report with collapsible remediations |
| Markdown | `--markdown FILE` | Portable report for inclusion in audit repositories |
| CSV | `--csv FILE` | Summary row per host + `FILE.findings` with one row per finding |
| Client HTML | `--report-html FILE` | Unified VampSecure Labs engagement report |
| Client PDF | `--report-pdf FILE` | PDF version of the VSL client report |

## Grading Scale

| Grade | Criteria |
|-------|----------|
| A+ | All headers present, solid CSP, secure cookies, no CORS issues |
| A | Good configuration; missing COOP/COEP/CORP or SameSite on some cookies |
| A- | CSP with `unsafe-inline`/`eval`/wildcard; suboptimal Referrer-Policy |
| B | CSP absent · X-Content-Type-Options absent · server version exposed · insecure cookie · CORS wildcard without credentials |
| C | X-Frame-Options absent without `frame-ancestors` · HSTS absent |
| F | CORS wildcard + credentials · confirmed open redirect |

## Exit Codes

| Code | Meaning | CI/CD Behavior |
|------|---------|----------------|
| `0` | No critical or high findings | Pipeline passes |
| `1` | High-severity findings detected | Pipeline fails — review required |
| `2` | Critical-severity findings detected | Pipeline fails — immediate action required |

## Legal Notice

Use exclusively on systems you own or for which you hold explicit written authorization from the system owner. VampSecure Studios assumes no liability for unauthorized use.

## Part of VampSecure Labs Toolkit

`vamp-http-audit` is one tool in the VampSecure Labs security research toolkit. For the full toolkit including the orchestrator that runs all tools in sequence and aggregates findings into a single engagement report, see:

- Portfolio: [github.com/belky-me](https://github.com/belky-me)
- Orchestrator: [github.com/belky-me/vamp-orchestrator](https://github.com/belky-me/vamp-orchestrator)

---

© VampSecure Studios — VampSecure Labs Security Research Division
