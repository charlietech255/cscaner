# CSCAN

CSCAN is an authorized security assessment toolkit for web applications, APIs, hosts, and services.

Repository: <https://github.com/charlietech255/cscaner>

Use it only against systems you own or systems for which you have explicit permission. Scans can generate real network traffic, submit test payloads, enumerate endpoints, and perform credential checks when explicitly enabled.

## Features

- DNS, WHOIS, subdomain, reverse-DNS, and GeoIP reconnaissance
- Common and full TCP port scanning with service banners
- TLS certificate, protocol, cipher, HSTS, and Heartbleed checks
- Web security-header and sensitive-path checks
- Crawling for pages, forms, parameters, JavaScript endpoints, secrets, and PII indicators
- Reflected XSS, SQL injection, SSRF, open redirect, path traversal, command-injection, SSTI, and IDOR-hint testing
- API path discovery, OpenAPI/Swagger route extraction, and safe HTTP method discovery
- NVD CVE lookup and local version-based candidate mapping
- OSINT integrations for Shodan, Wayback, GitHub, breach checks, and email discovery
- JSON and text reports with credential/session redaction
- Optional AI-assisted evidence summaries
- Optional browser-based JavaScript and network inspection on supported desktop platforms

## Requirements

- Python 3.10 or newer is recommended.
- Linux, Windows, WSL, and Termux are supported with different dependency profiles.
- A network connection is required for hosted-target scans, NVD, OSINT providers, wordlists, and optional AI services.
- Only use hosted URLs that are authorized for testing.

## Installation

### Linux and Hosted Servers

Supported on Debian, Ubuntu, Kali, Fedora, and similar systems.

```bash
git clone https://github.com/charlietech255/cscaner.git
cd cscaner
chmod +x install.sh fetch_wordlists.sh
./install.sh
./fetch_wordlists.sh
python3 cscan.py --list-modules
```

The installer uses a virtual environment on Kali when needed. For a manual installation:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

Optional browser support on compatible desktop/server architectures:

```bash
python3 -m pip install "camoufox[geoip]"
python3 -m camoufox fetch
```

Optional system tools:

```bash
# Debian, Ubuntu, or Kali
sudo apt update
sudo apt install -y nmap
```

### Windows

Native Windows supports the core Python scanner. WSL is recommended when you need Linux tools such as nmap or shell scripts.

```powershell
git clone https://github.com/charlietech255/cscaner.git
cd cscaner
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install --upgrade pip
py -m pip install -r requirements.txt
py cscan.py --list-modules
```

Use Git Bash or WSL to run `fetch_wordlists.sh`. In WSL, follow the Linux instructions.

### Termux on Android

Install Termux from [F-Droid](https://f-droid.org/packages/com.termux/) or the official [Termux GitHub releases](https://github.com/termux/termux-app/releases). The old Play Store build is not recommended.

Termux uses a separate dependency file. Do not install the desktop `requirements.txt` on Android.

```bash
pkg update && pkg upgrade -y
pkg install python git curl openssl -y
git clone https://github.com/charlietech255/cscaner.git
cd cscaner
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements-termux.txt
chmod +x fetch_wordlists.sh
./fetch_wordlists.sh
python3 cscan.py --list-modules
```

Or use the automatic installer, which detects Termux and selects the correct profile:

```bash
chmod +x install.sh
./install.sh
```

Termux supports the core DNS, web, crawler, API, TLS, OSINT, stealth, and reporting workflows. Camoufox/Playwright browser features and Paramiko SSH auditing are excluded because their Android dependencies are not reliable. Optional nmap support can be installed with `pkg install nmap`; it is not required for the core scanner.

## Usage

### Interactive mode

```bash
python3 cscan.py
```

Set a target in the menu, choose a module, and export results when the scan is complete.

### Direct mode

```bash
python3 cscan.py --list-modules
python3 cscan.py --target https://example.com --module dns
python3 cscan.py --target https://example.com --module web
python3 cscan.py --target https://example.com --module crawl
python3 cscan.py --target https://example.com --module ssl
python3 cscan.py --target https://example.com --module ports
python3 cscan.py --target https://example.com --module auto
```

Useful options:

```text
--target URL              Hosted URL, hostname, or IP address
--module NAME             dns, web, crawl, ssl, ports, or auto
--stealth                 Enable configured session/proxy/timing behavior
--insecure                Allow invalid TLS certificates; use only when authorized
--credential-testing      Explicitly enable SSH, HTTP Basic, MySQL, and PostgreSQL guessing
--list-modules            Print non-interactive modules
```

Credential testing is disabled by default. It should only be enabled with written authorization and a controlled credential list.

## Module Reference

The following modules are available in `modules/`. Some are called by the interactive menu or `auto` workflow rather than exposed as direct argparse module names.

### Core discovery and network

| Module | Purpose |
| --- | --- |
| `recon.py` | DNS records, WHOIS, subdomains, certificate-transparency names, GeoIP, and reverse DNS. |
| `scanner.py` | Common/full TCP port scans, service banners, and basic TLS certificate inspection. |
| `udp_scanner.py` | UDP service probes for selected DNS, SNMP, TFTP, and NTP indicators. Results are best-effort and require confirmation. |
| `utils.py` | Shared target hostname and IP resolution, including IPv4/IPv6 handling. |

### Web and API assessment

| Module | Purpose |
| --- | --- |
| `web.py` | Sensitive-path checks, response-content inspection, CMS detection, security headers, directory discovery, and local CVE candidate mapping. |
| `crawler.py` | Same-origin crawling for pages, forms, query parameters, JS endpoints, technologies, comments, emails, and masked secret indicators. |
| `active_vuln.py` | Authorized active checks for reflected XSS, SQL injection, SSRF, open redirects, path traversal, command injection, SSTI, and IDOR hints. Findings include evidence and technique metadata. |
| `path_api_enum.py` | API/path wordlist enumeration, soft-404 filtering, OpenAPI/Swagger route extraction, and safe `OPTIONS`/`GET`/`HEAD` method discovery. Unsafe methods require explicit lower-level opt-in. |
| `browser_engine.py` | Optional Camoufox browser rendering, network metadata capture, login testing, screenshots, fingerprint inspection, cookie metadata, and JavaScript secret detection. Sensitive values are redacted. |
| `cloudflare_bypass.py` | Optional authorized browser/session workflow for Cloudflare challenge handling. Availability depends on the browser engine and target behavior. |

### TLS and service security

| Module | Purpose |
| --- | --- |
| `ssl_audit.py` | Exact TLS protocol checks, weak cipher probing, certificate/HSTS review, POODLE indication, and conservative Heartbleed results. |
| `exploit.py` | FTP anonymous-login checks plus opt-in SSH and HTTP Basic Auth credential testing. |
| `service_brute.py` | Unauthenticated Redis, MongoDB, Elasticsearch, and RDP checks plus opt-in MySQL/PostgreSQL credential testing. |
| `stealth.py` | Shared requests session, proxy validation, timing/jitter, user-agent rotation, WAF signal tracking, and optional nmap integration. It does not provide anonymity. |

### Intelligence, analysis, and support

| Module | Purpose |
| --- | --- |
| `nvd_cve.py` | NVD API queries and live CVE mapping. Version matches are candidates and require vendor/backport verification. |
| `osint.py` | Passive Shodan, Wayback, GitHub, breach, DNS, and email intelligence. Third-party disclosure should be considered before use. |
| `ai_analyst.py` | Evidence-grounded AI summaries, host analysis, CVE assistance, and formal report generation. Secrets are not intentionally included in prompts. |
| `api_emulator.py` | Local API emulator and contract scanner for authorized API development/testing. Hosted API contract checks are also supported. |
| `crypto_utils.py` | Local hashing, signing, encoding, and utility routines. Its custom token helpers are not a replacement for a production authentication library. |
| `ui.py` | Terminal colors, prompts, progress bars, tables, and display helpers. |
| `lang.py` | English/Kiswahili UI strings and local language preference storage. |
| `__init__.py` | Python package marker for the module collection. |

## Injection Testing and Evidence

Active checks send test inputs to discovered URL parameters, form fields, or authorized API endpoints. The scanner records the issue category, target URL, parameter, HTTP method, evidence, and technique/payload used to produce the signal.

Reports should distinguish:

- **Confirmed**: direct evidence such as a validated response difference, reflected executable marker, database error, or controlled timing difference.
- **Possible/candidate**: heuristic or version-based signal requiring manual verification.
- **Inconclusive**: the probe could not complete or the response was ambiguous.

Do not treat an open port, technology banner, CVE version match, or generic error page as proof of exploitability.

## Reports and Data Handling

Interactive exports are written to `reports/` as JSON and text files. Reports redact passwords, cookies, authorization values, tokens, private keys, and similar session secrets. Browser and crawler secret findings retain masked context, source, length, and a short hash for correlation.

Keep reports private. They may still contain target URLs, hostnames, IP addresses, email addresses, headers, findings, and other sensitive assessment metadata.

## Wordlists

The repository includes small starter wordlists. `fetch_wordlists.sh` downloads larger lists from SecLists and stores originals under `wordlists/.originals/`.

```bash
chmod +x fetch_wordlists.sh
./fetch_wordlists.sh
```

The download requires `curl`, `cat`, `grep`, `sort`, `head`, and `mktemp`. On Windows, use WSL or Git Bash.

## Troubleshooting

### Missing Python package

Use the correct profile for your platform:

```bash
python3 -m pip install -r requirements.txt
# Termux only:
python3 -m pip install -r requirements-termux.txt
```

### Browser engine unavailable

Camoufox is optional and is not part of the Termux profile. On a supported desktop/server system:

```bash
python3 -m pip install "camoufox[geoip]"
python3 -m camoufox fetch
```

### SSH audit unavailable

Paramiko is optional and excluded on Termux. Use a supported Linux/Windows/WSL environment for SSH auditing, and enable credential testing explicitly.

### Invalid certificate

Prefer fixing the target certificate. For an authorized test where certificate errors are expected, use `--insecure`; this weakens transport verification and should be clearly documented in the assessment.

## Updating

```bash
cd cscaner
git pull origin main
```

Review dependency changes after updating:

```bash
python3 -m pip install -r requirements.txt
# Termux:
python3 -m pip install -r requirements-termux.txt
```

## Legal and Safety Notice

CSCAN is intended for authorized security assessment, defensive research, and controlled lab environments. You are responsible for authorization, scope, rate limits, data handling, and compliance with applicable laws and program rules. Never scan third-party systems without explicit permission.
