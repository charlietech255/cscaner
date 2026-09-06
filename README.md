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

### Recommended desktop/server setup (best for full features)

For the full scanner, including Cloudflare browser bypass, browser-based JS inspection, and advanced WAF behavior, use a desktop Linux environment or WSL. This is the recommended setup for best results.

```bash
git clone https://github.com/charlietech255/cscaner.git
cd cscaner
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip setuptools wheel
python3 -m pip install -r requirements.txt
python3 -m camoufox fetch
python3 cscan.py --list-modules
```

If you prefer the installer script instead of manual setup:

```bash
git clone https://github.com/charlietech255/cscaner.git
cd cscaner
chmod +x install.sh fetch_wordlists.sh
./install.sh
./fetch_wordlists.sh
python3 cscan.py --list-modules
```

### Linux and Hosted Servers

Supported on Debian, Ubuntu, Kali, Fedora, and similar systems.

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip nmap git curl

git clone https://github.com/charlietech255/cscaner.git
cd cscaner
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
python3 -m camoufox fetch
./fetch_wordlists.sh
python3 cscan.py --list-modules
```

### Windows

Native Windows supports the core Python scanner. WSL is recommended when you need the full browser and nmap features.

```powershell
git clone https://github.com/charlietech255/cscaner.git
cd cscaner
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install --upgrade pip
py -m pip install -r requirements.txt
py -m camoufox fetch
py cscan.py --list-modules
```

Use Git Bash or WSL to run `fetch_wordlists.sh`.

### Termux on Android

Use this only for the lightweight mobile profile. Do not install the desktop requirements on Android.

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

Or use the automatic installer:

```bash
chmod +x install.sh
./install.sh
```

Termux supports the core DNS, web, crawler, API, TLS, OSINT, stealth, and reporting workflows. Camoufox/Playwright browser features and Paramiko SSH auditing are excluded because their Android dependencies are not reliable.

## Proper usage workflow

Follow these steps in order for the best results.

### 1) Prepare the environment

```bash
cd cscaner
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip setuptools wheel
python3 -m pip install -r requirements.txt
python3 -m camoufox fetch
./fetch_wordlists.sh
```

This ensures the scanner, browser engine, and wordlists are ready before you scan anything.

### 2) Start with a quick reconnaissance pass

Use the simplest checks first.

```bash
python3 cscan.py --target https://example.com --module dns
python3 cscan.py --target https://example.com --module web
python3 cscan.py --target https://example.com --module ports
```

This gives you host, network, and basic web exposure information before deeper checks.

### 3) Run the auto mode on the target

This is the best general-purpose starting point for a real target.

```bash
python3 cscan.py --target https://example.com --module auto
```

The `auto` workflow will:
- detect WAF signals
- enable stealth mode
- escalate timing and jitter when needed
- attempt Cloudflare bypass if Camoufox is available
- run the main web and reconnaissance checks in a safer sequence

### 4) Use interactive mode for guided scanning

If you want step-by-step manual control:

```bash
python3 cscan.py
```

Then:
- select the target
- choose the module
- enable stealth if needed
- run the scan
- export the report from the menu

### 5) Move to deeper checks only after recon confirms a target is valid

Once the target looks reachable and relevant, proceed to deeper modules:

```bash
python3 cscan.py --target https://example.com --module crawl
python3 cscan.py --target https://example.com --module ssl
python3 cscan.py --target https://example.com --module api
```

Use the more aggressive modules only when you have explicit authorization and a clear reason to test them.

### 6) If Cloudflare blocks the target, use the browser bypass workflow

This is the expected sequence for Cloudflare-protected sites:

```bash
python3 cscan.py
```

Then in the menu:
- choose the target
- open the Cloudflare bypass option
- allow the browser to solve the challenge
- inject the solved `cf_clearance` cookie into the session
- continue with the normal scan flow

**How it works (and its limitations):**
The browser path uses **Camoufox**, a specialized stealth browser engine, to evade anti-bot detection. It achieves this by spoofing browser fingerprints (such as WebGL, fonts, and canvas) and simulating human-like behavior to solve Cloudflare JavaScript challenges and retrieve a valid `cf_clearance` cookie.

**Note on Accuracy:** The Camoufox bypass is **not 100% accurate**. Cloudflare frequently updates its security heuristics and Turnstile challenges. Success varies significantly depending on your IP reputation and the target's strictness level. You might still get blocked on heavily protected sites. This feature is only effective when Camoufox is installed and the challenge is actually solvable.

### 7) Export and review results

Always save and review reports before moving to further testing:

```bash
ls reports/
```

Check the generated JSON and text reports for:
- confirmed findings
- risky paths and headers
- WAF bypass status
- session/Cookie handling
- scan coverage and next steps

## Usage

### Interactive mode

```bash
python3 cscan.py
```

Set a target in the menu, choose a module, and export results when the scan is complete. The interactive CLI menu offers the following categories and options:

#### 🔍 RECONNAISSANCE & NETWORK
- `[01]` **DNS Lookup**: Queries DNS records (A, MX, TXT, etc.).
- `[02]` **WHOIS**: Retrieves domain registration details.
- `[03]` **Subdomains**: Attempts to discover subdomains.
- `[04]` **GeoIP Tracker**: Resolves the target's IP to a physical location.
- `[05]` **Reverse DNS**: Performs a PTR record lookup on the IP.
- `[06]` **Port Scan**: Quick scan of common TCP ports.
- `[07]` **Full Port Scan**: Extensive scan across a wider range of ports.
- `[08]` **Banner Grabber**: Captures service banners from open ports.
- `[09]` **SSL/TLS Inspect**: Audits the SSL certificate and cipher configs.

#### 🌐 WEB & EXPLOITATION
- `[10]` **Web Vuln Scan**: Basic vulnerability checks against the web app.
- `[11]` **HTTP Headers**: Analyzes headers for security misconfigurations.
- `[12]` **Dir Brute Force**: Finds hidden directories and files.
- `[13]` **CMS Detect**: Identifies the Content Management System.
- `[14]` **SSH Audit**: Audits SSH for weaknesses or default credentials.
- `[15]` **FTP Anonymous**: Checks for anonymous FTP login.
- `[16]` **HTTP Auth**: Tests for HTTP Authentication weaknesses.

#### 🤖 AUTOMATION & AI
- `[17]` **Full Auto-Scan**: Comprehensive automated recon and scanning.
- `[18]` **Export Results**: Saves findings to a JSON/text report.
- `[19]` **Analyse with AI**: Deep analysis of scan results using AI.
- `[20]` **Quick AI Overview**: Fast, high-level AI summary.
- `[21]` **CVE Lookup**: Searches NVD for discovered software versions.
- `[22]` **Ask AI Assistant**: Interactive prompt to ask the AI questions.
- `[23]` **Security Report**: Generates a formalized security report.

#### 🥷 STEALTH & ADVANCED OPSEC
- `[24]` **Stealth Config**: Configure proxies, timing, and user-agents.
- `[25]` **Toggle Stealth**: Quickly toggles stealth mode on/off.
- `[26]` **CF WAF Bypass (solve)**: Solves Cloudflare JS challenges.
- `[27]` **CF Bypass + Inject Session**: Solves CF and injects the clearance cookie into the session.

#### 🦊 ADVANCED BROWSER ENGINE (Camoufox)
- `[28]` **JS-Rendered Page**: Loads page in browser for JS content.
- `[29]` **Network Traffic**: Captures background API/network requests.
- `[30]` **Form Login Tester**: Tests login forms interactively.
- `[31]` **Screenshot Recon**: Takes visual screenshots of the target.
- `[32]` **Browser Fingerprint**: Analyzes how the target tracks fingerprints.
- `[33]` **Cookie Harvester**: Collects and analyzes cookies.
- `[34]` **JS Secret Scanner**: Scans client-side JS for hardcoded secrets.

#### 💣 ACTIVE EXPLOITATION
- `[35]` **Active Vuln Scan (XSS/SQLi/SSRF)**: Injects payloads to confirm vulnerabilities.
- `[36]` **Live CVE Map (NVD API)**: Queries live NVD API for target's stack.
- `[37]` **NVD Manual CVE Lookup**: Manual search in the CVE database.
- `[38]` **UDP Scanner (SNMP/TFTP/NTP)**: Scans for misconfigured UDP services.
- `[39]` **Deep SSL/TLS Audit**: Advanced cryptographic checks (e.g., Heartbleed).
- `[40]` **OSINT Passive Recon**: Passive intelligence gathering (Shodan, Wayback).
- `[41]` **Service Brute**: Credential brute-forcing (MySQL, Redis, RDP).

#### 🕷️ CRAWLER & AUTH
- `[42]` **Web Crawler (Discovery)**: Spiders the website to map pages and assets.
- `[43]` **Auth / Session Config**: Sets up headers/cookies for authenticated scanning.
- `[44]` **Path/API Enumerator**: Wordlist-based API and route enumeration.

- `[00]` **Exit**: Closes the application.

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
