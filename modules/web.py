#!/usr/bin/env python3
"""
CSCAN — Web Analysis Modules
"""

import re
import os
import random
import json
import time
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from modules.stealth import StealthSession, mutate_path

WORDLISTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'wordlists')

def _load_wordlist(filename: str) -> list:
    path = os.path.join(WORDLISTS_DIR, filename)
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
    except Exception:
        return []

import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from modules.ui import (
    section, ok, warn, alert, info, critical, bold, divider,
    print_table, progress_bar, G, R, Y, C, M, W, B, BR, DM, RS
)

_stealth_session = None
_insecure_ssl = False

def set_stealth_session(session: StealthSession):
    global _stealth_session
    _stealth_session = session

def set_insecure_ssl(flag: bool):
    global _insecure_ssl
    _insecure_ssl = flag


# ── Sensitive paths ────────────────────────────────────────────────────────────
SENSITIVE_PATHS = _load_wordlist('sensitive_paths.txt')

# ── Security headers ──────────────────────────────────────────────────────────
SECURITY_HEADERS_REQUIRED = {
    'Strict-Transport-Security': 'Enforce HTTPS connections',
    'Content-Security-Policy':   'Prevent XSS & data injection',
    'X-Frame-Options':           'Prevent clickjacking',
    'X-Content-Type-Options':    'Prevent MIME sniffing',
    'Referrer-Policy':           'Control referrer info',
    'Permissions-Policy':        'Control browser features',
}

INFO_LEAK_HEADERS = [
    'Server', 'X-Powered-By', 'X-AspNet-Version',
    'X-Generator', 'X-Drupal-Cache', 'X-Varnish',
]

# ── CMS / Tech signatures ─────────────────────────────────────────────────────
CMS_SIGS = {
    'WordPress':   ['/wp-login.php', '/wp-json/'],
    'Joomla':      ['/administrator/', '/components/'],
    'Drupal':      ['/sites/default/', '/modules/system/'],
    'Magento':     ['/skin/frontend/', '/js/mage/'],
    'Shopify':     ['cdn.shopify.com'],
    'Laravel':     ['laravel_session', 'XSRF-TOKEN'],
    'Django':      ['csrfmiddlewaretoken', 'django'],
    'Ruby on Rails': ['_session_id', 'X-Runtime'],
    'ASP.NET':     ['ASP.NET_SessionId', '__VIEWSTATE'],
    'Next.js':     ['__NEXT_DATA__', 'x-nextjs-cache'],
    'Nginx':       ['nginx'],
    'Apache':      ['Apache', 'mod_'],
    'Cloudflare':  ['cf-ray', '__cfduid'],
}

# ── Directory brute force wordlist ─────────────────────────────────────────────
DIR_WORDLIST = _load_wordlist('dir_bruteforce.txt')

TIMEOUT = 5


def _build_url(target: str, use_ssl: bool = False) -> str:
    if target.startswith(('http://', 'https://')):
        return target.rstrip('/')
    proto = 'https' if use_ssl else 'http'
    return f"{proto}://{target.rstrip('/')}"


def _get(url: str, path: str = '', timeout: int = TIMEOUT, allow_redirects: bool = False) -> requests.Response | None:
    full_url = url.rstrip('/') + path
    try:
        if _stealth_session:
            return _stealth_session.get(full_url, timeout=timeout, allow_redirects=allow_redirects)
        return requests.get(
            full_url,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=not _insecure_ssl,
            headers={'User-Agent': 'Mozilla/5.0 (compatible; CSCAN/2.1)'}
        )
    except Exception:
        return None


def _expand_mutations(words: list) -> list:
    expanded = []
    for w in words:
        expanded.append(w)
        muts = [m for m in mutate_path(w) if m != w]
        if muts:
            expanded.append(random.choice(muts))
    return expanded


# ── FIX #3: Content-severity patterns for 200-response grading ───────────────
# A 200 on /admin is very different from a 200 exposing a raw .env file.
# These patterns check the BODY to assign a severity tier.
_CRITICAL_CONTENT_PATTERNS = [
    # Environment / secret files
    (r'(?i)(DB_PASSWORD|DB_PASS|DATABASE_PASSWORD|SECRET_KEY|APP_KEY|AWS_SECRET|PRIVATE_KEY|API_KEY|ACCESS_TOKEN|AUTH_TOKEN)\s*[=:]', 'Secret key/credential in response'),
    (r'(?i)-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----', 'Private key material exposed'),
    (r'(?i)(password|passwd)\s*=\s*[\'"][^\'"]{3,}[\'"]', 'Hardcoded password in response'),
    # Source / config dumps
    (r'(?i)<\?php', 'PHP source code returned (not executed)'),
    (r'(?i)\[database\]|\[mysql\]|\[postgresql\]', 'Database config section exposed'),
    # Stack traces / debug info
    (r'(?i)(stack trace|Traceback \(most recent call|at .+\.php line \d|Debug mode is ON|Laravel debug)', 'Framework stack trace / debug mode'),
    (r'(?i)(SQLException|ORA-\d{5}|mysql_fetch|pg_query|SQLSTATE)', 'Database error / SQL exception leaked'),
    # Git internals
    (r'(?i)ref: refs/heads/', '.git/HEAD or git ref exposed'),
    (r'(?i)\[core\]\s*repositoryformatversion', '.git/config exposed'),
    # Directory listing
    (r'(?i)(index of /|directory listing for|alt="\[dir\]")', 'Directory listing enabled'),
]

_HIGH_CONTENT_PATTERNS = [
    (r'(?i)(admin|administrator|root|superuser)\s*:\s*\w+', 'Admin credential pattern in response'),
    (r'(?i)(mongodb|redis|memcache)://[\w:@./]+', 'Database connection string exposed'),
    (r'(?i)phpinfo\(\)', 'phpinfo() output returned'),
    (r'(?i)uid=\d+\(\w+\)', 'Unix /etc/passwd or command output in response'),
    (r'(?i)eval\(base64_decode', 'Obfuscated/backdoor PHP pattern'),
]

_INFO_CONTENT_PATTERNS = [
    (r'(?i)(version|release|build)\s*[=:]?\s*v?\d+\.\d+', 'Version information in response'),
    (r'(?i)(todo|fixme|hack|xxx|debug|test this)', 'Dev comment / TODO in response'),
]


def _grade_200_response(path: str, body: str, size: int) -> tuple:
    """
    Inspect the body of a 200 response and return
    (severity, label, matched_reason) where severity is
    'critical', 'high', 'info', or None (skip — likely a real page).
    """
    # Empty or near-empty body = likely a redirect trap or stub
    if size < 10:
        return (None, None, None)

    body_sample = body[:8000]  # only scan first 8 KB to stay fast

    for pattern, reason in _CRITICAL_CONTENT_PATTERNS:
        if re.search(pattern, body_sample):
            return ('critical', reason, pattern)

    for pattern, reason in _HIGH_CONTENT_PATTERNS:
        if re.search(pattern, body_sample):
            return ('high', reason, pattern)

    # Paths that are inherently sensitive even with generic 200 bodies
    ALWAYS_CRITICAL_PATHS = {
        '/.git/config', '/.git/HEAD', '/.env', '/.env.local', '/.env.production',
        '/wp-config.php', '/config.php', '/configuration.php', '/settings.php',
        '/web.config', '/phpinfo.php', '/info.php', '/server-status', '/server-info',
        '/backup.sql', '/database.sql', '/db_backup.sql', '/secrets.txt',
        '/credentials.txt',
    }
    if path in ALWAYS_CRITICAL_PATHS:
        return ('critical', 'Inherently sensitive path returned 200', '')

    for pattern, reason in _INFO_CONTENT_PATTERNS:
        if re.search(pattern, body_sample):
            return ('info', reason, pattern)

    return (None, None, None)  # looks like a normal page — skip


def _silent_cms_detect(target: str, use_ssl: bool = False) -> list:
    """Helper to passively identify CMS/tech before running intrusive scans."""
    base = _build_url(target, use_ssl)
    detected = []
    try:
        r = _get(base, timeout=8)
        if not r: return []
        body = r.text.lower()
        headers = {k.lower(): v.lower() for k, v in r.headers.items()}
        for tech, sigs in CMS_SIGS.items():
            for sig in sigs:
                if sig.lower() in body or sig.lower() in str(headers):
                    detected.append(tech)
                    break
        return detected
    except Exception:
        return []

# ── Web Vulnerability Scanner ─────────────────────────────────────────────────
def web_vuln_scan(target: str, use_ssl: bool = False, mutate: bool = False, workers: int = 20) -> dict:
    section("WEB VULNERABILITY SCANNER")
    base = _build_url(target, use_ssl)
    info(f"Target        : {BR}{W}{base}{RS}")
    
    # FIX #2: CMS Gate — identify tech to prevent spamming WP paths on non-WP sites
    detected_tech = _silent_cms_detect(target, use_ssl)
    if detected_tech:
        info(f"Tech Detected : {', '.join(detected_tech)}")
    else:
        info(f"Tech Detected : {DM}None (using standard paths only){RS}")

    filtered_paths = []
    for p in SENSITIVE_PATHS:
        pl = p.lower()
        if ('/wp-' in pl or 'wordpress' in pl) and 'WordPress' not in detected_tech:
            continue
        if 'joomla' in pl and 'Joomla' not in detected_tech:
            continue
        filtered_paths.append(p)

    paths_to_check = filtered_paths
    if mutate:
        info("Path mutation ENABLED — each path gets 1 alternate variant.")
        paths_to_check = _expand_mutations(filtered_paths)
    
    info(f"Probing       : {len(paths_to_check)} sensitive paths")
    info(f"Content-aware : ON — responses graded by body analysis, not just status code\n")

    # FIX #3: findings now tracks severity, not just category
    findings = {'critical': [], 'high': [], 'forbidden': [], 'auth_required': [], 'info': []}

    def check(path):
        r = _get(base, path)
        if r is None:
            return None
        if r.status_code == 200:
            severity, reason, _ = _grade_200_response(path, r.text, len(r.content))
            if severity:
                return (severity, path, len(r.content), reason)
            return None  # 200 but looks like a normal page — ignore
        elif r.status_code == 403:
            # Check if this is a CDN/WAF blocking the request entirely
            server_hdr = r.headers.get('Server', '').lower()
            if any(cdn in server_hdr for cdn in ['cloudflare', 'akamai', 'sucuri', 'fastly']):
                return ('info', path, 0, 'WAF Block (CDN Edge)')
            return ('forbidden', path, 0, 'Access denied (403 Forbidden)')
        elif r.status_code == 401:
            return ('auth_required', path, 0, 'HTTP authentication required')
        return None

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(check, p): p for p in paths_to_check}
        done = 0
        for fut in as_completed(futures):
            done += 1
            progress_bar(done, len(paths_to_check), 'probing paths')
            res = fut.result()
            if res:
                severity, path, size, reason = res
                findings[severity].append((path, size, reason))

    print('\n')
    for path, size, reason in findings['critical']:
        critical(f"CRITICAL: {base}{path}  [{size}B]  — {reason}")
    for path, size, reason in findings['high']:
        alert(f"HIGH:     {base}{path}  [{size}B]  — {reason}")
    for path, _, reason in findings['forbidden']:
        warn(f"Forbidden : {base}{path}  — {reason}")
    for path, _, reason in findings['auth_required']:
        info(f"Auth Req  : {base}{path}  — {reason}")
    for path, _, reason in findings['info']:
        info(f"Info      : {base}{path}  — {reason}")

    divider()
    n_crit = len(findings['critical'])
    n_high = len(findings['high'])
    total  = sum(len(v) for v in findings.values())
    if n_crit:
        alert(f"{n_crit} CRITICAL exposure(s) detected — immediate action needed!")
        info("Fix: Remove sensitive files or restrict access via .htaccess / nginx config")
    elif n_high:
        warn(f"{n_high} HIGH-severity path(s) found — review and remediate.")
    elif total == 0:
        ok("No sensitive paths exposed — good hygiene!")
    else:
        ok(f"No critical exposures. {total} non-200 or info responses noted.")

    if findings['forbidden'] or findings['auth_required']:
        print()
        info(f"{BR}{M}Risk Note:{RS} Forbidden (403) and Auth (401) paths suggest hidden")
        info("           administration panels or sensitive endpoints.")

    # Backward-compat: expose list for auto_scan summary
    findings['exposed'] = findings['critical'] + findings['high']
    return findings


# ── HTTP Header Auditor ────────────────────────────────────────────────────────
def http_header_audit(target: str, use_ssl: bool = False) -> dict:
    section("HTTP SECURITY HEADER AUDIT")
    base = _build_url(target, use_ssl)
    info(f"Requesting    : {BR}{W}{base}{RS}\n")

    r = _get(base)
    if r is None:
        alert("Could not connect to target.")
        return {}

    headers = dict(r.headers)

    # Check required security headers
    print(f"  {BR}{M}  Security Headers:{RS}")
    missing = []
    for hdr, purpose in SECURITY_HEADERS_REQUIRED.items():
        if hdr in headers:
            ok(f"{hdr:<35} {DM}— {purpose}{RS}")
        else:
            alert(f"{hdr:<35} {R}MISSING{RS}  {DM}— {purpose}{RS}")
            missing.append(hdr)

    print(f"\n  {BR}{M}  Information Disclosure Headers:{RS}")
    leaks = []
    for hdr in INFO_LEAK_HEADERS:
        if hdr in headers:
            val = headers[hdr]
            # Ignore expected CDN headers so we don't falsely flag them as "leaks"
            if hdr.lower() == 'server' and any(cdn in val.lower() for cdn in ['cloudflare', 'akamai', 'cloudfront', 'fastly', 'sucuri']):
                ok(f"{hdr:<20} = {Y}{val}{RS}  {DM}(Expected CDN){RS}")
            else:
                warn(f"{hdr:<20} = {Y}{val}{RS}")
                leaks.append((hdr, val))
        else:
            ok(f"{hdr:<20} {DM}not present (good){RS}")

    print(f"\n  {BR}{M}  Redirect / Cookie Flags:{RS}")
    if r.status_code in (301, 302):
        loc = headers.get('Location', '')
        info(f"Redirects to  : {loc}")
        if loc.startswith('https'):
            ok("Redirecting to HTTPS — good.")
        else:
            warn("Redirect does not go to HTTPS!")

    for cookie_name, cookie_val in r.cookies.items():
        flags = str(cookie_val)
        has_secure   = 'Secure' in flags
        has_httponly = 'HttpOnly' in flags
        col = G if (has_secure and has_httponly) else Y
        print(f"  {col}Cookie: {cookie_name} | Secure={has_secure} | HttpOnly={has_httponly}{RS}")

    divider()
    score = ((len(SECURITY_HEADERS_REQUIRED) - len(missing)) / len(SECURITY_HEADERS_REQUIRED)) * 100
    col   = G if score >= 80 else (Y if score >= 50 else R)
    print(f"\n  {BR}{W}Security Score:{RS} {col}{BR}{score:.0f}%{RS}  ({len(SECURITY_HEADERS_REQUIRED) - len(missing)}/{len(SECURITY_HEADERS_REQUIRED)} headers present)\n")

    return {'missing': missing, 'leaks': leaks, 'score': score}


# ── Directory Brute Forcer ────────────────────────────────────────────────────
def dir_bruteforce(target: str, use_ssl: bool = False, wordlist: list = None, mutate: bool = False, workers: int = 20) -> list:
    section("DIRECTORY & FILE BRUTE FORCER")
    base = _build_url(target, use_ssl)
    wl   = wordlist or DIR_WORDLIST
    info(f"Target        : {BR}{W}{base}{RS}")
    if mutate:
        info("Path mutation ENABLED — each word gets 1 alternate variant.")
        wl = _expand_mutations(wl)
    info(f"Wordlist      : {len(wl)} entries\n")

    found = []
    lock  = __import__('threading').Lock()

    def probe(word):
        path = f"/{word}"
        r = _get(base, path, timeout=4)
        if r is not None and r.status_code in (200, 301, 302, 403):
            with lock:
                found.append((path, r.status_code))
                col = G if r.status_code == 200 else (Y if r.status_code == 403 else C)
                print(f"\n  {col}[{r.status_code}]{RS}  {W}{base}{path}{RS}")

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(probe, w) for w in wl]
        for i, _ in enumerate(as_completed(futures), 1):
            progress_bar(i, len(wl), 'brute forcing')

    print('\n')
    ok(f"Scan complete. {len(found)} path(s) found.")
    return found


# ── CMS / Technology Fingerprinter ────────────────────────────────────────────
def cms_detect(target: str, use_ssl: bool = False) -> list:
    section("CMS & TECHNOLOGY FINGERPRINTER")
    base = _build_url(target, use_ssl)
    info(f"Target        : {BR}{W}{base}{RS}\n")

    detected = []

    try:
        r = _get(base, timeout=8)
        if r is None:
            alert("Could not connect to target.")
            return []
        body    = r.text.lower()
        headers = {k.lower(): v.lower() for k, v in r.headers.items()}

        for tech, sigs in CMS_SIGS.items():
            for sig in sigs:
                if sig.lower() in body or sig.lower() in str(headers):
                    detected.append(tech)
                    ok(f"Detected: {BR}{G}{tech}{RS}  {DM}(signature: {sig}){RS}")
                    break

        # Extra checks via common paths
        checks = {
            'WordPress':       '/wp-json/wp/v2/posts',
            'Joomla':          '/administrator/manifests/files/joomla.xml',
            'Drupal':          '/misc/drupal.js',
            'Laravel':         '/telescope/requests',
            'Django Admin':    '/admin/login/?next=/admin/',
        }
        for tech, path in checks.items():
            if tech not in detected:
                chk = _get(base, path)
                if chk and chk.status_code in (200, 302):
                    detected.append(tech)
                    ok(f"Detected: {BR}{G}{tech}{RS}  {DM}(path probe: {path}){RS}")

        if detected:
            print()
            info(f"Technologies found: {', '.join(set(detected))}")
        else:
            warn("No known CMS/framework signatures detected.")

    except Exception as e:
        alert(f"Fingerprinting failed: {e}")

    return list(set(detected))


# ── FIX #4: CVE Database updated to 2024 ─────────────────────────────────────
CVE_DATABASE = {
    # ── Web Servers ───────────────────────────────────────────────────────────
    "Apache": {
        "versions": {
            # 2024
            "2.4.58": ["CVE-2024-38473", "CVE-2024-38474", "CVE-2024-38475"],
            "2.4.57": ["CVE-2023-45802"],
            "2.4.56": ["CVE-2023-27522", "CVE-2023-25690"],
            "2.4.55": ["CVE-2023-27522"],
            "2.4.54": ["CVE-2022-37436", "CVE-2022-36760"],
            "2.4.53": ["CVE-2022-26377", "CVE-2022-28614", "CVE-2022-28615"],
            "2.4.51": ["CVE-2021-44224", "CVE-2021-44790"],
            # 2021
            "2.4.50": ["CVE-2021-42013", "CVE-2021-41773"],
            "2.4.49": ["CVE-2021-41773"],
            "2.4.48": ["CVE-2021-40438"],
            "2.4.46": ["CVE-2021-30641", "CVE-2021-26690"],
            "2.4.43": ["CVE-2020-11984", "CVE-2020-11993"],
        },
        "pattern": r"Apache/(\d+\.\d+\.\d+)",
    },
    "Nginx": {
        "versions": {
            # 2024
            "1.25.3": ["CVE-2024-7347"],
            "1.25.0": ["CVE-2023-44487"],  # HTTP/2 Rapid Reset
            "1.23.4": ["CVE-2022-41741", "CVE-2022-41742"],
            "1.22.0": ["CVE-2022-41741"],
            # 2021
            "1.21.0": ["CVE-2021-23017"],
            "1.19.10": ["CVE-2020-12440"],
            "1.17.7": ["CVE-2019-20372"],
            "1.16.1": ["CVE-2018-16845", "CVE-2018-16844"],
        },
        "pattern": r"nginx/(\d+\.\d+\.\d+)",
    },
    "IIS": {
        "versions": {
            "10.0": ["CVE-2022-21907", "CVE-2021-31166", "CVE-2020-0645"],
            "8.5":  ["CVE-2015-1635"],
        },
        "pattern": r"Microsoft-IIS/(\d+\.\d+)",
    },
    # ── Databases ────────────────────────────────────────────────────────────
    "MySQL": {
        "versions": {
            "8.0.35": ["CVE-2024-20961", "CVE-2024-20962"],
            "8.0.33": ["CVE-2023-21980", "CVE-2023-22005"],
            "8.0.28": ["CVE-2022-21592"],
            "8.0.25": ["CVE-2021-2144"],
            "5.7.38": ["CVE-2022-21589"],
            "5.7.34": ["CVE-2021-2156"],
            "5.6.51": ["CVE-2021-2154"],
        },
        "pattern": r"MySQL[ -](\d+\.\d+\.\d+)",
    },
    "PostgreSQL": {
        "versions": {
            "16.0": ["CVE-2023-5868", "CVE-2023-5869", "CVE-2023-5870"],
            "15.4": ["CVE-2023-39417"],
            "14.8": ["CVE-2023-2454"],
            "13.3": ["CVE-2021-32027"],
            "12.7": ["CVE-2021-32028"],
        },
        "pattern": r"PostgreSQL (\d+\.\d+(?:\.\d+)?)",
    },
    "MongoDB": {
        "versions": {
            "6.0.6": ["CVE-2023-0437"],
            "5.0.14": ["CVE-2022-24999"],
            "4.4.6":  ["CVE-2021-20330"],
            "4.2.12": ["CVE-2021-20329"],
        },
        "pattern": r"MongoDB (\d+\.\d+\.\d+)",
    },
    # ── Runtime / Languages ───────────────────────────────────────────────────
    "PHP": {
        "versions": {
            "8.3.6":  ["CVE-2024-4577"],
            "8.2.18": ["CVE-2024-4577", "CVE-2024-2756"],
            "8.1.28": ["CVE-2024-4577"],
            "8.0.28": ["CVE-2022-31628", "CVE-2022-31629"],
            "7.4.30": ["CVE-2022-31625"],
            "7.4.21": ["CVE-2021-21703"],
            "7.3.28": ["CVE-2021-21702"],
            "5.6.40": ["CVE-2019-11043"],
        },
        "pattern": r"PHP/(\d+\.\d+\.\d+)",
    },
    # ── CMS ───────────────────────────────────────────────────────────────────
    "WordPress": {
        "versions": {
            "6.4.2": ["CVE-2024-6386"],
            "6.3.2": ["CVE-2023-38000"],
            "6.2.2": ["CVE-2023-22622"],
            "6.1.1": ["CVE-2023-2745"],
            "5.9.5": ["CVE-2022-43504", "CVE-2022-43497"],
            "5.8":   ["CVE-2021-29447"],
            "5.7":   ["CVE-2021-29445"],
            "5.6":   ["CVE-2021-29442"],
        },
        "pattern": r"WordPress (\d+\.\d+(?:\.\d+)?)",
    },
    "Joomla": {
        "versions": {
            "5.0.2":  ["CVE-2024-21726"],
            "4.3.3":  ["CVE-2023-40626"],
            "4.2.6":  ["CVE-2023-23752"],
            "3.10.11": ["CVE-2022-27912"],
            "3.9.27": ["CVE-2021-23132"],
            "3.7.0":  ["CVE-2017-8917"],
        },
        "pattern": r"Joomla!? (\d+\.\d+\.\d+)",
    },
    "Drupal": {
        "versions": {
            "10.1.5": ["CVE-2023-5256"],
            "10.0.10": ["CVE-2023-31250"],
            "9.5.10": ["CVE-2023-31250"],
            "9.4.9":  ["CVE-2022-39261"],
            "9.2":    ["CVE-2021-29403"],
            "8.9":    ["CVE-2020-13671"],
            "7.69":   ["CVE-2019-6340"],
        },
        "pattern": r"Drupal (\d+\.\d+(?:\.\d+)?)",
    },
    # ── Additional common server software ────────────────────────────────────
    "OpenSSH": {
        "versions": {
            "9.7": ["CVE-2024-6387"],   # regreSSHion — remote code exec
            "9.2": ["CVE-2023-38408"],
            "8.9": ["CVE-2023-28531"],
        },
        "pattern": r"OpenSSH[_/ ](\d+\.\d+(?:p\d+)?)",
    },
    "OpenSSL": {
        "versions": {
            "3.1.4": ["CVE-2024-0727"],
            "3.0.8": ["CVE-2023-0286", "CVE-2022-4304"],
            "1.1.1s": ["CVE-2023-0286"],
            "1.1.1n": ["CVE-2022-0778"],
        },
        "pattern": r"OpenSSL/(\d+\.\d+\.\d+\w*)",
    },
}

VERSION_PATTERNS = {
    "PHP": r"PHP/(\d+\.\d+\.\d+)",
    "WordPress": r"WordPress (\d+\.\d+\.\d+)",
    "Joomla": r"Joomla! (\d+\.\d+\.\d+)",
    "Drupal": r"Drupal (\d+\.\d+)",
    "Apache": r"Apache/(\d+\.\d+\.\d+)",
    "Nginx": r"nginx/(\d+\.\d+\.\d+)"
}

SENSITIVE_KEYWORDS = [
    "password", "secret", "api_key", "database", 
    "credentials", "token", "aws_key", "ssh_key",
    "private_key", "admin_pass", "connection_string",
    "db_password", "api_secret", "private_token"
]

API_ENDPOINTS = [
    "/api/v1/", "/api/v2/", "/api/v3/", "/graphql", "/rest/", 
    "/swagger/", "/openapi/", "/oauth/", "/auth/",
    "/v1/", "/v2/", "/v3/", "/json/", "/xmlrpc/",
    "/.well-known/openid-configuration"
]


# ── Version Comparison Functions ───────────────────────────────────────────────
def compare_versions(v1: str, v2: str) -> int:
    """Compare two version strings. Returns -1 if v1<v2, 0 if equal, 1 if v1>v2"""
    def normalize(v):
        return [int(x) for x in re.sub(r'(\.0+)*$', '', v).split(".")]
    
    try:
        v1_parts = normalize(v1)
        v2_parts = normalize(v2)
        
        for i in range(max(len(v1_parts), len(v2_parts))):
            v1_part = v1_parts[i] if i < len(v1_parts) else 0
            v2_part = v2_parts[i] if i < len(v2_parts) else 0
            if v1_part < v2_part:
                return -1
            elif v1_part > v2_part:
                return 1
        return 0
    except Exception:
        return 0


# ── WAF Detection ──────────────────────────────────────────────────────────────
def detect_waf(target: str, use_ssl: bool = False) -> str | None:
    """Detect Web Application Firewall"""
    section("WAF DETECTION")
    base = _build_url(target, use_ssl)
    info(f"Checking     : {BR}{W}{base}{RS}\n")
    
    waf_signatures = {
        "Cloudflare": ["cloudflare", "cf-ray"],
        "AWS WAF": ["x-amzn-waf"],
        "Imperva": ["imperva", "incapsula"],
        "Akamai": ["akamai"],
        "Barracuda": ["barracuda"],
        "F5": ["f5", "big-ip"],
        "Sucuri": ["sucuri"],
        "ModSecurity": ["modsecurity"]
    }
    
    r = _get(base)
    if r is None:
        alert("Could not connect to target.")
        return None
    
    headers = {k.lower(): v.lower() for k, v in r.headers.items()}
    for waf, sigs in waf_signatures.items():
        for sig in sigs:
            for h_val in headers.values():
                if sig in h_val:
                    alert(f"WAF DETECTED: {BR}{M}{waf}{RS}")
                    return waf
    
    ok("No WAF detected")
    return None


# ── Version Extraction ────────────────────────────────────────────────────────
def extract_versions(target: str, use_ssl: bool = False) -> dict:
    """Extract software versions from response headers and body"""
    section("VERSION EXTRACTION")
    base = _build_url(target, use_ssl)
    info(f"Scanning     : {BR}{W}{base}{RS}\n")
    
    versions = {}
    r = _get(base, timeout=8)
    if r is None:
        alert("Could not connect to target.")
        return versions
    
    headers_str = str(r.headers).lower()
    response_text = r.text.lower()
    
    for tech, pattern in VERSION_PATTERNS.items():
        # Check in headers first
        match = re.search(pattern, headers_str, re.IGNORECASE)
        if not match:
            match = re.search(pattern, response_text, re.IGNORECASE)
        
        if match:
            versions[tech] = match.group(1)
            ok(f"Found {tech}: {BR}{G}{match.group(1)}{RS}")
    
    if not versions:
        warn("No versions detected")
    
    return versions


# ── Sensitive Information Disclosure Detection ─────────────────────────────────
def detect_info_disclosure(target: str, use_ssl: bool = False) -> list:
    """Detect sensitive information leaks in response"""
    section("SENSITIVE INFORMATION DISCLOSURE")
    base = _build_url(target, use_ssl)
    info(f"Checking     : {BR}{W}{base}{RS}\n")
    
    disclosures = []
    r = _get(base, timeout=8)
    if r is None:
        alert("Could not connect to target.")
        return disclosures
    
    text_lower = r.text.lower()
    
    for keyword in SENSITIVE_KEYWORDS:
        if keyword.lower() in text_lower:
            start_pos = text_lower.find(keyword.lower())
            context = r.text[max(0, start_pos-50):start_pos+50]
            disclosures.append({
                "keyword": keyword,
                "context": context.strip()
            })
            alert(f"FOUND: {BR}{R}{keyword}{RS}")
            info(f"Context: ...{DM}{context.strip()}{RS}...")
    
    if not disclosures:
        ok("No sensitive keywords found")
    
    return disclosures


# ── API Endpoint Scanner ───────────────────────────────────────────────────────
def scan_api_endpoints(target: str, use_ssl: bool = False, workers: int = 10) -> list:
    """Scan for common API endpoints"""
    section("API ENDPOINT SCANNER")
    base = _build_url(target, use_ssl)
    info(f"Target       : {BR}{W}{base}{RS}")
    info(f"Scanning     : {len(API_ENDPOINTS)} endpoints\n")
    
    found_endpoints = []
    lock = __import__('threading').Lock()
    
    def check_endpoint(endpoint):
        full_url = base.rstrip("/") + endpoint
        try:
            res = _get(full_url, timeout=3)
            if res is None:
                return
            if res.status_code in [200, 403, 401]:
                content_type = res.headers.get('Content-Type', '')
                if 'json' in content_type.lower() or 'api' in content_type.lower() or res.status_code == 200:
                    with lock:
                        found_endpoints.append({
                            "url": full_url,
                            "status": res.status_code,
                            "type": "API Endpoint"
                        })
                        status_col = G if res.status_code == 200 else (Y if res.status_code == 403 else R)
                        print(f"\n  {status_col}[{res.status_code}]{RS}  {full_url}")
        except Exception:
            pass

    
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(check_endpoint, ep) for ep in API_ENDPOINTS]
        for i, _ in enumerate(as_completed(futures), 1):
            progress_bar(i, len(API_ENDPOINTS), 'scanning endpoints')
    
    print('\n')
    if found_endpoints:
        ok(f"Found {len(found_endpoints)} API endpoint(s)")
    else:
        info("No API endpoints detected")
    
    return found_endpoints


# ── PHPInfo Scanner ────────────────────────────────────────────────────────────
def scan_phpinfo(target: str, use_ssl: bool = False) -> dict | None:
    """Scan and parse phpinfo() page"""
    section("PHPINFO SCANNER")
    base = _build_url(target, use_ssl)
    
    common_paths = ['/phpinfo.php', '/info.php', '/test.php', '/php.php', '/phptest.php']
    
    for path in common_paths:
        phpinfo_url = base.rstrip('/') + path
        info(f"Checking     : {phpinfo_url}")
        
        try:
            from bs4 import BeautifulSoup
            response = _get(base, path, timeout=8)
            
            if response is None or "phpinfo()" not in response.text.lower():
                continue
            
            alert(f"PHPINFO FOUND at {BR}{R}{phpinfo_url}{RS}\n")
            
            soup = BeautifulSoup(response.text, 'html.parser')
            results = {
                'php_version': 'Not Found',
                'system': 'Not Found',
                'server': 'Not Found',
                'modules': []
            }
            
            # PHP Version
            version_match = re.search(r'PHP Version[^0-9]*(\d+\.\d+\.\d+[^<]*)', response.text, re.IGNORECASE)
            if version_match:
                results['php_version'] = version_match.group(1).strip()
                ok(f"PHP Version  : {BR}{G}{results['php_version']}{RS}")
            
            # Extract modules from table rows
            for tr in soup.find_all('tr'):
                tds = tr.find_all('td')
                if len(tds) >= 2:
                    module_name = tds[0].get_text(strip=True)
                    if module_name and not any(x in module_name.lower() for x in ['php version', 'system', 'configure command']):
                        if module_name not in results['modules']:
                            results['modules'].append(module_name)
            
            if results['modules']:
                info(f"Modules ({len(results['modules'])}): {', '.join(results['modules'][:10])}...")
            
            return results
            
        except Exception as e:
            continue
    
    warn("No phpinfo page found")
    return None


# ── Enhanced CVE Detection ────────────────────────────────────────────────────
def detect_cves_enhanced(versions: dict) -> list:
    """Enhanced CVE detection with version comparison"""
    section("CVE VULNERABILITY ANALYSIS")
    vulnerabilities = []
    
    if not versions:
        warn("No technologies detected for CVE analysis")
        return vulnerabilities
    
    for tech_name, version in versions.items():
        if tech_name not in CVE_DATABASE:
            continue
        
        pattern = CVE_DATABASE[tech_name]["pattern"]
        version_match = re.search(pattern, version, re.IGNORECASE)
        
        if not version_match:
            continue
        
        current_version = version_match.group(1)
        info(f"Analyzing {tech_name}: {BR}{C}{current_version}{RS}")
        
        # Compare against vulnerable versions
        for vuln_version, cves in CVE_DATABASE[tech_name]["versions"].items():
            if compare_versions(current_version, vuln_version) <= 0:
                for cve in cves:
                    vulnerabilities.append({
                        "cve": cve,
                        "tech": tech_name,
                        "vulnerable_version": vuln_version,
                        "detected_version": current_version
                    })
                    alert(f"VULNERABILITY: {BR}{R}{cve}{RS} - {tech_name} {current_version}")
    
    if not vulnerabilities:
        ok("No known CVEs detected")
    
    return vulnerabilities


# ── Report Generation ──────────────────────────────────────────────────────────
def generate_scan_report(target: str, findings: dict) -> tuple:
    """Generate comprehensive JSON and TXT reports of scan findings"""
    section("REPORT GENERATION")
    
    # Create reports folder if it doesn't exist
    report_dir = "reports"
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)
        info(f"Created report directory: {BR}{C}{report_dir}{RS}")
    
    report = {
        "target": target,
        "scan_date": datetime.now().isoformat(),
        "findings": findings,
        "summary": {
            "total_findings": sum(len(v) if isinstance(v, list) else 1 for v in findings.values() if v),
            "critical_issues": 0,
            "high_priority": 0
        }
    }
    
    # Count critical issues
    if findings.get('exposed_paths'):
        report['summary']['critical_issues'] += len(findings['exposed_paths'])
    if findings.get('phpinfo_found'):
        report['summary']['critical_issues'] += 1
    if findings.get('cves'):
        report['summary']['high_priority'] += len(findings['cves'])
    
    timestamp = int(time.time())
    hostname = urlparse(target).hostname or 'unknown'
    
    # JSON Report
    json_filename = os.path.join(report_dir, f"scan_report_{hostname}_{timestamp}.json")
    # TXT Report
    txt_filename = os.path.join(report_dir, f"scan_report_{hostname}_{timestamp}.txt")
    
    try:
        # Save JSON Report
        with open(json_filename, 'w') as f:
            json.dump(report, f, indent=4)
        ok(f"JSON Report  : {BR}{G}{json_filename}{RS}")
        
        # Generate and save TXT Report
        txt_content = _generate_txt_report(target, report, findings)
        with open(txt_filename, 'w', encoding='utf-8') as f:
            f.write(txt_content)
        ok(f"TXT Report   : {BR}{G}{txt_filename}{RS}")
        
        return (json_filename, txt_filename)
    except Exception as e:
        alert(f"Report generation failed: {e}")
        return (None, None)


def _generate_txt_report(target: str, report: dict, findings: dict) -> str:
    """Generate formatted text report"""
    content = []
    content.append("=" * 80)
    content.append("                     WEB SECURITY SCAN REPORT".center(80))
    content.append("=" * 80)
    content.append("")
    
    # Header Info
    content.append("SCAN INFORMATION")
    content.append("-" * 80)
    content.append(f"Target URL       : {target}")
    content.append(f"Scan Date        : {report['scan_date']}")
    content.append(f"Report Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    content.append("")
    
    # Summary
    content.append("SUMMARY")
    content.append("-" * 80)
    content.append(f"Total Findings   : {report['summary']['total_findings']}")
    content.append(f"Critical Issues  : {report['summary']['critical_issues']}")
    content.append(f"High Priority    : {report['summary']['high_priority']}")
    content.append("")
    
    # Detailed Findings
    if findings:
        content.append("DETAILED FINDINGS")
        content.append("-" * 80)
        
        for category, items in findings.items():
            if items:
                content.append(f"\n{category.upper().replace('_', ' ')}")
                content.append("~" * 40)
                
                if isinstance(items, list):
                    if isinstance(items[0], dict):
                        # For list of dicts (CVEs, endpoints, etc.)
                        for i, item in enumerate(items, 1):
                            content.append(f"  [{i}] {item}")
                    else:
                        # For simple list (strings, tuples)
                        for i, item in enumerate(items, 1):
                            content.append(f"  [{i}] {item}")
                elif isinstance(items, dict):
                    # For dict findings
                    for key, value in items.items():
                        content.append(f"  • {key}: {value}")
        
        content.append("")
    
    # Footer
    content.append("=" * 80)
    content.append("END OF REPORT".center(80))
    content.append("=" * 80)
    
    return "\n".join(content)
