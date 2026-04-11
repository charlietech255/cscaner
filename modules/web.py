#!/usr/bin/env python3
"""
CSCAN — Web Analysis Modules
"""

import re
import os
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

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


def _get(url: str, path: str = '', timeout: int = TIMEOUT) -> requests.Response | None:
    try:
        return requests.get(
            url.rstrip('/') + path,
            timeout=timeout,
            allow_redirects=False,
            verify=False,
            headers={'User-Agent': 'Mozilla/5.0 (CSCAN Security Scanner)'}
        )
    except Exception:
        return None


# ── Web Vulnerability Scanner ─────────────────────────────────────────────────
def web_vuln_scan(target: str, use_ssl: bool = False) -> dict:
    section("WEB VULNERABILITY SCANNER")
    base = _build_url(target, use_ssl)
    info(f"Target        : {BR}{W}{base}{RS}")
    info(f"Probing       : {len(SENSITIVE_PATHS)} sensitive paths\n")

    findings = {'exposed': [], 'forbidden': [], 'auth_required': []}

    def check(path):
        r = _get(base, path)
        if r is None:
            return
        if r.status_code == 200:
            # Check for directory listing in body
            is_listing = any(x in r.text.lower() for x in ['index of /', 'directory listing for', 'alt="[dir]"'])
            return ('exposed', path, r.status_code, len(r.content), is_listing)
        elif r.status_code == 403:
            return ('forbidden', path, r.status_code, 0, False)
        elif r.status_code == 401:
            return ('auth_required', path, r.status_code, 0, False)
        return None

    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(check, p): p for p in SENSITIVE_PATHS}
        done = 0
        for fut in as_completed(futures):
            done += 1
            progress_bar(done, len(SENSITIVE_PATHS), 'probing paths')
            res = fut.result()
            if res:
                kind, path, code, size, is_listing = res
                findings[kind].append((path, size, is_listing))

    print('\n')
    # Display exposed (critical)
    for path, size, is_listing in findings['exposed']:
        pfx = "DIR LISTING: " if is_listing else "EXPOSED: "
        critical(f"{pfx}{base}{path}  [{size} bytes]")

    for path, _ in findings['forbidden']:
        warn(f"Forbidden (may be internal): {base}{path}")

    for path, _ in findings['auth_required']:
        info(f"Auth Required: {base}{path}")

    divider()
    total = sum(len(v) for v in findings.values())
    if findings['exposed']:
        alert(f"⚡  {len(findings['exposed'])} path(s) are publicly EXPOSED — immediate action needed!")
        info("Fix: Remove sensitive files or restrict access via .htaccess / nginx config")
    elif total == 0:
        ok("No sensitive paths exposed — good hygiene!")
    else:
        ok(f"No critical exposures. {total} non-200 responses noted.")

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
            warn(f"{hdr:<20} = {Y}{headers[hdr]}{RS}")
            leaks.append((hdr, headers[hdr]))
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
def dir_bruteforce(target: str, use_ssl: bool = False, wordlist: list = None) -> list:
    section("DIRECTORY & FILE BRUTE FORCER")
    base = _build_url(target, use_ssl)
    wl   = wordlist or DIR_WORDLIST
    info(f"Target        : {BR}{W}{base}{RS}")
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

    with ThreadPoolExecutor(max_workers=20) as ex:
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
        r = requests.get(
            base, timeout=8, verify=False,
            headers={'User-Agent': 'Mozilla/5.0 (CSCAN Scanner)'}
        )
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
