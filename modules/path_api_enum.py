#!/usr/bin/env python3
"""
CSCAN — Path / API Endpoint Enumerator (v2 — Smart False-Positive Filtering)

Discovers REAL API endpoints and accessible paths on a target.
Uses baseline fingerprinting to detect custom 404 pages that return HTTP 200,
ensuring only genuinely valid endpoints are reported.

Techniques:
  1. Baseline calibration — requests random non-existent paths to learn
     what the target's "not found" response looks like (body hash, size, keywords)
  2. Similarity scoring — compares each response against baselines to filter soft-404s
  3. Content-type aware detection (JSON/XML = likely API)
  4. HTTP method probing (GET, POST, PUT, DELETE, PATCH, OPTIONS)
  5. OpenAPI / Swagger spec auto-detection & route extraction
"""

import re
import time
import json
import random
import hashlib
import string
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from difflib import SequenceMatcher

import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from modules.stealth import StealthSession
from modules.ui import (
    section, ok, warn, alert, info, bold, divider,
    progress_bar, print_table,
    G, R, Y, C, M, W, B, BR, DM, RS
)

_stealth_session = None
_insecure_ssl = False
TIMEOUT = 8


# ── Stealth integration ───────────────────────────────────────────────────────
def set_stealth_session(s):
    global _stealth_session
    _stealth_session = s

def set_insecure_ssl(flag):
    global _insecure_ssl
    _insecure_ssl = flag


# ── Default API path wordlist ─────────────────────────────────────────────────
DEFAULT_API_PATHS = [
    "/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3",
    "/rest", "/rest/v1", "/rest/v2",
    "/graphql", "/graphql/console", "/gql",
    "/swagger.json", "/swagger/", "/swagger-ui/", "/swagger-ui.html",
    "/openapi.json", "/openapi.yaml", "/openapi/",
    "/api-docs", "/api-docs/", "/docs", "/docs/",
    "/redoc", "/redoc/", "/.well-known/openapi.yaml",
    "/api/auth", "/api/login", "/api/register", "/api/signup",
    "/api/token", "/api/refresh", "/api/logout",
    "/auth/login", "/auth/register", "/auth/token",
    "/oauth/token", "/oauth/authorize",
    "/api/v1/auth", "/api/v1/login", "/login", "/register", "/signup",
    "/api/users", "/api/user", "/api/me", "/api/profile",
    "/api/accounts", "/api/account",
    "/api/products", "/api/items", "/api/orders",
    "/api/posts", "/api/comments", "/api/categories",
    "/api/files", "/api/upload", "/api/uploads",
    "/api/images", "/api/media",
    "/api/settings", "/api/config", "/api/configuration",
    "/api/notifications", "/api/messages",
    "/api/search", "/api/query",
    "/api/payments", "/api/billing", "/api/invoices",
    "/api/admin", "/admin/api", "/internal/api",
    "/api/health", "/api/status", "/api/ping",
    "/health", "/healthz", "/ready", "/readyz",
    "/status", "/ping", "/info",
    "/metrics", "/prometheus/metrics",
    "/api/metrics", "/api/stats", "/api/analytics",
    "/api/logs", "/api/events", "/api/audit",
    "/debug", "/debug/vars", "/debug/pprof",
    "/env", "/environment", "/api/debug", "/api/env",
    "/_debug", "/__debug__",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/info",
    "/actuator/beans", "/actuator/mappings",
    "/v1/users", "/v1/auth", "/v1/health", "/v1/status",
    "/v2/users", "/v2/auth", "/v2/health", "/v2/status",
    "/api/webhooks", "/api/webhook", "/webhooks", "/hooks",
    "/api/callbacks",
    "/graphql/schema", "/graphql/playground", "/graphiql", "/__graphql",
    "/api/storage", "/api/bucket", "/api/download",
    "/api/export", "/api/import",
    "/api/version", "/api/info",
    "/api/countries", "/api/languages", "/api/timezones",
    "/sitemap.xml", "/robots.txt",
    "/.env", "/wp-json/", "/wp-json/wp/v2/",
    "/jsonapi", "/jsonapi/node",
]


# ── HTTP helper ───────────────────────────────────────────────────────────────
def _request(method, url, timeout=TIMEOUT, allow_redirects=False):
    """Make an HTTP request respecting stealth settings."""
    try:
        kw = {
            'timeout': timeout,
            'allow_redirects': allow_redirects,
        }
        if _stealth_session:
            fn = getattr(_stealth_session, method.lower(), _stealth_session.get)
            return fn(url, **kw)

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                          'AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/124.0.0.0 Safari/537.36',
            'Accept': 'application/json, text/html, */*',
        }
        fn = getattr(requests, method.lower(), requests.get)
        return fn(url, headers=headers, verify=not _insecure_ssl, **kw)
    except Exception:
        return None


# ── Soft-404 / Baseline Fingerprinting ────────────────────────────────────────
# This is the core anti-false-positive system.
# We probe random non-existent paths to learn what the server returns for
# "not found" — even when it sends HTTP 200.

_SOFT404_KEYWORDS = (
    'not found', 'page not found', '404', 'does not exist', 'no such page',
    'nothing here', 'page you requested', 'could not be found',
    'doesn\'t exist', 'resource not found', 'the page you are looking for',
    'we couldn\'t find', 'page is not available', 'error 404',
    'page cannot be found', 'oops', 'sorry, we can\'t find',
)


def _random_path() -> str:
    """Generate a clearly non-existent random path for baseline probing."""
    rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    # Vary structure to detect path-prefix-based catch-alls
    templates = [
        f'/cscan_baseline_{rand}',
        f'/api/cscan_{rand}_nonexistent',
        f'/v1/cscan_{rand}',
        f'/{rand}/does/not/exist',
    ]
    return random.choice(templates)


def _body_hash(text: str) -> str:
    """Hash the normalized body content for comparison."""
    # Strip whitespace variations and normalize
    normalized = re.sub(r'\s+', ' ', text.strip().lower())
    # Remove dynamic tokens (CSRF, nonce, timestamps)
    normalized = re.sub(r'[0-9a-f]{32,}', 'HASH', normalized)
    normalized = re.sub(r'\d{10,}', 'TIMESTAMP', normalized)
    return hashlib.md5(normalized.encode()).hexdigest()


def _extract_title(html: str) -> str:
    """Extract page title from HTML."""
    m = re.search(r'<title[^>]*>(.*?)</title>', html, re.I | re.S)
    return m.group(1).strip().lower() if m else ''


class BaselineFingerprint:
    """
    Captures what the target returns for non-existent pages.
    Used to detect soft-404s (custom 404 pages that return 200).
    """

    def __init__(self, base_url: str, num_probes: int = 4):
        self.base_url = base_url
        self.fingerprints = []  # list of dicts with hash, size, title, status, keywords
        self._calibrate(num_probes)

    def _calibrate(self, num_probes: int):
        """Send probes to non-existent paths and record response fingerprints."""
        for _ in range(num_probes):
            path = _random_path()
            url = f'{self.base_url}{path}'
            r = _request('GET', url, allow_redirects=True)
            if not r:
                continue

            body = r.text or ''
            fp = {
                'status': r.status_code,
                'size': len(r.content),
                'hash': _body_hash(body),
                'title': _extract_title(body),
                'content_type': r.headers.get('Content-Type', '').lower(),
                'has_soft404_keywords': any(kw in body.lower() for kw in _SOFT404_KEYWORDS),
            }
            self.fingerprints.append(fp)

    def is_soft_404(self, resp) -> bool:
        """
        Determine if a response is a soft-404 (custom not-found page disguised as 200).

        Returns True if the response matches baseline fingerprints = fake/not-real endpoint.
        """
        if not resp or not self.fingerprints:
            return False

        body = resp.text or ''
        resp_hash = _body_hash(body)
        resp_size = len(resp.content)
        resp_title = _extract_title(body)
        resp_ct = resp.headers.get('Content-Type', '').lower()

        for fp in self.fingerprints:
            # Exact body hash match → definitely soft-404
            if resp_hash == fp['hash']:
                return True

            # Same title as baseline (and title is not empty/generic)
            if fp['title'] and resp_title == fp['title']:
                # Also check size is within 15% tolerance
                if fp['size'] > 0:
                    ratio = resp_size / fp['size'] if fp['size'] else 0
                    if 0.85 <= ratio <= 1.15:
                        return True

            # Size match within tight tolerance (±50 bytes) AND same content-type
            if abs(resp_size - fp['size']) < 50 and resp_ct == fp['content_type']:
                # Additional check: body similarity
                if fp['size'] > 100:  # only if bodies are non-trivial
                    return True

        # Check for soft-404 keyword indicators in body
        body_lower = body[:2000].lower()
        if any(kw in body_lower for kw in _SOFT404_KEYWORDS):
            # Only flag if it's an HTML response (APIs might legitimately say "not found")
            if 'html' in resp_ct:
                return True

        return False

    def get_baseline_info(self) -> dict:
        """Return summary of baseline fingerprints for reporting."""
        if not self.fingerprints:
            return {
                'probes': 0,
                'type': 'unknown',
                'statuses': [],
                'avg_size': 0,
                'has_catch_all': False,
                'soft404_detected': False,
            }
        statuses = [fp['status'] for fp in self.fingerprints]
        sizes = [fp['size'] for fp in self.fingerprints]
        return {
            'probes': len(self.fingerprints),
            'statuses': list(set(statuses)),
            'avg_size': sum(sizes) // len(sizes) if sizes else 0,
            'has_catch_all': any(s == 200 for s in statuses),
            'soft404_detected': any(fp['has_soft404_keywords'] for fp in self.fingerprints),
        }


# ── Response validation helpers ───────────────────────────────────────────────

def _is_api_response(resp) -> bool:
    """Determine if a response looks like a real API endpoint."""
    if not resp:
        return False
    ct = resp.headers.get('Content-Type', '').lower()
    if any(t in ct for t in ('json', 'xml', 'graphql')):
        return True
    # Try to parse as JSON
    try:
        json.loads(resp.text[:5000])
        return True
    except (json.JSONDecodeError, ValueError):
        pass
    return False


def _classify_endpoint(path, resp) -> str:
    """Classify what kind of endpoint this is."""
    ct = resp.headers.get('Content-Type', '').lower() if resp else ''
    path_lower = path.lower()

    if 'swagger' in path_lower or 'openapi' in path_lower or 'api-docs' in path_lower:
        return 'DOCUMENTATION'
    elif 'graphql' in path_lower or 'gql' in path_lower:
        return 'GRAPHQL'
    elif any(w in path_lower for w in ('auth', 'login', 'token', 'oauth', 'register')):
        return 'AUTHENTICATION'
    elif any(w in path_lower for w in ('admin', 'internal', 'debug', 'actuator')):
        return 'ADMIN/DEBUG'
    elif any(w in path_lower for w in ('health', 'status', 'ping', 'ready', 'metrics')):
        return 'HEALTH/MONITORING'
    elif any(w in path_lower for w in ('upload', 'file', 'storage', 'media', 'image')):
        return 'FILE HANDLING'
    elif any(w in path_lower for w in ('webhook', 'hook', 'callback')):
        return 'WEBHOOK'
    elif 'json' in ct or 'xml' in ct:
        return 'API'
    elif 'html' in ct:
        return 'WEB PAGE'
    else:
        return 'ENDPOINT'


def _probe_methods(url, include_unsafe: bool = False) -> list:
    """Discover methods without mutating state unless explicitly requested."""
    allowed = []
    r = _request('OPTIONS', url, timeout=5)
    if r and r.status_code < 400:
        allow_header = r.headers.get('Allow', '')
        if allow_header:
            advertised = [m.strip().upper() for m in allow_header.split(',')]
            safe = {'GET', 'HEAD', 'OPTIONS'}
            allowed.extend(method for method in advertised
                           if method in safe or include_unsafe)

    methods = ('GET', 'HEAD')
    if include_unsafe:
        methods += ('POST', 'PUT', 'DELETE', 'PATCH')
    for method in methods:
        r = _request(method, url, timeout=5)
        if r and r.status_code < 405:
            allowed.append(method)
    return list(dict.fromkeys(allowed))


# ── Main enumeration logic ────────────────────────────────────────────────────
class APIEnumerator:
    """
    Enumerates API endpoints and paths on a target with smart
    false-positive filtering via baseline fingerprinting.
    """

    def __init__(self, base_url: str, wordlist: list = None,
                 workers: int = 15, probe_methods: bool = False,
                 probe_unsafe_methods: bool = False,
                 timeout: int = TIMEOUT):
        self.base_url = base_url.rstrip('/')
        self.wordlist = wordlist or DEFAULT_API_PATHS
        self.workers = workers
        self.probe_methods = probe_methods
        self.probe_unsafe_methods = probe_unsafe_methods
        self.timeout = timeout

        # Results
        self.found_endpoints = []
        self.soft404_filtered = 0    # count of soft-404s we caught
        self.spec_urls = []
        self.total_checked = 0
        self.start_time = None
        self.baseline = None

    def _check_path(self, path: str) -> dict | None:
        """Check a single path. Returns endpoint info or None."""
        url = f'{self.base_url}{path}'
        r = _request('GET', url, timeout=self.timeout)
        if not r:
            return None

        status = r.status_code

        # Hard 404/5xx = definitely not found
        if status in (404, 410, 502, 503, 504):
            return None

        # ── SOFT-404 DETECTION ────────────────────────────────────────────────
        # This is the key improvement: catch custom 404 pages returning 200
        if status == 200 and self.baseline and self.baseline.is_soft_404(r):
            self.soft404_filtered += 1
            return None

        ct = r.headers.get('Content-Type', '').lower()

        # For 200 responses, do additional validation
        if status == 200:
            body = r.text or ''
            body_lower = body[:3000].lower()

            # Empty body with HTML content type = likely catch-all
            if 'html' in ct and len(body.strip()) < 50:
                self.soft404_filtered += 1
                return None

            # Check if response body is just a redirect page
            if 'html' in ct and '<meta http-equiv="refresh"' in body_lower:
                # It's a meta-redirect — might be a soft-404 redirect
                if any(kw in body_lower for kw in _SOFT404_KEYWORDS):
                    self.soft404_filtered += 1
                    return None

        # Build endpoint info
        endpoint = {
            'path': path,
            'url': url,
            'status': status,
            'content_type': ct,
            'size': len(r.content),
            'is_api': _is_api_response(r),
            'category': _classify_endpoint(path, r),
            'methods': ['GET'],
            'headers': dict(r.headers),
        }

        # Check for interesting headers
        interesting_headers = {}
        for h in ('X-Powered-By', 'Server', 'X-Request-Id', 'X-RateLimit-Limit',
                  'X-API-Version', 'Access-Control-Allow-Origin',
                  'Access-Control-Allow-Methods', 'WWW-Authenticate'):
            val = r.headers.get(h)
            if val:
                interesting_headers[h] = val
        endpoint['interesting_headers'] = interesting_headers

        # If it's a spec file, store it specially
        if any(w in path.lower() for w in ('swagger', 'openapi', 'api-docs')):
            if status == 200:
                self.spec_urls.append(url)
                try:
                    spec = json.loads(r.text)
                    paths = spec.get('paths', {})
                    endpoint['spec_routes'] = list(paths.keys())[:50]
                except (json.JSONDecodeError, ValueError):
                    pass

        return endpoint

    def enumerate(self) -> dict:
        """Run the full API enumeration scan."""
        self.start_time = time.time()
        section("PATH / API ENDPOINT ENUMERATOR")
        info(f"Target       : {BR}{W}{self.base_url}{RS}")
        info(f"Wordlist     : {BR}{W}{len(self.wordlist)} paths{RS}")
        info(f"Workers      : {BR}{W}{self.workers}{RS}")
        info(f"Method Probe : {BR}{W}{'ON' if self.probe_methods else 'OFF'}{RS}")
        print()

        # ── Phase 0: Baseline calibration (anti-false-positive) ───────────────
        bold("Phase 0: Calibrating baseline (detecting custom 404 pages)...")
        self.baseline = BaselineFingerprint(self.base_url, num_probes=4)
        bl_info = self.baseline.get_baseline_info()

        if bl_info['has_catch_all']:
            warn(f"Target returns HTTP 200 for non-existent paths (soft-404 / catch-all detected)")
            info(f"Baseline: {bl_info['probes']} probes, avg size {bl_info['avg_size']} bytes")
            info("Soft-404 filtering is ACTIVE — false positives will be suppressed.")
        else:
            ok(f"Target returns proper 404 for non-existent paths. Baseline recorded.")
        print()

        # ── Phase 1: Path discovery ───────────────────────────────────────────
        bold("Phase 1: Discovering real endpoints...")
        print()

        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = {}
            for path in self.wordlist:
                f = executor.submit(self._check_path, path)
                futures[f] = path

            done = 0
            total = len(futures)
            for future in as_completed(futures):
                done += 1
                self.total_checked += 1
                progress_bar(done, total, 'scanning paths')
                result = future.result()
                if result:
                    self.found_endpoints.append(result)

        print('\n')
        if self.soft404_filtered:
            info(f"Filtered {self.soft404_filtered} soft-404 false positive(s)")

        # ── Phase 2: Method probing on discovered endpoints ───────────────────
        if self.probe_methods and self.found_endpoints:
            bold("Phase 2: Probing allowed HTTP methods...")
            print()
            for i, ep in enumerate(self.found_endpoints):
                progress_bar(i + 1, len(self.found_endpoints), 'probing methods')
                methods = _probe_methods(ep['url'], self.probe_unsafe_methods)
                if methods:
                    ep['methods'] = methods
            print('\n')

        # ── Phase 3: Extract routes from discovered API specs ─────────────────
        spec_routes = set()
        if self.spec_urls:
            bold("Phase 3: Extracting routes from API specs...")
            for spec_url in self.spec_urls:
                r = _request('GET', spec_url)
                if r and r.status_code == 200:
                    try:
                        spec = json.loads(r.text)
                        for route in spec.get('paths', {}).keys():
                            spec_routes.add(route)
                    except (json.JSONDecodeError, ValueError):
                        pass
            if spec_routes:
                ok(f"Extracted {len(spec_routes)} route(s) from API specification(s)")
                new_paths = [p for p in spec_routes
                             if p not in [ep['path'] for ep in self.found_endpoints]]
                if new_paths:
                    info(f"Probing {len(new_paths)} newly discovered spec routes...")
                    with ThreadPoolExecutor(max_workers=self.workers) as executor:
                        futures = {executor.submit(self._check_path, p): p
                                   for p in new_paths[:100]}
                        for future in as_completed(futures):
                            result = future.result()
                            if result:
                                self.found_endpoints.append(result)

        elapsed = time.time() - self.start_time
        print()
        self._print_report(elapsed, spec_routes)
        return self._build_result(elapsed, spec_routes)

    def _print_report(self, elapsed: float, spec_routes: set):
        """Print a formatted report of findings."""
        divider()
        section("API ENUMERATION REPORT")
        print()
        ok(f"Paths checked       : {self.total_checked}")
        ok(f"Real endpoints      : {len(self.found_endpoints)}")
        ok(f"Soft-404s filtered  : {self.soft404_filtered}")
        ok(f"API specs found     : {len(self.spec_urls)}")
        ok(f"Spec routes         : {len(spec_routes)}")
        ok(f"Time elapsed        : {elapsed:.1f}s")
        print()

        if not self.found_endpoints:
            warn("No real endpoints discovered. Target may block all probes.")
            return

        # Group by category
        categories = {}
        for ep in self.found_endpoints:
            cat = ep['category']
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(ep)

        for cat, endpoints in sorted(categories.items()):
            print(f"\n  {BR}{M}  [{cat}] ({len(endpoints)} endpoint(s)){RS}")
            for ep in endpoints:
                status = ep['status']
                if status == 200:
                    status_color = G
                elif status in (301, 302, 307):
                    status_color = Y
                elif status in (401, 403):
                    status_color = R
                else:
                    status_color = W

                api_flag = f" {C}[API]{RS}" if ep['is_api'] else ""
                methods_str = ','.join(ep['methods'])
                print(f"    {status_color}[{status}]{RS} {W}{ep['path']}{RS}"
                      f"  {DM}({methods_str}){RS}"
                      f"  {DM}{ep['content_type'][:30]}{RS}{api_flag}")

                for h, v in ep.get('interesting_headers', {}).items():
                    print(f"         {DM}↳ {h}: {v[:60]}{RS}")

        # Highlight security-sensitive findings
        sensitive = [ep for ep in self.found_endpoints
                     if ep['category'] in ('ADMIN/DEBUG', 'AUTHENTICATION')
                     or ep['status'] == 200 and any(w in ep['path'].lower()
                         for w in ('.env', 'debug', 'actuator', 'internal'))]
        if sensitive:
            print(f"\n  {BR}{R}  ⚠ SECURITY-SENSITIVE ENDPOINTS:{RS}")
            for ep in sensitive:
                print(f"    {R}◆{RS} {W}{ep['path']}{RS} → {Y}Status {ep['status']}{RS}")

        # Show spec routes that are documented but not live
        if spec_routes:
            live_paths = {ep['path'] for ep in self.found_endpoints}
            documented_only = spec_routes - live_paths
            if documented_only:
                print(f"\n  {BR}{C}  Documented but unreachable ({len(documented_only)}):{RS}")
                for route in sorted(documented_only)[:20]:
                    print(f"    {DM}•{RS} {W}{route}{RS}")

    def _build_result(self, elapsed: float, spec_routes: set) -> dict:
        """Build structured result dict for session storage."""
        return {
            'target': self.base_url,
            'timestamp': datetime.now().isoformat(),
            'paths_checked': self.total_checked,
            'endpoints_found': len(self.found_endpoints),
            'soft404_filtered': self.soft404_filtered,
            'elapsed_seconds': round(elapsed, 2),
            'baseline_info': self.baseline.get_baseline_info() if self.baseline else {},
            'endpoints': [
                {
                    'path': ep['path'],
                    'url': ep['url'],
                    'status': ep['status'],
                    'content_type': ep['content_type'],
                    'size': ep['size'],
                    'is_api': ep['is_api'],
                    'category': ep['category'],
                    'methods': ep['methods'],
                    'interesting_headers': ep.get('interesting_headers', {}),
                }
                for ep in self.found_endpoints
            ],
            'spec_urls': self.spec_urls,
            'spec_routes': list(spec_routes),
            'categories': {
                cat: len([e for e in self.found_endpoints if e['category'] == cat])
                for cat in set(e['category'] for e in self.found_endpoints)
            },
        }


# ── Public interface ──────────────────────────────────────────────────────────
def enumerate_api(target: str, use_ssl: bool = False, wordlist: list = None,
                  workers: int = 15, probe_methods: bool = False,
                  probe_unsafe_methods: bool = False) -> dict:
    """
    Enumerate API endpoints and paths on a target.
    Uses baseline fingerprinting to eliminate false positives from
    custom 404 pages that return HTTP 200.

    Args:
        target: Domain or URL to scan
        use_ssl: Use HTTPS if target doesn't specify protocol
        wordlist: Custom list of paths to check (uses built-in if None)
        workers: Number of concurrent threads
        probe_methods: Whether to probe allowed HTTP methods per endpoint

    Returns:
        Dict with all discovered endpoints and metadata
    """
    if target.startswith(('http://', 'https://')):
        base = target.rstrip('/')
    else:
        proto = 'https' if use_ssl else 'http'
        base = f'{proto}://{target.rstrip("/")}'

    enumerator = APIEnumerator(
        base_url=base,
        wordlist=wordlist,
        workers=workers,
        probe_methods=probe_methods,
        probe_unsafe_methods=probe_unsafe_methods,
    )
    return enumerator.enumerate()
