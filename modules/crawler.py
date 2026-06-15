#!/usr/bin/env python3
"""
CSCAN — Web Crawler & Discovery Engine
Spiders a target site to discover real pages, forms, parameters,
and endpoints BEFORE vulnerability testing begins.

This replaces the "guess parameter names" approach with real discovery.
"""

import re
import time
import random
import hashlib
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser

import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from modules.stealth import StealthSession
from modules.ui import (
    section, ok, warn, alert, info, critical, bold, divider,
    progress_bar, G, R, Y, C, M, W, BR, DM, RS
)

_stealth_session = None
_insecure_ssl = False
TIMEOUT = 8


def set_stealth_session(s):
    global _stealth_session
    _stealth_session = s

def set_insecure_ssl(flag):
    global _insecure_ssl
    _insecure_ssl = flag


# ── HTTP helper ───────────────────────────────────────────────────────────────
def _get(url, timeout=TIMEOUT, allow_redirects=True, cookies=None, headers=None):
    try:
        kw = {'timeout': timeout, 'allow_redirects': allow_redirects}
        if cookies:
            kw['cookies'] = cookies
        if _stealth_session:
            if headers:
                kw['headers'] = headers
            return _stealth_session.get(url, **kw)
        h = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'}
        if headers:
            h.update(headers)
        return requests.get(url, headers=h, verify=not _insecure_ssl, **kw)
    except Exception:
        return None


# ── HTML Parser for forms, links, and inputs ──────────────────────────────────
class _PageParser(HTMLParser):
    """Extract links, forms, input fields, and meta info from HTML."""

    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.links = set()
        self.forms = []
        self.scripts = []
        self.comments = []
        self.meta = {}
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        attrs_d = dict(attrs)
        tag = tag.lower()

        # Links
        if tag == 'a':
            href = attrs_d.get('href', '')
            if href and not href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                self.links.add(urljoin(self.base_url, href))

        # Forms
        elif tag == 'form':
            self._current_form = {
                'action': urljoin(self.base_url, attrs_d.get('action', '')),
                'method': attrs_d.get('method', 'GET').upper(),
                'inputs': [],
                'selects': [],
                'textareas': [],
            }

        # Inputs inside forms
        elif tag == 'input' and self._current_form is not None:
            self._current_form['inputs'].append({
                'name': attrs_d.get('name', ''),
                'type': attrs_d.get('type', 'text'),
                'value': attrs_d.get('value', ''),
                'id': attrs_d.get('id', ''),
            })

        elif tag == 'select' and self._current_form is not None:
            self._current_form['selects'].append({
                'name': attrs_d.get('name', ''),
                'id': attrs_d.get('id', ''),
            })

        elif tag == 'textarea' and self._current_form is not None:
            self._current_form['textareas'].append({
                'name': attrs_d.get('name', ''),
                'id': attrs_d.get('id', ''),
            })

        # Standalone inputs (not in form)
        elif tag == 'input' and self._current_form is None:
            name = attrs_d.get('name', '')
            if name:
                self.links.add(f'__param__:{name}')

        # Script sources
        elif tag == 'script':
            src = attrs_d.get('src', '')
            if src:
                self.scripts.append(urljoin(self.base_url, src))

        # Meta tags
        elif tag == 'meta':
            name = attrs_d.get('name', attrs_d.get('property', ''))
            content = attrs_d.get('content', '')
            if name and content:
                self.meta[name] = content

        # iframes, embeds
        elif tag in ('iframe', 'embed', 'object'):
            src = attrs_d.get('src', attrs_d.get('data', ''))
            if src:
                self.links.add(urljoin(self.base_url, src))

    def handle_endtag(self, tag):
        if tag.lower() == 'form' and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def handle_comment(self, data):
        data = data.strip()
        if len(data) > 5:
            self.comments.append(data)

    def handle_data(self, data):
        pass


# ── JS endpoint extractor ────────────────────────────────────────────────────
_JS_ENDPOINT_PATTERNS = [
    # API paths in strings
    re.compile(r'''['"](/api/[a-zA-Z0-9_/\-]+)['"]'''),
    re.compile(r'''['"](/v[123]/[a-zA-Z0-9_/\-]+)['"]'''),
    # fetch/axios/XMLHttpRequest calls
    re.compile(r'''(?:fetch|axios\.(?:get|post|put|delete)|\.open\s*\(\s*['"][A-Z]+['"]\s*,\s*)['"]((?:https?://)?/[a-zA-Z0-9_/\-?.=&]+)['"]'''),
    # Relative paths in strings
    re.compile(r'''['"](/[a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_\-]+){1,6})['"]'''),
    # GraphQL endpoints
    re.compile(r'''['"](/graphql[a-zA-Z0-9_/\-]*)['"]'''),
    # Webpack chunk paths
    re.compile(r'''['"](/static/[a-zA-Z0-9_/.\-]+)['"]'''),
    re.compile(r'''['"](/assets/[a-zA-Z0-9_/.\-]+)['"]'''),
]

_JS_SECRET_PATTERNS = [
    re.compile(r'''(?:api[_-]?key|apikey|api_secret|secret[_-]?key|access[_-]?token|auth[_-]?token|bearer)\s*[=:]\s*['"]([a-zA-Z0-9_\-]{16,})['"]''', re.I),
    re.compile(r'''(?:AWS_ACCESS_KEY_ID|aws_secret)\s*[=:]\s*['"]([A-Z0-9]{16,})['"]''', re.I),
    re.compile(r'''(?:password|passwd|pwd)\s*[=:]\s*['"]([^'"]{4,})['"]''', re.I),
]


def _extract_js_endpoints(js_text: str) -> list:
    """Extract API endpoints and paths from JavaScript source."""
    endpoints = set()
    for pattern in _JS_ENDPOINT_PATTERNS:
        for match in pattern.finditer(js_text[:200_000]):  # cap at 200KB
            ep = match.group(1)
            if len(ep) > 3 and not ep.endswith(('.png', '.jpg', '.gif', '.svg', '.css', '.woff', '.woff2', '.ttf')):
                endpoints.add(ep)
    return list(endpoints)


def _extract_js_secrets(js_text: str) -> list:
    """Extract potential secrets/keys from JavaScript source."""
    secrets = []
    for pattern in _JS_SECRET_PATTERNS:
        for match in pattern.finditer(js_text[:200_000]):
            secrets.append({
                'pattern': pattern.pattern[:40],
                'value': match.group(1)[:60],
                'context': js_text[max(0, match.start()-20):match.end()+20][:100],
            })
    return secrets


# ── URL parameter extractor ───────────────────────────────────────────────────
def _extract_params_from_url(url: str) -> dict:
    """Extract query parameters from a URL."""
    parsed = urlparse(url)
    return parse_qs(parsed.query)


# ── Main Crawler ──────────────────────────────────────────────────────────────
class WebCrawler:
    """
    Spider a website to discover pages, forms, parameters, and JS endpoints.

    Returns a CrawlResult with all discovered attack surface data.
    """

    def __init__(self, base_url: str, max_depth: int = 3, max_pages: int = 100,
                 cookies: dict = None, auth_header: str = None,
                 workers: int = 5, respect_robots: bool = True):
        self.base_url = base_url.rstrip('/')
        self.parsed_base = urlparse(self.base_url)
        self.domain = self.parsed_base.hostname
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.cookies = cookies or {}
        self.auth_header = auth_header
        self.workers = workers

        # Results
        self.visited = set()
        self.pages = {}            # url -> {status, size, title}
        self.forms = []            # list of form dicts
        self.parameters = {}       # param_name -> set of urls where found
        self.js_endpoints = set()
        self.js_secrets = []
        self.comments = []
        self.technologies = set()
        self.emails = set()
        self.error_pages = {}      # url -> status_code
        self.disallowed = set()    # from robots.txt

        # Content hashing for catch-all detection
        self._content_hashes = {}
        self._catch_all_hash = None

        if respect_robots:
            self._parse_robots()

    def _parse_robots(self):
        """Parse robots.txt for disallowed paths (useful recon data)."""
        r = _get(f'{self.base_url}/robots.txt', timeout=5)
        if r and r.status_code == 200:
            for line in r.text.splitlines():
                line = line.strip()
                if line.lower().startswith('disallow:'):
                    path = line.split(':', 1)[1].strip()
                    if path and path != '/':
                        self.disallowed.add(path)
                elif line.lower().startswith('sitemap:'):
                    sitemap_url = line.split(':', 1)[1].strip()
                    # If sitemap has a colon in the URL part, rejoin
                    if not sitemap_url.startswith('http'):
                        sitemap_url = 'http:' + sitemap_url
                    self._parse_sitemap(sitemap_url)

    def _parse_sitemap(self, url: str):
        """Parse sitemap.xml for additional URLs."""
        r = _get(url, timeout=5)
        if not r or r.status_code != 200:
            return
        # Simple regex extraction — works for both XML sitemaps and sitemap indexes
        for match in re.finditer(r'<loc>\s*(https?://[^<]+)\s*</loc>', r.text):
            found_url = match.group(1)
            if self.domain in found_url:
                self.visited.discard(found_url)  # ensure we visit it

    def _is_same_domain(self, url: str) -> bool:
        """Check if URL belongs to the same domain."""
        try:
            parsed = urlparse(url)
            return parsed.hostname == self.domain
        except Exception:
            return False

    def _normalize_url(self, url: str) -> str:
        """Normalize URL for dedup."""
        parsed = urlparse(url)
        # Remove fragments, normalize path
        path = parsed.path.rstrip('/') or '/'
        query = '&'.join(sorted(parsed.query.split('&'))) if parsed.query else ''
        return f'{parsed.scheme}://{parsed.hostname}{path}{"?" + query if query else ""}'

    def _detect_catch_all(self):
        """Detect catch-all routing by requesting a random nonexistent path."""
        rand_path = f'/cscan_probe_{random.randint(100000, 999999)}'
        r = _get(f'{self.base_url}{rand_path}', cookies=self.cookies)
        if r and r.status_code == 200:
            self._catch_all_hash = hashlib.md5(r.content).hexdigest()

    def _is_catch_all(self, content: bytes) -> bool:
        """Check if response matches the catch-all page."""
        if not self._catch_all_hash:
            return False
        return hashlib.md5(content).hexdigest() == self._catch_all_hash

    def _crawl_page(self, url: str, depth: int) -> list:
        """Crawl a single page and return discovered URLs."""
        if len(self.visited) >= self.max_pages:
            return []

        norm = self._normalize_url(url)
        if norm in self.visited:
            return []
        self.visited.add(norm)

        # Skip non-HTML resources
        skip_ext = ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.css',
                    '.woff', '.woff2', '.ttf', '.eot', '.pdf', '.zip', '.tar',
                    '.gz', '.mp4', '.mp3', '.avi', '.mov')
        if any(url.lower().endswith(ext) for ext in skip_ext):
            return []

        headers = {}
        if self.auth_header:
            headers['Authorization'] = self.auth_header

        r = _get(url, cookies=self.cookies, headers=headers if headers else None)
        if not r:
            return []

        # Track error pages
        if r.status_code >= 400:
            self.error_pages[url] = r.status_code
            return []

        # Skip catch-all pages
        if self._is_catch_all(r.content):
            return []

        content_type = r.headers.get('Content-Type', '')

        # Track page info
        title_match = re.search(r'<title[^>]*>([^<]+)</title>', r.text, re.I)
        self.pages[url] = {
            'status': r.status_code,
            'size': len(r.content),
            'title': title_match.group(1).strip() if title_match else '',
            'content_type': content_type,
        }

        # Technology detection from headers
        server = r.headers.get('Server', '')
        if server:
            self.technologies.add(f'Server: {server}')
        powered = r.headers.get('X-Powered-By', '')
        if powered:
            self.technologies.add(f'X-Powered-By: {powered}')
        for cookie_name in r.cookies.keys():
            if 'PHPSESSID' in cookie_name.upper():
                self.technologies.add('PHP')
            elif 'JSESSIONID' in cookie_name.upper():
                self.technologies.add('Java/Servlet')
            elif 'ASP.NET' in cookie_name.upper():
                self.technologies.add('ASP.NET')
            elif 'laravel' in cookie_name.lower():
                self.technologies.add('Laravel')

        # Extract URL parameters
        params = _extract_params_from_url(url)
        for param_name in params:
            if param_name not in self.parameters:
                self.parameters[param_name] = set()
            self.parameters[param_name].add(url)

        # Email extraction
        email_re = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
        self.emails.update(email_re.findall(r.text[:50000]))

        # Don't parse non-HTML
        if 'html' not in content_type and 'text' not in content_type:
            return []

        # Parse HTML
        new_urls = []
        try:
            parser = _PageParser(url)
            parser.feed(r.text)

            # Collect forms
            for form in parser.forms:
                form['page_url'] = url
                # Extract all parameter names from form
                all_params = []
                for inp in form.get('inputs', []):
                    name = inp.get('name', '')
                    if name:
                        all_params.append(name)
                        if name not in self.parameters:
                            self.parameters[name] = set()
                        self.parameters[name].add(url)
                for sel in form.get('selects', []):
                    name = sel.get('name', '')
                    if name:
                        all_params.append(name)
                for ta in form.get('textareas', []):
                    name = ta.get('name', '')
                    if name:
                        all_params.append(name)
                form['all_param_names'] = all_params
                self.forms.append(form)

            # Collect comments
            self.comments.extend(parser.comments[:20])

            # Collect links for further crawling
            if depth < self.max_depth:
                for link in parser.links:
                    if link.startswith('__param__:'):
                        continue
                    if self._is_same_domain(link):
                        norm_link = self._normalize_url(link)
                        if norm_link not in self.visited:
                            new_urls.append((link, depth + 1))

            # Process JS files
            for js_url in parser.scripts[:20]:  # cap JS files per page
                if self._is_same_domain(js_url) or True:  # also check external JS
                    js_r = _get(js_url, timeout=5, cookies=self.cookies)
                    if js_r and js_r.status_code == 200 and len(js_r.content) < 2_000_000:
                        endpoints = _extract_js_endpoints(js_r.text)
                        for ep in endpoints:
                            full = urljoin(self.base_url, ep)
                            self.js_endpoints.add(full)
                        secrets = _extract_js_secrets(js_r.text)
                        self.js_secrets.extend(secrets)

            # Also check inline scripts
            inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', r.text, re.S | re.I)
            for script_body in inline_scripts[:10]:
                if len(script_body) > 20:
                    endpoints = _extract_js_endpoints(script_body)
                    for ep in endpoints:
                        full = urljoin(self.base_url, ep)
                        self.js_endpoints.add(full)
                    secrets = _extract_js_secrets(script_body)
                    self.js_secrets.extend(secrets)

        except Exception:
            pass

        return new_urls

    def crawl(self) -> dict:
        """
        Run the full crawl. Returns a structured result dict.
        """
        section("WEB CRAWLER & ATTACK SURFACE DISCOVERY")
        info(f"Target        : {BR}{W}{self.base_url}{RS}")
        info(f"Max Depth     : {BR}{W}{self.max_depth}{RS}")
        info(f"Max Pages     : {BR}{W}{self.max_pages}{RS}")
        if self.cookies:
            ok(f"Auth cookies  : {len(self.cookies)} cookie(s) loaded")
        if self.auth_header:
            ok("Auth header   : Configured")
        if self.disallowed:
            info(f"robots.txt    : {len(self.disallowed)} disallowed path(s) found")
        print()

        # Detect catch-all routing
        self._detect_catch_all()
        if self._catch_all_hash:
            warn("Catch-all routing detected — duplicate content will be filtered.")

        # BFS crawl
        queue = deque([(self.base_url, 0)])
        crawled = 0

        while queue and len(self.visited) < self.max_pages:
            url, depth = queue.popleft()
            crawled += 1
            progress_bar(crawled, self.max_pages, f'crawling (depth {depth})')

            new_urls = self._crawl_page(url, depth)
            for new_url, new_depth in new_urls:
                queue.append((new_url, new_depth))

        # Also probe JS-discovered endpoints
        info(f"\nProbing {len(self.js_endpoints)} JS-discovered endpoints...")
        for ep_url in list(self.js_endpoints)[:50]:
            if self._normalize_url(ep_url) not in self.visited:
                self._crawl_page(ep_url, self.max_depth)

        # Also probe robots.txt disallowed paths
        for path in self.disallowed:
            full = f'{self.base_url}{path}'
            if self._normalize_url(full) not in self.visited:
                self._crawl_page(full, self.max_depth)

        print('\n')
        self._print_summary()

        return self._build_result()

    def _print_summary(self):
        divider()
        ok(f"Pages crawled : {len(self.pages)}")
        ok(f"Forms found   : {len(self.forms)}")
        ok(f"Parameters    : {len(self.parameters)}")
        ok(f"JS endpoints  : {len(self.js_endpoints)}")

        if self.forms:
            print(f"\n  {BR}{M}  Discovered Forms:{RS}")
            for f in self.forms[:15]:
                params = ', '.join(f.get('all_param_names', [])[:6])
                print(f"  {BR}{Y}[{f['method']}]{RS} {W}{f['action'][:60]}{RS}")
                print(f"       {DM}params: {params}{RS}")

        if self.parameters:
            print(f"\n  {BR}{M}  Unique Parameters ({len(self.parameters)}):{RS}")
            for name in sorted(self.parameters.keys())[:30]:
                pages = self.parameters[name]
                print(f"  {G}•{RS} {W}{name}{RS}  {DM}(on {len(pages)} page(s)){RS}")

        if self.js_endpoints:
            print(f"\n  {BR}{M}  JS-Discovered Endpoints ({len(self.js_endpoints)}):{RS}")
            for ep in sorted(self.js_endpoints)[:15]:
                print(f"  {C}•{RS} {W}{ep}{RS}")

        if self.js_secrets:
            print(f"\n  {BR}{R}  Potential Secrets in JS ({len(self.js_secrets)}):{RS}")
            for s in self.js_secrets[:10]:
                print(f"  {R}◆{RS} {W}{s['value'][:40]}...{RS}")

        if self.disallowed:
            print(f"\n  {BR}{M}  robots.txt Disallowed ({len(self.disallowed)}):{RS}")
            for path in sorted(self.disallowed)[:10]:
                print(f"  {Y}•{RS} {W}{path}{RS}")

        if self.technologies:
            print(f"\n  {BR}{M}  Technologies:{RS}")
            for tech in sorted(self.technologies):
                print(f"  {C}•{RS} {W}{tech}{RS}")

        if self.emails:
            filtered = {e for e in self.emails if 'example.com' not in e}
            if filtered:
                print(f"\n  {BR}{M}  Emails Found ({len(filtered)}):{RS}")
                for email in sorted(filtered)[:10]:
                    print(f"  {G}•{RS} {W}{email}{RS}")

        if self.comments:
            interesting = [c for c in self.comments if any(w in c.lower() for w in
                          ('todo', 'fixme', 'hack', 'bug', 'password', 'secret',
                           'admin', 'debug', 'test', 'key', 'token', 'api'))]
            if interesting:
                print(f"\n  {BR}{Y}  Interesting HTML Comments ({len(interesting)}):{RS}")
                for c in interesting[:5]:
                    print(f"  {Y}!{RS} {DM}{c[:80]}{RS}")

    def _build_result(self) -> dict:
        return {
            'base_url': self.base_url,
            'pages_crawled': len(self.pages),
            'pages': {url: info for url, info in list(self.pages.items())[:200]},
            'forms': self.forms[:100],
            'parameters': {k: list(v)[:5] for k, v in self.parameters.items()},
            'js_endpoints': list(self.js_endpoints)[:200],
            'js_secrets': self.js_secrets[:50],
            'technologies': list(self.technologies),
            'emails': list(self.emails)[:50],
            'disallowed_paths': list(self.disallowed),
            'comments': self.comments[:50],
            'error_pages': self.error_pages,
        }


# ── Public interface ──────────────────────────────────────────────────────────
def crawl_target(target: str, use_ssl: bool = False, max_depth: int = 3,
                 max_pages: int = 100, cookies: dict = None,
                 auth_header: str = None) -> dict:
    """
    Crawl a target website and return all discovered attack surface data.
    This should be run BEFORE any active vulnerability testing.
    """
    if target.startswith(('http://', 'https://')):
        base = target.rstrip('/')
    else:
        proto = 'https' if use_ssl else 'http'
        base = f'{proto}://{target.rstrip("/")}'

    crawler = WebCrawler(
        base_url=base,
        max_depth=max_depth,
        max_pages=max_pages,
        cookies=cookies,
        auth_header=auth_header,
    )
    return crawler.crawl()
