#!/usr/bin/env python3
"""
CSCAN — Email Finder
====================
Discovers publicly exposed e-mail addresses for a target domain from:

  1. Live site crawl (mailto:/text extraction via the shared crawler)
  2. Certificate Transparency logs (crt.sh) — cert SANs often embed emails
  3. Domain WHOIS (python-whois) — registrant / admin / tech contacts
  4. DuckDuckGo HTML search (optional) — passive indexed exposure

Every address is de-duplicated and tagged: ROLE addresses (info@, admin@…)
and EXTERNAL addresses (belonging to other domains) are flagged so analysts
can prioritise human targets over aliases. MX records are resolved over
DNS-over-HTTPS (no extra dependency) to hint whether the domain even has
mail infrastructure.
"""

import re
from urllib.parse import urlparse

import requests

from modules.stealth import StealthSession
from modules.ui import (
    section, ok, warn, alert, info, divider, print_table,
    G, R, Y, C, M, W, BR, DM, RS, T
)
from modules.crawler import crawl_target
from modules.subdomain_finder import extract_hostname

_stealth_session = None

def set_stealth_session(session: StealthSession):
    global _stealth_session
    _stealth_session = session


# ── Email extraction ─────────────────────────────────────────────────────────
_EMAIL_RE = re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')

_ROLE_HINTS = (
    'admin', 'postmaster', 'webmaster', 'hostmaster', 'info', 'contact',
    'support', 'sales', 'billing', 'abuse', 'noreply', 'no-reply',
    'it', 'helpdesk', 'service', 'office', 'hello', 'hr',
)


def _extract_from_text(text: str, hostname: str) -> set:
    """Pull all e-mail addresses out of arbitrary text."""
    found = set()
    if not text:
        return found
    for m in _EMAIL_RE.findall(text):
        # Skip addresses that are obviously part of JS variable names or
        # placeholder/example strings that scanners love to trip on.
        if m.lower().endswith(('.example.com', '.example.net', '.example.org',
                               '.test', '.local', '.invalid', '.localhost')):
            continue
        found.add(m.lower().replace('&#64;', '@').replace('&commat;', '@')
                  .replace('%40', '@'))
    return found


def _is_role(email: str) -> bool:
    local = email.split('@', 1)[0].lower().replace('.', '').replace('-', '')
    return any(role in local for role in _ROLE_HINTS)


def _is_external(email: str, hostname: str) -> bool:
    dom = email.rsplit('@', 1)[1].lower()
    return not (dom == hostname or dom.endswith('.' + hostname))


# ── Passive sources ──────────────────────────────────────────────────────────
def _query_crtsh(hostname: str, timeout: float = 12.0) -> set:
    """Scan crt.sh JSON output for e-mail SANs embedded in certificates."""
    found = set()
    try:
        r = _http_get(
            f'https://crt.sh/?q=%25.{hostname}&output=json', timeout=timeout)
        if not r or r.status_code != 200:
            return found
        import json
        try:
            entries = r.json()
        except ValueError:
            entries = []
        for entry in entries if isinstance(entries, list) else []:
            blob = ' '.join(str(v) for v in entry.values() if v)
            found |= _extract_from_text(blob, hostname)
    except Exception:
        pass
    return found


def _query_whois(hostname: str) -> set:
    """Registrant / admin / tech contact emails from the registry record."""
    found = set()
    try:
        import whois
        w = whois.whois(hostname)
        for key in ('emails', 'admin_email', 'tech_email', 'registrant_email'):
            val = w.get(key)
            if isinstance(val, str):
                found.add(val.lower())
            elif isinstance(val, (list, tuple)):
                for v in val:
                    if isinstance(v, str):
                        found.add(v.lower())
    except Exception:
        pass
    return found


def _query_search(hostname: str, timeout: float = 12.0) -> set:
    """DuckDuckGo HTML search for indexed e-mail exposures (best-effort)."""
    found = set()
    try:
        r = _http_get(
            'https://html.duckduckgo.com/html/',
            params={'q': f'"@{hostname}"'}, timeout=timeout)
        if not r or r.status_code != 200:
            return found
        found |= _extract_from_text(r.text, hostname)
    except Exception:
        pass
    return found


# ── Infrastructure hints ─────────────────────────────────────────────────────
def _get_mx(hostname: str, timeout: float = 8.0) -> list:
    """Resolve MX records over DNS-over-HTTPS (Google) — zero deps."""
    try:
        r = _http_get(
            'https://dns.google/resolve',
            params={'name': hostname, 'type': 'MX'}, timeout=timeout)
        if not r or r.status_code != 200:
            return []
        import json
        try:
            data = r.json()
        except ValueError:
            return []
        mx = []
        for ans in data.get('Answer', []):
            if ans.get('type') == 15 and ans.get('data'):
                parts = str(ans['data']).split()
                mx.append({'priority': parts[0], 'host': parts[1].rstrip('.')})
        return sorted(mx, key=lambda m: m['priority'])
    except Exception:
        return []


def _http_get(url: str, timeout: float = 10.0, headers: dict = None,
              params: dict = None):
    try:
        if _stealth_session:
            return _stealth_session.get(url, timeout=timeout,
                                        headers=headers or {}, params=params or None)
        return requests.get(url, timeout=timeout, headers=headers or {},
                            params=params or None)
    except Exception:
        return None


# ── Main entry point ─────────────────────────────────────────────────────────
def email_finder(domain: str, timeout: float = 10.0, max_pages: int = 25,
                 use_crawl: bool = True, use_search: bool = True) -> dict:
    """Discover e-mail addresses for a domain across multiple sources."""
    display = extract_hostname(domain)

    section(T("email_finder_title"))
    info(f"Target        : {display}")
    info(f"Sources       : Site Crawl, crt.sh, WHOIS"
         + (", DuckDuckGo" if use_search else ""))
    print()

    hostname = display.lower().rstrip('.')

    found_by_src = {}
    found = {}

    def register(email, source):
        email = email.lower().strip()
        if not email:
            return
        if email not in found:
            found[email] = {'email': email, 'sources': []}
        if source not in found[email]['sources']:
            found[email]['sources'].append(source)
        found_by_src.setdefault(source, set()).add(email)

    # 1. Site crawl (reuses the shared crawler's email extraction)
    if use_crawl:
        info("Crawling target pages for e-mail addresses...")
        try:
            res = crawl_target(
                f'https://{hostname}' if '://' not in domain else domain,
                max_depth=1, max_pages=max_pages)
            crawl_emails = res.get('emails') or []
            for em in crawl_emails:
                register(str(em), 'crawl')
            ok(f"Found {len(crawl_emails)} e-mail(s) from the crawl.")
        except Exception as e:
            warn(f"Site crawl failed: {e}")

    # 2. Certificate Transparency
    info("Querying crt.sh Certificate Transparency logs...")
    try:
        ct = _query_crtsh(hostname, timeout)
        for em in ct:
            register(em, 'crt.sh')
        ok(f"crt.sh returned {len(ct)} e-mail address(es).")
    except Exception as e:
        warn(f"crt.sh query failed: {e}")

    # 3. WHOIS records
    info("Checking WHOIS registrant/contact records...")
    try:
        wh = _query_whois(hostname)
        for em in wh:
            register(em, 'whois')
        ok(f"WHOIS returned {len(wh)} e-mail address(es).")
    except Exception as e:
        warn(f"WHOIS query failed: {e}")

    # 4. DuckDuckGo search
    if use_search:
        info("Searching DuckDuckGo for indexed e-mail exposure...")
        try:
            ddg = _query_search(hostname, timeout)
            for em in ddg:
                register(em, 'search')
            ok(f"DuckDuckGo returned {len(ddg)} e-mail address(es).")
        except Exception as e:
            warn(f"DuckDuckGo search failed: {e}")

    # 5. MX infrastructure hint
    mx = _get_mx(hostname, timeout)
    if mx:
        ok(f"Mail servers present ({len(mx)} MX record(s)).")
    else:
        info("No MX records resolvable — domain may have no e-mail service.")

    result = {
        'domain': hostname,
        'emails': sorted(found.values(), key=lambda e: e['email']),
        'total': len(found),
        'sources': {k: sorted(v) for k, v in found_by_src.items()},
        'mx': mx,
    }

    # ── Display ───────────────────────────────────────────────────────────────
    print()
    divider()
    ok(f"Total unique e-mail addresses discovered: {BR}{G}{len(found)}{RS}\n")

    if found:
        rows = []
        for e in sorted(found.values(), key=lambda x: x['email']):
            mail = e['email']
            role = f"{Y}role{RS}" if _is_role(mail) else f"{DM}—{RS}"
            ext = f"{W}external{RS}" if _is_external(mail, hostname) else f"{G}internal{RS}"
            rows.append((mail, role, ext, ', '.join(e['sources'])))
        print_table(['E-mail', 'Type', 'Scope', 'Found via'], rows)
        roles = sum(1 for e in found.values() if _is_role(e['email']))
        ext_n = sum(1 for e in found.values() if _is_external(e['email'], hostname))
        if roles:
            info(f"{roles} role address(es) — good candidates for phishing/social-"
                 "engineering assessments.")
        if ext_n:
            info(f"{ext_n} external address(es) — likely third-party/partner contacts.")
    else:
        warn("No e-mail addresses discovered. Try source code/JS endpoints "
             "via the crawler, or passive sources may be rate-limited.")

    return result