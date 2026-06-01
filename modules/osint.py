#!/usr/bin/env python3
"""
CSCAN — OSINT & Passive Recon Module
Gathers intelligence WITHOUT touching the target directly:
  - Shodan host lookup (requires free API key)
  - Wayback Machine endpoint discovery
  - GitHub public repo / secret dork
  - Email harvesting from domain (whois + DNS + web)
  - HaveIBeenPwned domain breach check
"""

import re
import json
import time
import socket
import urllib.parse
from datetime import datetime

import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from modules.ui import (
    section, ok, warn, alert, info, critical, divider,
    G, R, Y, C, M, W, BR, DM, RS
)

TIMEOUT = 10
_UA = 'Mozilla/5.0 (compatible; CSCAN/2.2; +https://github.com/cscan)'


def _get(url, params=None, headers=None, timeout=TIMEOUT) -> requests.Response | None:
    h = {'User-Agent': _UA}
    if headers:
        h.update(headers)
    try:
        return requests.get(url, params=params, headers=h, timeout=timeout, verify=False)
    except Exception:
        return None


def _extract_hostname(target: str) -> str:
    return target.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]


def _extract_domain(hostname: str) -> str:
    """Strip subdomains: api.example.com → example.com"""
    parts = hostname.split('.')
    return '.'.join(parts[-2:]) if len(parts) >= 2 else hostname


# ── Shodan ───────────────────────────────────────────────────────────────────
def shodan_lookup(target: str, api_key: str) -> dict:
    section("SHODAN HOST INTELLIGENCE")

    if not api_key:
        warn("No Shodan API key provided. Get a free one at https://account.shodan.io")
        return {}

    hostname = _extract_hostname(target)
    try:
        ip = socket.gethostbyname(hostname)
    except Exception:
        ip = hostname

    info(f"Querying Shodan for: {BR}{W}{ip}{RS}")

    r = _get(f'https://api.shodan.io/shodan/host/{ip}', params={'key': api_key})
    if r is None or r.status_code != 200:
        err = r.json().get('error', 'Unknown error') if r else 'No response'
        warn(f"Shodan lookup failed: {err}")
        return {}

    d = r.json()

    # Display key fields
    print()
    info(f"Organization  : {BR}{W}{d.get('org', 'N/A')}{RS}")
    info(f"ISP           : {BR}{W}{d.get('isp', 'N/A')}{RS}")
    info(f"Country       : {BR}{W}{d.get('country_name', 'N/A')}{RS}")
    info(f"OS            : {BR}{W}{d.get('os', 'Unknown')}{RS}")
    info(f"Last Update   : {BR}{W}{d.get('last_update', 'N/A')[:10]}{RS}")

    ports  = d.get('ports', [])
    vulns  = d.get('vulns', [])
    tags   = d.get('tags', [])
    hostnames = d.get('hostnames', [])

    if ports:
        ok(f"Open Ports (Shodan): {', '.join(str(p) for p in ports)}")
    if hostnames:
        info(f"Hostnames     : {', '.join(hostnames[:5])}")
    if tags:
        info(f"Tags          : {', '.join(tags)}")

    if vulns:
        critical(f"Shodan reports {len(vulns)} known CVE(s) for this host!")
        for v in list(vulns)[:10]:
            print(f"  {BR}{R}◆{RS}  {v}")
    else:
        ok("No CVEs reported by Shodan for this host.")

    # Service banners
    for svc in d.get('data', [])[:5]:
        port = svc.get('port', '?')
        transport = svc.get('transport', 'tcp')
        banner = svc.get('data', '').strip()[:80]
        prod   = svc.get('product', '')
        ver    = svc.get('version', '')
        print(f"\n  {BR}{C}{port}/{transport}{RS}  {W}{prod} {ver}{RS}")
        if banner:
            print(f"    {DM}{banner}{RS}")

    return {
        'ip': ip, 'org': d.get('org'), 'ports': ports,
        'vulns': list(vulns), 'hostnames': hostnames,
    }


# ── Wayback Machine ──────────────────────────────────────────────────────────
def wayback_endpoints(target: str, max_urls: int = 50) -> list:
    section("WAYBACK MACHINE ENDPOINT DISCOVERY")
    hostname = _extract_hostname(target)
    info(f"Querying archive.org for: {BR}{W}{hostname}{RS}")
    info("This reveals old endpoints that may still be active or expose info.\n")

    # CDX API — returns all crawled URLs
    r = _get(
        'http://web.archive.org/cdx/search/cdx',
        params={
            'url':     f'{hostname}/*',
            'output':  'json',
            'fl':      'original,statuscode,timestamp',
            'collapse': 'urlkey',
            'limit':   str(max_urls),
            'filter':  'statuscode:200',
        }
    )

    if r is None or r.status_code != 200:
        warn("Wayback Machine query failed or no results.")
        return []

    try:
        data = r.json()
    except Exception:
        warn("Could not parse Wayback Machine response.")
        return []

    if len(data) <= 1:
        warn("No archived URLs found for this domain.")
        return []

    urls = []
    interesting_patterns = re.compile(
        r'\.(php|asp|aspx|jsp|env|sql|bak|log|conf|config|json|xml|txt|zip|tar|gz|sh|py)$'
        r'|/(admin|api|backup|config|debug|test|dev|staging|internal|private)',
        re.I
    )

    for row in data[1:]:  # skip header row
        url_str, status, ts = row[0], row[1], row[2]
        urls.append(url_str)
        if interesting_patterns.search(url_str):
            date = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
            print(f"  {BR}{Y}[INTERESTING]{RS}  {W}{url_str}{RS}  {DM}({date}){RS}")

    ok(f"Found {len(urls)} archived URL(s). Interesting paths highlighted above.")
    info("Check these URLs — some may still be live on the current server.")
    return urls


# ── GitHub Secret Dork ────────────────────────────────────────────────────────
def github_dork(domain: str, github_token: str = None) -> list:
    section("GITHUB PUBLIC REPO SECRET SEARCH")
    info(f"Searching GitHub for mentions of: {BR}{W}{domain}{RS}")
    warn("Results are from PUBLIC repositories only — no private repo access.\n")

    headers = {'Accept': 'application/vnd.github.v3+json'}
    if github_token:
        headers['Authorization'] = f'token {github_token}'

    queries = [
        f'"{domain}" password',
        f'"{domain}" secret',
        f'"{domain}" api_key',
        f'"{domain}" token',
        f'"{domain}" db_password',
    ]

    findings = []
    for query in queries[:3]:  # limit to avoid rate-limit
        r = _get(
            'https://api.github.com/search/code',
            params={'q': query, 'per_page': 5},
            headers=headers,
        )
        if r is None:
            continue
        if r.status_code == 403:
            warn("GitHub rate limit hit. Provide a GitHub token for more requests.")
            break
        if r.status_code != 200:
            continue

        data = r.json()
        items = data.get('items', [])
        for item in items:
            repo = item.get('repository', {}).get('full_name', 'unknown')
            path = item.get('path', '')
            html = item.get('html_url', '')
            findings.append({'repo': repo, 'path': path, 'url': html, 'query': query})
            alert(f"GitHub match: {BR}{R}{repo}/{path}{RS}")
            print(f"         {DM}{html}{RS}")

        time.sleep(0.5)  # GitHub rate limit

    if not findings:
        ok("No obvious secret leaks found in public GitHub repos.")
    else:
        critical(f"{len(findings)} potential leak(s) in public GitHub repos — review immediately!")

    return findings


# ── Email Harvesting ─────────────────────────────────────────────────────────
_EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')


def email_harvest(target: str) -> list:
    section("EMAIL ADDRESS HARVESTER")
    hostname = _extract_hostname(target)
    domain   = _extract_domain(hostname)
    info(f"Harvesting emails for: {BR}{W}{domain}{RS}\n")

    emails = set()

    # Source 1: WHOIS
    info("Checking WHOIS records…")
    try:
        import whois
        w = whois.whois(domain)
        raw = str(w)
        found = _EMAIL_RE.findall(raw)
        emails.update(found)
        if found:
            ok(f"WHOIS: found {len(found)} email(s)")
    except Exception:
        pass

    # Source 2: DNS SOA record (admin email)
    info("Checking DNS SOA record…")
    try:
        r = requests.get(
            'https://cloudflare-dns.com/dns-query',
            params={'name': domain, 'type': 'SOA'},
            headers={'Accept': 'application/dns-json'}, timeout=5
        )
        for ans in r.json().get('Answer', []):
            data = ans.get('data', '')
            # SOA admin email is 2nd field, dots replaced by @
            parts = data.split()
            if len(parts) >= 2:
                raw_email = parts[1].rstrip('.')
                # SOA: "admin.example.com" → "admin@example.com"
                email = raw_email.replace('.', '@', 1)
                if '@' in email:
                    emails.add(email)
    except Exception:
        pass

    # Source 3: Homepage scrape
    info("Scraping homepage for email addresses…")
    base = f'https://{hostname}'
    r = _get(base)
    if r:
        found = _EMAIL_RE.findall(r.text)
        emails.update(found)

    # Filter out common non-real emails
    filtered = {e for e in emails if not any(x in e.lower() for x in
                ['example.com', 'test.com', 'noreply', 'no-reply', 'donotreply'])}

    print()
    if filtered:
        ok(f"Found {len(filtered)} email address(es):")
        for email in sorted(filtered):
            print(f"  {BR}{G}◆{RS}  {W}{email}{RS}")
        info("These may be used for spear-phishing or credential stuffing awareness.")
    else:
        ok("No email addresses found in public sources.")

    return list(filtered)


# ── HaveIBeenPwned domain check ───────────────────────────────────────────────
def hibp_domain_check(domain: str, hibp_key: str = None) -> list:
    """
    Check if the domain appears in HIBP breach data.
    Requires a HIBP API key (https://haveibeenpwned.com/API/Key).
    """
    section("HAVEIBEENPWNED DOMAIN BREACH CHECK")

    if not hibp_key:
        warn("HIBP API key not provided — skipping breach check.")
        info("Get a key at: https://haveibeenpwned.com/API/Key")
        return []

    info(f"Checking breach database for: {BR}{W}{domain}{RS}")

    r = _get(
        f'https://haveibeenpwned.com/api/v3/breachesforaccount/{domain}',
        headers={'hibp-api-key': hibp_key, 'user-agent': 'CSCAN-Security-Scanner'}
    )

    if r is None:
        warn("HIBP request failed.")
        return []

    if r.status_code == 404:
        ok(f"Domain '{domain}' not found in any known breach.")
        return []

    if r.status_code == 401:
        warn("HIBP API key invalid or expired.")
        return []

    if r.status_code != 200:
        warn(f"HIBP returned HTTP {r.status_code}.")
        return []

    breaches = r.json()
    if breaches:
        critical(f"Domain appears in {len(breaches)} breach(es)!")
        for b in breaches:
            name = b.get('Name', 'Unknown')
            date = b.get('BreachDate', 'N/A')
            count = b.get('PwnCount', 0)
            classes = ', '.join(b.get('DataClasses', [])[:4])
            print(f"  {BR}{R}◆{RS}  {W}{name}{RS}  {DM}({date}, {count:,} accounts){RS}")
            print(f"         {DM}Data:{RS} {classes}")
    else:
        ok("No breaches found for this domain.")

    return breaches


# ── Master OSINT function ─────────────────────────────────────────────────────
def osint_recon(target: str, shodan_key: str = None, github_token: str = None,
                hibp_key: str = None) -> dict:
    """Run all passive OSINT checks."""
    section("PASSIVE OSINT RECON SUITE")
    hostname = _extract_hostname(target)
    domain   = _extract_domain(hostname)
    warn("All checks below are PASSIVE — no direct connection to target.\n")

    results = {}

    if shodan_key:
        results['shodan'] = shodan_lookup(target, shodan_key)
    else:
        info("Shodan skipped (no API key). Add one in session config.")

    results['wayback']  = wayback_endpoints(target)
    results['github']   = github_dork(domain, github_token)
    results['emails']   = email_harvest(target)

    if hibp_key:
        results['hibp'] = hibp_domain_check(domain, hibp_key)
    else:
        info("HIBP breach check skipped (no API key).")

    return results


# ── Interactive menu ──────────────────────────────────────────────────────────
def menu_osint(session: dict) -> dict:
    section("OSINT — CONFIGURE API KEYS")
    info("Keys are optional. Leave blank to skip that source.\n")

    shodan  = input(f"  {BR}{W}Shodan API Key  (https://account.shodan.io)  : {RS}").strip() or None
    github  = input(f"  {BR}{W}GitHub Token    (optional, for higher limits) : {RS}").strip() or None
    hibp    = input(f"  {BR}{W}HIBP API Key    (https://haveibeenpwned.com)  : {RS}").strip() or None

    target  = session.get('target')
    if not target:
        warn("No target set — use 'T' to set a target first.")
        return {}

    return osint_recon(target, shodan_key=shodan, github_token=github, hibp_key=hibp)
