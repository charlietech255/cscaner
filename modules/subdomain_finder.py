#!/usr/bin/env python3
"""
CSCAN — Deep Subdomain Finder
=============================
Combines multiple discovery techniques into one dedicated module:

  1. Wordlist DNS brute force (disabled automatically on wildcard DNS)
  2. Certificate Transparency logs (crt.sh)
  3. Rapiddns.io passive DNS
  4. HackerTarget hostsearch API
  5. AlienVault OTX passive DNS

Every discovered host is resolved and Cloudflare-fronted hosts are flagged.
"""

import os
import re
import socket
import threading
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from modules.stealth import StealthSession
from modules.ui import (
    section, ok, warn, alert, info, divider, print_table,
    progress_bar, G, R, Y, C, M, W, BR, DM, RS
)

WORDLISTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'wordlists')

_IP_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')

# ── Module-level stealth session (configured from cscan.py) ───────────────────
_stealth_session = None

def set_stealth_session(session: StealthSession):
    global _stealth_session
    _stealth_session = session


def extract_hostname(target: str) -> str:
    if '://' in target:
        return urlparse(target).hostname or target
    return target.split('/')[0]


def _http_get(url: str, timeout: float = 10.0, headers: dict = None):
    try:
        if _stealth_session:
            return _stealth_session.get(url, timeout=timeout, headers=headers or {})
        return requests.get(url, timeout=timeout, headers=headers or {})
    except Exception:
        return None


# ── Wildcard detection ────────────────────────────────────────────────────────
def detect_wildcard(domain: str) -> str | None:
    import random
    import string
    probe = ''.join(random.choices(string.ascii_lowercase, k=16)) + '.' + domain
    try:
        return socket.gethostbyname(probe)
    except Exception:
        return None


def _resolve(name: str):
    try:
        return socket.gethostbyname(name)
    except Exception:
        return 'unresolved'


def _is_cloudflare(ip: str) -> bool:
    try:
        from modules.osnit_origin_ip import _is_cloudflare_ip
        return bool(ip and ip != 'unresolved' and _is_cloudflare_ip(ip))
    except ImportError:
        return False


# ── Passive source parsers (pure, testable) ──────────────────────────────────
def _parse_crtsh(data: list, domain: str) -> list:
    """crt.sh JSON output → unique FQDNs."""
    names = set()
    for entry in data or []:
        raw = (entry or {}).get('name_value', '')
        for n in str(raw).split('\n'):
            n = n.strip().lstrip('*.').lower()
            if n and n.endswith('.' + domain) and n != domain:
                names.add(n)
    return sorted(names)


def _parse_rapiddns(html: str, domain: str) -> list:
    """Rapiddns.io HTML page → unique FQDNs."""
    names = set()
    pattern = re.compile(
        r'[a-z0-9](?:[a-z0-9._\-]*[a-z0-9])?\.' + re.escape(domain.lower()) + r'\b'
    )
    for m in pattern.finditer(html.lower()):
        n = m.group(0).rstrip('.')
        if n.endswith('.' + domain) and n != domain:
            names.add(n)
    return sorted(names)


def _parse_hackertarget(text: str, domain: str) -> tuple:
    """HackerTarget hostsearch CSV → (names, {name: ip})."""
    names = set()
    ips = {}
    for line in str(text).splitlines():
        line = line.strip()
        if not line or ',' not in line:
            continue
        name, _, ip = line.partition(',')
        name = name.strip().lower()
        ip = ip.strip()
        if (name.endswith('.' + domain) and name != domain and _IP_RE.match(ip)):
            names.add(name)
            ips.setdefault(name, ip)
    return sorted(names), ips


def _parse_otx(data: dict, domain: str) -> list:
    """AlienVault OTX passive_dns JSON → unique FQDNs."""
    names = set()
    for rec in (data or {}).get('passive_dns') or []:
        host = str((rec or {}).get('hostname', '')).strip().lower().rstrip('.')
        if host and host.endswith('.' + domain) and host != domain:
            names.add(host)
    return sorted(names)


# ── Passive source queries ───────────────────────────────────────────────────
def _query_crtsh(domain: str, timeout: float = 12.0) -> list:
    r = _http_get(
        f"https://crt.sh/?q=%25.{domain}&output=json",
        timeout=timeout,
        headers={'User-Agent': 'Mozilla/5.0 (compatible; CSCAN/2.2)'},
    )
    if r is not None and r.status_code == 200:
        try:
            return _parse_crtsh(r.json(), domain)
        except (ValueError, TypeError):
            pass
    return []


def _query_rapiddns(domain: str, timeout: float = 12.0) -> list:
    r = _http_get(
        f"https://rapiddns.io/subdomain/{domain}?full=1",
        timeout=timeout,
        headers={'User-Agent': 'Mozilla/5.0 (compatible; CSCAN/2.2)'},
    )
    if r is not None and r.status_code == 200:
        return _parse_rapiddns(r.text, domain)
    return []


def _query_hackertarget(domain: str, timeout: float = 12.0) -> tuple:
    r = _http_get(
        f"https://api.hackertarget.com/hostsearch/?q={domain}",
        timeout=timeout,
        headers={'User-Agent': 'Mozilla/5.0 (compatible; CSCAN/2.2)'},
    )
    if r is not None and r.status_code == 200:
        return _parse_hackertarget(r.text, domain)
    return [], {}


def _query_otx(domain: str, timeout: float = 12.0) -> list:
    r = _http_get(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
        timeout=timeout,
        headers={'Accept': 'application/json'},
    )
    if r is not None and r.status_code == 200:
        try:
            return _parse_otx(r.json(), domain)
        except (ValueError, TypeError):
            pass
    return []


# ── Active brute force ───────────────────────────────────────────────────────
def _bruteforce_dns(domain: str, wordlist: list, workers: int = 30) -> list:
    found = []
    lock = threading.Lock()

    def check(sub):
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
        except Exception:
            return
        with lock:
            found.append((fqdn, ip))

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(check, s) for s in wordlist]
        for i, _ in enumerate(as_completed(futures), 1):
            progress_bar(i, len(wordlist), 'DNS bruteforce')
    print()
    return found


# ── Orchestrator ─────────────────────────────────────────────────────────────
def deep_subdomain_finder(
    target: str,
    wordlist: list = None,
    workers: int = 30,
    timeout: float = 10.0,
) -> dict:
    hostname = extract_hostname(target)
    if hostname.startswith('www.'):
        hostname = hostname[4:]

    section("DEEP SUBDOMAIN FINDER")
    info(f"Base domain   : {BR}{W}{hostname}{RS}")
    info(f"Sources       : crt.sh, Rapiddns, HackerTarget, AlienVault OTX, DNS bruteforce")

    wildcard_ip = detect_wildcard(hostname)
    if wildcard_ip:
        warn(f"Wildcard DNS detected ({BR}{Y}{wildcard_ip}{RS}) — decreasing confidence."
             " Wordlist bruteforce skipped; passive sources still queried.")
    else:
        ok("No wildcard DNS — results will be accurate.")

    print()
    sources = {
        'crt.sh': [],
        'rapiddns': [],
        'hackertarget': [],
        'alienvault': [],
        'bruteforce': [],
    }
    found_by_name = {}

    def register(name, source, ip=None):
        name = name.lower().rstrip('.')
        if name.endswith('.' + hostname) and name != hostname:
            if name not in found_by_name:
                found_by_name[name] = {'name': name, 'ip': ip, 'sources': []}
            if source not in found_by_name[name]['sources']:
                found_by_name[name]['sources'].append(source)

    # 1. Certificate Transparency
    info("Querying crt.sh Certificate Transparency logs...")
    try:
        ct = _query_crtsh(hostname, timeout)
        for n in ct:
            register(n, 'crt.sh')
        sources['crt.sh'] = ct
        ok(f"crt.sh returned {len(ct)} hostname(s).")
    except Exception as e:
        warn(f"crt.sh query failed: {e}")

    # 2. Rapiddns
    info("Querying Rapiddns.io passive DNS...")
    try:
        rd = _query_rapiddns(hostname, timeout)
        for n in rd:
            register(n, 'rapiddns')
        sources['rapiddns'] = rd
        ok(f"Rapiddns returned {len(rd)} hostname(s).")
    except Exception as e:
        warn(f"Rapiddns query failed: {e}")

    # 3. HackerTarget
    info("Querying HackerTarget hostsearch...")
    try:
        ht_names, ht_ips = _query_hackertarget(hostname, timeout)
        for n in ht_names:
            register(n, 'hackertarget', ip=ht_ips.get(n))
        sources['hackertarget'] = ht_names
        ok(f"HackerTarget returned {len(ht_names)} hostname(s).")
    except Exception as e:
        warn(f"HackerTarget query failed: {e}")

    # 4. AlienVault OTX
    info("Querying AlienVault OTX passive DNS...")
    try:
        otx = _query_otx(hostname, timeout)
        for n in otx:
            register(n, 'alienvault')
        sources['alienvault'] = otx
        ok(f"AlienVault OTX returned {len(otx)} hostname(s).")
    except Exception as e:
        warn(f"AlienVault OTX query failed: {e}")

    # 5. Wordlist brute force (skip when wildcard DNS is active)
    if not wildcard_ip and wordlist:
        info(f"Running DNS bruteforce over {len(wordlist)} entries...")
        for fqdn, ip in _bruteforce_dns(hostname, wordlist, workers):
            register(fqdn, 'bruteforce', ip=ip)
        sources['bruteforce'] = sorted(
            n for n, rec in found_by_name.items() if 'bruteforce' in rec['sources']
        )
        ok("Bruteforce phase complete.")
    elif not wordlist:
        warn("No wordlist provided — skipping DNS bruteforce.")

    # Resolve any host without an IP yet
    for name, rec in found_by_name.items():
        if not rec['ip']:
            rec['ip'] = _resolve(name)

    # Build final ordered list with Cloudflare flags
    subdomains = []
    for name in sorted(found_by_name):
        rec = found_by_name[name]
        subdomains.append({
            'name': rec['name'],
            'ip': rec['ip'],
            'cloudflare': _is_cloudflare(rec['ip']),
            'sources': rec['sources'],
        })

    result = {
        'domain': hostname,
        'wildcard_ip': wildcard_ip,
        'sources': sources,
        'subdomains': subdomains,
        'total': len(subdomains),
    }

    # ── Display ───────────────────────────────────────────────────────────────
    print()
    divider()
    ok(f"Total unique subdomains discovered: {BR}{G}{len(subdomains)}{RS}\n")

    if subdomains:
        rows = []
        for s in subdomains:
            cf = f"{Y}[CF]{RS}" if s['cloudflare'] else ""
            rows.append((s['name'], s['ip'], cf,
                         ', '.join(sorted(set(s['sources'])))))
        print_table(['Subdomain', 'IP', 'CF?', 'Found via'], rows)
        cf_count = sum(1 for s in subdomains if s['cloudflare'])
        if cf_count:
            info(f"{cf_count} subdomain(s) resolve behind Cloudflare — run Origin IP"
                 " Discovery (option 47) to uncloak their real servers.")
    else:
        warn("No subdomains discovered. The domain may be new, well-protected,"
             " or the passive sources are rate-limited.")

    if wildcard_ip:
        warn(f"Wildcard DNS ({wildcard_ip}) present — brute-force results are unreliable.")

    return result