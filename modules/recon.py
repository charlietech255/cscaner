#!/usr/bin/env python3
"""
CSCAN — Reconnaissance Modules
DNS, WHOIS, Subdomains, GeoIP, Reverse DNS
"""

import socket
import ssl
import json
import time
from urllib.parse import urlparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import os

from modules.stealth import StealthSession

WORDLISTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'wordlists')

# ── Module-level stealth session (configured from cscan.py) ───────────────────
_stealth_session = None

def set_stealth_session(session: StealthSession):
    global _stealth_session
    _stealth_session = session

def _load_wordlist(filename: str) -> list:
    path = os.path.join(WORDLISTS_DIR, filename)
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
    except Exception:
        return []

from modules.ui import (
    section, ok, warn, alert, info, critical, bold, divider,
    print_table, progress_bar, G, R, Y, C, M, W, BR, DM, RS
)

# ── Common subdomains wordlist ────────────────────────────────────────────────
SUBDOMAIN_WORDLIST = _load_wordlist('subdomains.txt')


def extract_hostname(target: str) -> str:
    """Strip protocol and path from a target to get clean hostname."""
    if '://' in target:
        return urlparse(target).hostname or target
    return target.split('/')[0]


# ── DNS Lookup ────────────────────────────────────────────────────────────────
def dns_lookup(target: str) -> dict:
    hostname = extract_hostname(target)
    result = {'hostname': hostname, 'ipv4': [], 'ipv6': [], 'mx': [], 'ns': []}

    section("DNS LOOKUP & IP RESOLVER")
    info(f"Target hostname: {BR}{W}{hostname}{RS}")

    # IPv4
    try:
        info_list = socket.getaddrinfo(hostname, None, socket.AF_INET)
        ips = list(set(r[4][0] for r in info_list))
        result['ipv4'] = ips
        for ip in ips:
            ok(f"IPv4 Address  : {BR}{G}{ip}{RS}")
    except Exception:
        warn("No IPv4 address found.")

    # IPv6
    try:
        info_list = socket.getaddrinfo(hostname, None, socket.AF_INET6)
        ips = list(set(r[4][0] for r in info_list))
        result['ipv6'] = ips
        for ip in ips:
            ok(f"IPv6 Address  : {BR}{C}{ip}{RS}")
    except Exception:
        pass

    # lets jaribu DNS records kupitia public DNS-over-HTTPS (Cloudflare)
    for rtype in ('MX', 'NS'):
        try:
            if _stealth_session:
                r = _stealth_session.get(
                    'https://cloudflare-dns.com/dns-query',
                    params={'name': hostname, 'type': rtype},
                    headers={'Accept': 'application/dns-json'},
                    timeout=5
                )
            else:
                r = requests.get(
                    'https://cloudflare-dns.com/dns-query',
                    params={'name': hostname, 'type': rtype},
                    headers={'Accept': 'application/dns-json'},
                    timeout=5
                )
            data = r.json()
            answers = [a['data'] for a in data.get('Answer', [])]
            result[rtype.lower()] = answers
            for rec in answers:
                info(f"{rtype:<4} Record    : {W}{rec}{RS}")
        except Exception:
            pass

    if not result['ipv4']:
        alert(f"Could not resolve {hostname}")

    return result


# ── WHOIS ─────────────────────────────────────────────────────────────────────
def whois_lookup(target: str) -> dict:
    section("WHOIS DOMAIN INTELLIGENCE")
    hostname = extract_hostname(target)
    info(f"Querying WHOIS for: {BR}{W}{hostname}{RS}")

    try:
        import whois
        w = whois.whois(hostname)
        fields = {
            'Domain Name':    w.domain_name,
            'Registrar':      w.registrar,
            'Creation Date':  w.creation_date,
            'Expiry Date':    w.expiration_date,
            'Updated Date':   w.updated_date,
            'Name Servers':   w.name_servers,
            'Status':         w.status,
            'Emails':         w.emails,
            'Org':            w.org,
            'Country':        w.country,
        }
        rows = []
        for k, v in fields.items():
            if v:
                val = ', '.join(v) if isinstance(v, list) else str(v).split('\n')[0]
                rows.append((k, val[:60]))
                print(f"  {DM}{C}{'·' * 2}{RS}  {BR}{Y}{k:<16}{RS}  {W}{val[:60]}{RS}")
        return fields
    except ImportError:
        alert("python-whois not installed. Run: pip install python-whois")
        return {}
    except Exception as e:
        alert(f"WHOIS query failed: {e}")
        return {}


def _crtsh_subdomains(domain: str) -> list:
    """
    FIX #7: Query crt.sh Certificate Transparency logs for passively known subdomains.
    Returns a list of unique FQDNs found in issued certificates.
    """
    try:
        r = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=12,
            headers={'User-Agent': 'Mozilla/5.0 (compatible; CSCAN/2.1)'},
        )
        if r.status_code != 200:
            return []
        entries = r.json()
        names = set()
        for entry in entries:
            raw = entry.get('name_value', '')
            for n in raw.split('\n'):
                n = n.strip().lstrip('*.')
                if n and n.endswith(domain) and n != domain:
                    names.add(n.lower())
        return sorted(names)
    except Exception:
        return []


def _detect_wildcard(domain: str) -> str | None:
    """
    FIX #7: Detect wildcard DNS by resolving a random unlikely subdomain.
    Returns the wildcard IP if one exists, else None.
    """
    import random, string
    probe = ''.join(random.choices(string.ascii_lowercase, k=16)) + '.' + domain
    try:
        return socket.gethostbyname(probe)
    except Exception:
        return None


# ── Subdomain Enumerator ──────────────────────────────────────────────────────
def subdomain_enum(target: str, wordlist: list = None, workers: int = 30) -> list:
    section("SUBDOMAIN ENUMERATOR")
    hostname = extract_hostname(target)
    if hostname.startswith('www.'):
        hostname = hostname[4:]

    wl = wordlist or SUBDOMAIN_WORDLIST
    info(f"Base domain   : {BR}{W}{hostname}{RS}")
    info(f"Wordlist size : {BR}{W}{len(wl)}{RS} subdomains")

    # ── FIX #7: Wildcard detection ────────────────────────────────────────────
    info("Checking for wildcard DNS...")
    wildcard_ip = _detect_wildcard(hostname)
    if wildcard_ip:
        warn(f"Wildcard DNS detected! All subdomains resolve to {BR}{Y}{wildcard_ip}{RS}")
        warn("Wordlist bruteforce results will be UNRELIABLE — skipping DNS phase.")
        warn("Relying on Certificate Transparency logs only.")
    else:
        ok("No wildcard DNS — bruteforce results will be accurate.")
    print()

    found = []
    lock  = __import__('threading').Lock()

    # ── Phase 1: wordlist DNS bruteforce (skip if wildcard detected) ───────────
    if not wildcard_ip:
        info(f"Phase 1/2 — DNS bruteforce ({len(wl)} entries)...\n")

        def check_sub(sub):
            fqdn = f"{sub}.{hostname}"
            try:
                ip = socket.gethostbyname(fqdn)
                with lock:
                    found.append((fqdn, ip))
                    print(f"  {BR}{G}[FOUND]{RS}  {BR}{W}{fqdn:<40}{RS}  {G}{ip}{RS}")
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = [ex.submit(check_sub, s) for s in wl]
            for i, _ in enumerate(as_completed(futures), 1):
                progress_bar(i, len(wl), 'DNS bruteforce')
        print()
    else:
        info("Phase 1/2 — DNS bruteforce skipped (wildcard active).")

    # ── Phase 2: Certificate Transparency (crt.sh) passive lookup ──────────
    info(f"Phase 2/2 — Certificate Transparency logs (crt.sh)...")
    ct_names = _crtsh_subdomains(hostname)
    if ct_names:
        ok(f"crt.sh returned {len(ct_names)} certificate entry(ies).")
        existing_fqdns = {f for f, _ in found}
        ct_new = 0
        for fqdn in ct_names:
            if fqdn in existing_fqdns:
                continue
            try:
                ip = socket.gethostbyname(fqdn)
                found.append((fqdn, ip))
                existing_fqdns.add(fqdn)
                print(f"  {BR}{M}[CT-LOG]{RS} {BR}{W}{fqdn:<40}{RS}  {G}{ip}{RS}")
                ct_new += 1
            except Exception:
                # Still report the name even if it doesn't currently resolve
                found.append((fqdn, 'unresolved'))
                existing_fqdns.add(fqdn)
                print(f"  {BR}{Y}[CT-LOG]{RS} {DM}{fqdn:<40}  (does not resolve currently){RS}")
                ct_new += 1
        ok(f"CT logs added {ct_new} unique subdomain(s).")
    else:
        warn("crt.sh returned no results (API may be rate-limited or domain is new).")

    print()
    if found:
        ok(f"Total: {len(found)} subdomain(s) discovered.")
    else:
        warn("No subdomains discovered.")
    return found


# ── GeoIP ─────────────────────────────────────────────────────────────────────
# Known Cloudflare AS numbers — GeoIP on these returns CF's infra, not origin
_CLOUDFLARE_ASN = {'AS13335', 'AS209242'}

def _find_origin_ips_via_mx(hostname: str) -> list:
    """Attempt to find the real origin IP of a domain hidden behind Cloudflare via MX records."""
    import socket
    import requests
    
    potential_ips = set()
    try:
        r = requests.get(
            'https://cloudflare-dns.com/dns-query',
            params={'name': hostname, 'type': 'MX'},
            headers={'Accept': 'application/dns-json'},
            timeout=5
        )
        data = r.json()
        answers = [a['data'] for a in data.get('Answer', [])]
        for rec in answers:
            parts = rec.split()
            mx_domain = parts[1].strip('.') if len(parts) >= 2 else rec.strip('.')
            try:
                potential_ips.add(socket.gethostbyname(mx_domain))
            except Exception:
                pass
    except Exception:
        pass
    
    return list(potential_ips)


def geoip_lookup(target: str) -> dict:
    section("GEOIP & LOCATION TRACKER")
    hostname = extract_hostname(target)

    # Resolve to IP first
    try:
        ip = socket.gethostbyname(hostname)
    except Exception:
        ip = hostname  # pass an IP directly

    info(f"Looking up: {BR}{W}{ip}{RS}\n")

    try:
        # ip-api.com free tier requires HTTP (HTTPS returns 403)
        if _stealth_session:
            r = _stealth_session.get(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=8)
        else:
            r = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=8)
        d = r.json()
        if d.get('status') == 'success':
            # Detect Cloudflare edge IP
            asn = d.get('as', '')
            is_cf_edge = any(cf in asn for cf in _CLOUDFLARE_ASN)
            if is_cf_edge:
                warn(f"This IP ({ip}) belongs to {BR}{Y}Cloudflare ({asn}){RS}")
                warn("GeoIP shows Cloudflare's network location, NOT the origin server.")
                
                info("Auto-investigating MX records to find potential real origin IP...")
                origin_ips = _find_origin_ips_via_mx(hostname)
                if origin_ips:
                    ok("Found potential origin IPs bypassing Cloudflare via MX:")
                    for oip in origin_ips:
                        print(f"  {BR}{M}◈{RS}  {BR}{R}{oip}{RS}")
                    d['potential_origin_ips'] = origin_ips
                else:
                    warn("Could not discover origin IP via MX records.")
                print()

            rows = [
                ('IP Address',   d.get('query',       'N/A')),
                ('Country',      d.get('country',     'N/A')),
                ('Region',       d.get('regionName',  'N/A')),
                ('City',         d.get('city',        'N/A')),
                ('ZIP Code',     d.get('zip',         'N/A')),
                ('Latitude',     d.get('lat',         'N/A')),
                ('Longitude',    d.get('lon',         'N/A')),
                ('Timezone',     d.get('timezone',    'N/A')),
                ('ISP',          d.get('isp',         'N/A')),
                ('Organization', d.get('org',         'N/A')),
                ('ASN',          asn),
                ('Mobile?',      d.get('mobile',      'N/A')),
                ('Proxy/VPN?',   d.get('proxy',       'N/A')),
            ]
            for label, val in rows:
                colour = R if str(val) == 'True' else (Y if is_cf_edge and label == 'ASN' else W)
                print(f"  {DM}{C}◈{RS}  {BR}{Y}{label:<14}{RS}  {colour}{val}{RS}")
            return d
        else:
            warn(f"GeoIP API returned: {d.get('message', 'unknown error')}")
    except Exception as e:
        alert(f"GeoIP lookup failed: {e}")
    return {}


# ── Reverse DNS ───────────────────────────────────────────────────────────────
def reverse_dns(target: str) -> str:
    section("REVERSE DNS LOOKUP")
    hostname = extract_hostname(target)
    try:
        ip = socket.gethostbyname(hostname)
    except Exception:
        ip = hostname

    info(f"Input IP/Host : {BR}{W}{ip}{RS}")
    try:
        rev = socket.gethostbyaddr(ip)
        ok(f"Reverse PTR   : {BR}{G}{rev[0]}{RS}")
        if rev[1]:
            info(f"Aliases       : {', '.join(rev[1])}")
        return rev[0]
    except socket.herror:
        warn("No reverse DNS record found for this IP.")
    except Exception as e:
        alert(f"Reverse DNS failed: {e}")
    return ''
