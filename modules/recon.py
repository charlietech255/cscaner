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


# ── Subdomain Enumerator ──────────────────────────────────────────────────────
def subdomain_enum(target: str, wordlist: list = None, workers: int = 30) -> list:
    section("SUBDOMAIN ENUMERATOR")
    hostname = extract_hostname(target)
    if hostname.startswith('www.'):
        hostname = hostname[4:]

    wl = wordlist or SUBDOMAIN_WORDLIST
    info(f"Base domain   : {BR}{W}{hostname}{RS}")
    info(f"Wordlist size : {BR}{W}{len(wl)}{RS} subdomains\n")

    found = []
    lock  = __import__('threading').Lock()

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
            progress_bar(i, len(wl), 'scanning subdomains')

    print()
    if found:
        ok(f"Found {len(found)} subdomain(s).")
    else:
        warn("No subdomains discovered.")
    return found


# ── GeoIP ─────────────────────────────────────────────────────────────────────
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
        if _stealth_session:
            r = _stealth_session.get(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=8)
        else:
            r = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=8)
        d = r.json()
        if d.get('status') == 'success':
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
                ('ASN',          d.get('as',          'N/A')),
                ('Mobile?',      d.get('mobile',      'N/A')),
                ('Proxy/VPN?',   d.get('proxy',       'N/A')),
            ]
            for label, val in rows:
                colour = R if str(val) == 'True' else W
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
