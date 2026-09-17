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

    # If any resolved IP is a Cloudflare/WAF fronting IP, also find and show
    # the real origin IP.
    if result.get('ipv4'):
        try:
            from modules.osnit_origin_ip import maybe_show_origin, _is_cloudflare_ip
            has_cf = any(_is_cloudflare_ip(ip) for ip in result['ipv4'])
            if has_cf:
                print()
                info(f"{BR}{Y}Cloudflare/WAF IP detected — searching for the real origin IP...{RS}")
                origin_report = maybe_show_origin(hostname)
                if origin_report:
                    result['origin_ip'] = origin_report
        except ImportError:
            pass

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
                # python-whois returns datetimes and lists of datetimes for some fields
                if isinstance(v, (list, tuple)):
                    vals = []
                    for item in v:
                        vals.append(str(item).split('\n')[0][:60])
                    val = ', '.join(vals)
                else:
                    val = str(v).split('\n')[0][:60]
                rows.append((k, val))
                print(f"  {DM}{C}{'·' * 2}{RS}  {BR}{Y}{k:<16}{RS}  {W}{val}{RS}")
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

    # Flag subdomains that resolve behind Cloudflare and, where possible,
    # reveal the origin IP for those subdomains.
    try:
        from modules.osnit_origin_ip import maybe_show_origin, _is_cloudflare_ip
    except ImportError:
        maybe_show_origin, _is_cloudflare_ip = None, None

    cf_subdomains = []
    if found and _is_cloudflare_ip is not None:
        for fqdn, ip in found:
            if isinstance(ip, str) and ip != 'unresolved' and _is_cloudflare_ip(ip):
                cf_subdomains.append((fqdn, ip))
    if cf_subdomains:
        print()
        divider()
        info(f"{BR}{Y}{len(cf_subdomains)} subdomain(s) resolve behind Cloudflare/WAF:{RS}")
        for fqdn, ip in cf_subdomains[:4]:
            print(f"  {BR}{Y}◈{RS}  {W}{fqdn:<40}{RS}  {Y}{ip}{RS}  {DM}(Cloudflare edge){RS}")
            if maybe_show_origin is not None:
                maybe_show_origin(fqdn)
        if len(cf_subdomains) > 4:
            info(f"{DM}Origin lookup run for the first 4 Cloudflare-fronted subdomains."
                 f" Remaining {len(cf_subdomains) - 4} skipped to limit external lookups.{RS}")

    print()
    if found:
        ok(f"Total: {len(found)} subdomain(s) discovered.")
    else:
        warn("No subdomains discovered.")
    return found


# ── GeoIP ─────────────────────────────────────────────────────────────────────
# Known Cloudflare AS numbers — GeoIP on these returns CF's infra, not origin.
# Providers return them with or without the 'AS' prefix (e.g. '13335' vs 'AS13335'),
# so matching is done on the numeric part only.
_CLOUDFLARE_ASN_NUMBERS = {'13335', '209242'}

def _is_cloudflare_asn(asn_value) -> bool:
    """True when a provider ASN value belongs to Cloudflare, regardless of 'AS' prefix."""
    digits = ''.join(ch for ch in str(asn_value or '') if ch.isdigit())
    return digits in _CLOUDFLARE_ASN_NUMBERS

def _find_origin_ips_via_mx(hostname: str) -> list:
    """Find related MX infrastructure; these addresses are not confirmed origins."""
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


def _geoip_query(ip: str) -> dict:
    """Query GeoIP from multiple free providers with graceful fallback."""

    def _provider(url, **kw):
        try:
            if _stealth_session:
                return _stealth_session.get(url, timeout=8, **kw)
            return requests.get(url, timeout=8, **kw)
        except Exception:
            return None

    # Provider 1: ipwho.is (HTTPS, JSON)
    r = _provider(f"https://ipwho.is/{ip}")
    if r is not None and r.status_code == 200:
        try:
            d = r.json()
            if d.get('success'):
                return {
                    'success': True,
                    'query': d.get('ip', ip),
                    'country': d.get('country', 'N/A'),
                    'regionName': d.get('region', 'N/A'),
                    'city': d.get('city', 'N/A'),
                    'zip': d.get('postal', 'N/A'),
                    'latitude': d.get('latitude', 'N/A'),
                    'longitude': d.get('longitude', 'N/A'),
                    'timezone': (d.get('timezone') or {}).get('id', 'N/A'),
                    'isp': (d.get('connection') or {}).get('isp', 'N/A'),
                    'org': (d.get('connection') or {}).get('org', 'N/A'),
                    'as': str((d.get('connection') or {}).get('asn', 'N/A') or ''),
                    'mobile': d.get('is_mobile', 'N/A'),
                    'proxy': d.get('is_proxy', 'N/A'),
                }
        except (ValueError, TypeError):
            pass  # fall through to next provider

    # Provider 2: ip-api.com (free, HTTP) — reliable for host info
    r2 = _provider(f"http://ip-api.com/json/{ip}", headers={'User-Agent': 'Mozilla/5.0 CSCAN'})
    if r2 is not None and r2.status_code == 200:
        try:
            d2 = r2.json()
            if d2.get('status') == 'success':
                return {
                    'success': True,
                    'query': ip,
                    'country': d2.get('country', 'N/A'),
                    'regionName': d2.get('regionName', 'N/A'),
                    'city': d2.get('city', 'N/A'),
                    'zip': d2.get('zip', 'N/A'),
                    'latitude': d2.get('lat', 'N/A'),
                    'longitude': d2.get('lon', 'N/A'),
                    'timezone': d2.get('timezone', 'N/A'),
                    'isp': d2.get('isp', 'N/A'),
                    'org': d2.get('org', 'N/A'),
                    'as': d2.get('as', 'N/A'),
                    'mobile': 'N/A',
                    'proxy': d2.get('proxy', 'N/A'),
                }
        except (ValueError, TypeError):
            pass

    # Provider 3: ipinfo.io (free)
    r3 = _provider(f"https://ipinfo.io/{ip}/json", headers={'User-Agent': 'curl/8.0'})
    if r3 is not None and r3.status_code == 200:
        try:
            d3 = r3.json()
            if d3.get('ip'):
                return {
                    'success': True,
                    'query': ip,
                    'country': d3.get('country', 'N/A'),
                    'regionName': d3.get('region', 'N/A'),
                    'city': d3.get('city', 'N/A'),
                    'zip': d3.get('postal', 'N/A'),
                    'latitude': (d3.get('loc') or '').split(',')[0] if d3.get('loc') else 'N/A',
                    'longitude': (d3.get('loc') or '').split(',')[1] if d3.get('loc') else 'N/A',
                    'timezone': d3.get('timezone', 'N/A'),
                    'isp': (d3.get('org') or '').split(' ')[0] if d3.get('org') else 'N/A',
                    'org': d3.get('org', 'N/A'),
                    'as': d3.get('org', 'N/A'),
                    'mobile': 'N/A',
                    'proxy': 'N/A',
                }
        except (ValueError, TypeError):
            pass

    return {'success': False}


def geoip_lookup(target: str) -> dict:
    section("GEOIP & LOCATION TRACKER")
    hostname = extract_hostname(target)

    # Resolve to IP first
    try:
        ip = socket.gethostbyname(hostname)
    except Exception:
        ip = hostname  # pass an IP directly

    info(f"Looking up: {BR}{W}{ip}{RS}\n")

    d = _geoip_query(ip)
    if not d.get('success'):
        warn(f"All GeoIP providers failed for {ip} — skipping location data.")
        try:
            from modules.osnit_origin_ip import _is_cloudflare_ip
            cloudflare_edge = _is_cloudflare_ip(ip)
        except ImportError:
            cloudflare_edge = False
        if cloudflare_edge:
            info("Cloudflare/edge IP detected — run the Origin IP Discovery module to find the real server.")
        else:
            info("GeoIP providers were unreachable or returned no data — retry in a few seconds.")
        return {}

    try:
        # Detect Cloudflare edge IP
        asn_raw = d.get('as', '')
        asn = str(asn_raw or '').strip()
        is_cf_edge = _is_cloudflare_asn(asn_raw)
        if is_cf_edge:
            warn(f"This IP ({ip}) belongs to {BR}{Y}Cloudflare ({asn}){RS}")
            warn("GeoIP shows Cloudflare's network location, NOT the origin server.")

            info("Checking MX records for related infrastructure (not confirmed origins)...")
            origin_ips = _find_origin_ips_via_mx(hostname)
            if origin_ips:
                ok("Found related MX infrastructure IPs (not confirmed application origins):")
                for oip in origin_ips:
                    print(f"  {BR}{M}◈{RS}  {BR}{R}{oip}{RS}")
                d['potential_origin_ips'] = origin_ips
            else:
                warn("Could not discover origin IP via MX records.")
            print()

            # Full origin-IP discovery alongside the Cloudflare edge IP.
            # Failures here must never kill the Geolocation result — they are
            # an optional enhancement, so only warn on error.
            try:
                from modules.osnit_origin_ip import maybe_show_origin
                info(f"{BR}{Y}Cloudflare/WAF IP detected — searching for the real origin IP...{RS}")
                origin_report = maybe_show_origin(hostname)
                if origin_report:
                    d['origin_ip_report'] = origin_report
            except ImportError:
                pass
            except Exception as e:
                warn(f"Origin IP discovery skipped (GeoIP data still valid): {e}")

        rows = [
            ('IP Address',   d.get('query',       'N/A')),
            ('Country',      d.get('country',     'N/A')),
            ('Region',       d.get('regionName',  'N/A')),
            ('City',         d.get('city',        'N/A')),
            ('ZIP Code',     d.get('zip',         'N/A')),
            ('Latitude',     d.get('latitude',    'N/A')),
            ('Longitude',    d.get('longitude',   'N/A')),
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
