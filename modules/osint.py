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
        return requests.get(url, params=params, headers=h, timeout=timeout, verify=True)
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
        'https://web.archive.org/cdx/search/cdx',
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


# ── AlienVault OTX (no API key needed for basic lookups) ──────────────────────
def alienvault_otx(target: str) -> dict:
    """Query AlienVault Open Threat Exchange for passive DNS, malware, and URL data."""
    section("ALIENVAULT OTX THREAT INTELLIGENCE")
    hostname = _extract_hostname(target)
    domain   = _extract_domain(hostname)
    info(f"Querying OTX for: {BR}{W}{domain}{RS}\n")

    result = {'passive_dns': [], 'malware': [], 'urls': [], 'pulses': 0}

    # Passive DNS
    r = _get(f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns',
             headers={'Accept': 'application/json'})
    if r and r.status_code == 200:
        data = r.json()
        records = data.get('passive_dns', [])
        seen = set()
        for rec in records[:50]:
            addr = rec.get('address', '')
            hostname_rec = rec.get('hostname', '')
            if addr and addr not in seen:
                seen.add(addr)
                result['passive_dns'].append({
                    'hostname': hostname_rec, 'address': addr,
                    'first': rec.get('first', ''), 'last': rec.get('last', ''),
                    'record_type': rec.get('record_type', ''),
                })
        if result['passive_dns']:
            ok(f"Passive DNS: {len(result['passive_dns'])} unique IP(s)")
            for rec in result['passive_dns'][:10]:
                rtype = rec.get('record_type', 'A')
                print(f"  {G}•{RS} {W}{rec['hostname']}{RS} → {C}{rec['address']}{RS}  {DM}({rtype}, last: {rec['last'][:10]}){RS}")
        else:
            info("No passive DNS records found.")

    # URL list
    r2 = _get(f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list',
              headers={'Accept': 'application/json'})
    if r2 and r2.status_code == 200:
        data2 = r2.json()
        urls = data2.get('url_list', [])
        result['urls'] = [u.get('url', '') for u in urls[:30]]
        if urls:
            ok(f"Historical URLs: {len(urls)} found")
            for u in urls[:5]:
                print(f"  {Y}•{RS} {DM}{u.get('url', '')[:70]}{RS}  {DM}({u.get('httpcode', '?')}){RS}")

    # General info (pulse count = community threat reports)
    r3 = _get(f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general',
              headers={'Accept': 'application/json'})
    if r3 and r3.status_code == 200:
        data3 = r3.json()
        result['pulses'] = data3.get('pulse_info', {}).get('count', 0)
        if result['pulses'] > 0:
            alert(f"This domain appears in {BR}{R}{result['pulses']}{RS} OTX threat pulse(s)!")
        else:
            ok("Domain not flagged in any OTX threat pulses.")

    return result


# ── URLScan.io (free, no key for search) ──────────────────────────────────────
def urlscan_lookup(target: str) -> dict:
    """Search URLScan.io for historical scans of the target domain."""
    section("URLSCAN.IO HISTORICAL SCAN DATA")
    hostname = _extract_hostname(target)
    domain   = _extract_domain(hostname)
    info(f"Searching URLScan.io for: {BR}{W}{domain}{RS}\n")

    result = {'scans': [], 'technologies': set(), 'ips': set(), 'asns': set()}

    r = _get(f'https://urlscan.io/api/v1/search/',
             params={'q': f'domain:{domain}', 'size': 20})
    if not r or r.status_code != 200:
        warn("URLScan.io query failed or returned no results.")
        return result

    data = r.json()
    results_list = data.get('results', [])

    if not results_list:
        info("No historical scans found for this domain.")
        return result

    ok(f"Found {data.get('total', len(results_list))} historical scan(s)")

    for scan in results_list[:10]:
        page = scan.get('page', {})
        task = scan.get('task', {})
        stats = scan.get('stats', {})

        url = page.get('url', '')
        ip = page.get('ip', '')
        asn = page.get('asn', '')
        server = page.get('server', '')
        status = page.get('status', '')
        ts = task.get('time', '')[:10]

        result['scans'].append({'url': url, 'ip': ip, 'server': server, 'status': status, 'date': ts})
        if ip: result['ips'].add(ip)
        if asn: result['asns'].add(asn)
        if server: result['technologies'].add(server)

        print(f"  {C}•{RS} {W}{url[:50]}{RS}  {DM}IP:{ip}  Server:{server}  ({ts}){RS}")

    result['technologies'] = list(result['technologies'])
    result['ips'] = list(result['ips'])
    result['asns'] = list(result['asns'])

    if result['ips']:
        print(f"\n  {BR}{M}Unique IPs:{RS} {', '.join(result['ips'][:10])}")
    if result['technologies']:
        print(f"  {BR}{M}Servers:{RS} {', '.join(result['technologies'][:10])}")

    return result


# ── ThreatCrowd (free, no key) ────────────────────────────────────────────────
def threatcrowd_lookup(target: str) -> dict:
    """Query ThreatCrowd for domain intelligence."""
    section("THREATCROWD DOMAIN INTELLIGENCE")
    hostname = _extract_hostname(target)
    domain   = _extract_domain(hostname)
    info(f"Querying ThreatCrowd for: {BR}{W}{domain}{RS}\n")

    result = {'subdomains': [], 'resolutions': [], 'emails': [], 'references': []}

    r = _get(f'https://www.threatcrowd.org/searchApi/v2/domain/report/',
             params={'domain': domain})
    if not r or r.status_code != 200:
        warn("ThreatCrowd query failed.")
        return result

    try:
        data = r.json()
    except Exception:
        warn("Could not parse ThreatCrowd response.")
        return result

    if data.get('response_code') != '1':
        info("No ThreatCrowd data for this domain.")
        return result

    subs = data.get('subdomains', [])
    if subs:
        result['subdomains'] = subs[:50]
        ok(f"Subdomains: {len(subs)} found")
        for s in subs[:10]:
            print(f"  {G}•{RS} {W}{s}{RS}")
        if len(subs) > 10:
            print(f"  {DM}... and {len(subs) - 10} more{RS}")

    resolutions = data.get('resolutions', [])
    if resolutions:
        result['resolutions'] = resolutions[:30]
        ok(f"DNS resolutions: {len(resolutions)} historical record(s)")
        for res in resolutions[:5]:
            ip = res.get('ip_address', '')
            date = res.get('last_resolved', '')
            print(f"  {C}•{RS} {W}{ip}{RS}  {DM}(last: {date}){RS}")

    emails_found = data.get('emails', [])
    if emails_found:
        result['emails'] = emails_found[:20]
        ok(f"Emails: {len(emails_found)} found")

    refs = data.get('references', [])
    if refs:
        result['references'] = refs[:10]
        warn(f"Malware references: {len(refs)} link(s) — domain may be flagged")

    return result


# ── crt.sh enhanced (Certificate Transparency — free) ─────────────────────────
def crtsh_deep(target: str) -> dict:
    """Deep Certificate Transparency search via crt.sh."""
    section("CERTIFICATE TRANSPARENCY DEEP SEARCH")
    hostname = _extract_hostname(target)
    domain   = _extract_domain(hostname)
    info(f"Querying crt.sh for: {BR}{W}{domain}{RS}\n")

    result = {'subdomains': [], 'issuers': set(), 'wildcards': [], 'expired': []}

    r = _get(f'https://crt.sh/?q=%25.{domain}&output=json', timeout=15)
    if not r or r.status_code != 200:
        warn("crt.sh query failed or timed out.")
        return result

    try:
        entries = r.json()
    except Exception:
        warn("Could not parse crt.sh response.")
        return result

    names = set()
    for entry in entries:
        raw = entry.get('name_value', '')
        issuer = entry.get('issuer_name', '')
        not_after = entry.get('not_after', '')
        for n in raw.split('\n'):
            n = n.strip().lstrip('*.')
            if n and n.endswith(domain) and n != domain:
                names.add(n.lower())
            if n.startswith('*.'):
                result['wildcards'].append(n)
        if issuer:
            result['issuers'].add(issuer[:60])

    result['subdomains'] = sorted(names)
    result['issuers'] = list(result['issuers'])
    result['wildcards'] = list(set(result['wildcards']))[:10]

    if names:
        ok(f"CT logs reveal {len(names)} unique subdomain(s)")
        for s in sorted(names)[:15]:
            print(f"  {G}•{RS} {W}{s}{RS}")
        if len(names) > 15:
            print(f"  {DM}... and {len(names) - 15} more{RS}")
    else:
        info("No subdomains found in CT logs.")

    if result['issuers']:
        print(f"\n  {BR}{M}Certificate Issuers:{RS}")
        for iss in list(result['issuers'])[:5]:
            print(f"  {C}•{RS} {DM}{iss}{RS}")

    return result


# ── DNS history via SecurityTrails-like free sources ──────────────────────────
def passive_dns_aggregate(target: str) -> dict:
    """Aggregate passive DNS from multiple free sources."""
    section("PASSIVE DNS AGGREGATION")
    hostname = _extract_hostname(target)
    domain   = _extract_domain(hostname)
    info(f"Aggregating passive DNS for: {BR}{W}{domain}{RS}\n")

    all_ips = set()
    all_subs = set()
    result = {'ips': [], 'subdomains': []}

    # Source 1: HackerTarget
    r = _get(f'https://api.hackertarget.com/hostsearch/?q={domain}', timeout=10)
    if r and r.status_code == 200 and 'error' not in r.text.lower():
        for line in r.text.strip().splitlines():
            parts = line.split(',')
            if len(parts) >= 2:
                sub = parts[0].strip()
                ip = parts[1].strip()
                all_subs.add(sub)
                all_ips.add(ip)
        if all_subs:
            ok(f"HackerTarget: {len(all_subs)} host(s) found")

    # Source 2: RapidDNS
    r2 = _get(f'https://rapiddns.io/subdomain/{domain}?full=1', timeout=10)
    if r2 and r2.status_code == 200:
        import re as _re
        matches = _re.findall(r'<td>([a-zA-Z0-9._-]+\.' + _re.escape(domain) + r')</td>', r2.text)
        for m in matches:
            all_subs.add(m.lower())
        if matches:
            ok(f"RapidDNS: {len(matches)} additional subdomain(s)")

    # Source 3: Riddler.io
    r3 = _get(f'https://riddler.io/search/exportcsv?q=pld:{domain}', timeout=10)
    if r3 and r3.status_code == 200:
        for line in r3.text.strip().splitlines()[1:]:
            parts = line.split(',')
            for part in parts:
                part = part.strip().strip('"')
                if part.endswith(domain) and '.' in part:
                    all_subs.add(part.lower())

    result['ips'] = sorted(all_ips)
    result['subdomains'] = sorted(all_subs)

    if all_subs:
        ok(f"Total unique subdomains: {len(all_subs)}")
        for s in sorted(all_subs)[:15]:
            print(f"  {G}•{RS} {W}{s}{RS}")
        if len(all_subs) > 15:
            print(f"  {DM}... and {len(all_subs) - 15} more{RS}")

    if all_ips:
        print(f"\n  {BR}{M}Unique IPs:{RS}")
        for ip in sorted(all_ips)[:10]:
            print(f"  {C}•{RS} {W}{ip}{RS}")

    return result


# ── Master OSINT function ─────────────────────────────────────────────────────
def osint_recon(target: str, shodan_key: str = None, github_token: str = None,
                hibp_key: str = None) -> dict:
    """Run all passive OSINT checks — both free and API-key-gated."""
    section("PASSIVE OSINT RECON SUITE")
    hostname = _extract_hostname(target)
    domain   = _extract_domain(hostname)
    warn("All checks below are PASSIVE — no direct connection to target.\n")

    results = {}

    # ── Free sources (no API key needed) ──────────────────────────────────────
    info(f"{BR}{C}Running free OSINT sources...{RS}\n")

    results['ct_deep']       = crtsh_deep(target)
    results['passive_dns']   = passive_dns_aggregate(target)
    results['alienvault']    = alienvault_otx(target)
    results['urlscan']       = urlscan_lookup(target)
    results['threatcrowd']   = threatcrowd_lookup(target)
    results['wayback']       = wayback_endpoints(target)
    results['emails']        = email_harvest(target)

    # ── API-key sources ───────────────────────────────────────────────────────
    if shodan_key:
        results['shodan'] = shodan_lookup(target, shodan_key)
    else:
        info("Shodan skipped (no API key).")

    results['github'] = github_dork(domain, github_token)

    if hibp_key:
        results['hibp'] = hibp_domain_check(domain, hibp_key)
    else:
        info("HIBP breach check skipped (no API key).")

    # ── OSINT summary ─────────────────────────────────────────────────────────
    section(f"OSINT SUMMARY — {domain}")
    total_subs = set()
    total_ips = set()
    for key in ('ct_deep', 'passive_dns', 'threatcrowd'):
        data = results.get(key, {})
        total_subs.update(data.get('subdomains', []))
    for key in ('passive_dns', 'urlscan'):
        data = results.get(key, {})
        total_ips.update(data.get('ips', []))

    ok(f"Total unique subdomains discovered : {BR}{G}{len(total_subs)}{RS}")
    ok(f"Total unique IPs discovered        : {BR}{G}{len(total_ips)}{RS}")
    ok(f"Email addresses found              : {BR}{G}{len(results.get('emails', []))}{RS}")
    ok(f"Wayback URLs archived              : {BR}{G}{len(results.get('wayback', []))}{RS}")

    otx = results.get('alienvault', {})
    if otx.get('pulses', 0) > 0:
        alert(f"OTX threat pulses                  : {BR}{R}{otx['pulses']}{RS}")
    tc = results.get('threatcrowd', {})
    if tc.get('references'):
        alert(f"ThreatCrowd malware references     : {BR}{R}{len(tc['references'])}{RS}")

    return results


# ── Interactive menu ──────────────────────────────────────────────────────────
def menu_osint(session: dict) -> dict:
    section("OSINT — PASSIVE RECONNAISSANCE")
    info("CSCAN will query multiple free OSINT sources automatically.")
    info("API keys are optional — more sources unlock with keys.\n")

    shodan  = input(f"  {BR}{W}Shodan API Key  (https://account.shodan.io)  : {RS}").strip() or None
    github  = input(f"  {BR}{W}GitHub Token    (optional, for higher limits) : {RS}").strip() or None
    hibp    = input(f"  {BR}{W}HIBP API Key    (https://haveibeenpwned.com)  : {RS}").strip() or None

    target  = session.get('target')
    if not target:
        warn("No target set — use 'T' to set a target first.")
        return {}

    return osint_recon(target, shodan_key=shodan, github_token=github, hibp_key=hibp)
