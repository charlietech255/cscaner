#!/usr/bin/env python3
"""
CSCAN — OSINT: Origin IP Discovery (Cloudflare/WAF-fronted targets)
====================================================================
Finds the real server IP behind Cloudflare or other WAFs using PUBLIC
data sources — no attacks, no Camoufox (that stays in cloudflare_bypass.py).

Techniques:
  1. DNS history via SecurityTrails (optional API key)
  2. Certificate Transparency search (crt.sh — free)
  3. Un-proxied subdomain resolution
  4. MX record infrastructure correlation
  5. Direct IP verification via Host-header
  6. AlienVault OTX passive DNS (free)
  7. URLScan.io historical scans (free)
"""

from __future__ import annotations

import ipaddress
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import requests

from modules.ui import (
    section, ok, warn, alert, info, critical, divider,
    G, R, Y, C, M, W, BR, DM, RS
)


# ── Result container ──────────────────────────────────────────────────────
@dataclass
class OriginCandidate:
    ip: str
    source: str                  # e.g. "dns_history", "cert_search", "subdomain:mail"
    evidence: str                # short human-readable reason
    confidence: str = "possible" # "confirmed" | "possible"
    verified_response_snippet: Optional[str] = None


@dataclass
class OriginIPReport:
    domain: str
    candidates: list[OriginCandidate] = field(default_factory=list)
    cf_ips: list[str] = field(default_factory=list)  # current Cloudflare fronting IPs

    def add(self, c: OriginCandidate):
        # dedupe by IP
        for existing in self.candidates:
            if existing.ip == c.ip:
                # keep the higher-confidence one, merge sources
                if c.confidence == "confirmed" and existing.confidence != "confirmed":
                    existing.confidence = "confirmed"
                    existing.verified_response_snippet = c.verified_response_snippet
                existing.source += f" + {c.source}"
                return
        self.candidates.append(c)

    def confirmed(self) -> list[OriginCandidate]:
        return [c for c in self.candidates if c.confidence == "confirmed"]

    def possible(self) -> list[OriginCandidate]:
        return [c for c in self.candidates if c.confidence == "possible"]


# ── Cloudflare IP range fetcher (cached per session) ─────────────────────
_CF_RANGES_CACHE: list[ipaddress.IPv4Network] | None = None


def _fetch_cloudflare_ranges() -> list[ipaddress.IPv4Network]:
    """Fetch Cloudflare's published IPv4 ranges from cloudflare.com."""
    global _CF_RANGES_CACHE
    if _CF_RANGES_CACHE is not None:
        return _CF_RANGES_CACHE

    ranges = []
    try:
        r = requests.get("https://www.cloudflare.com/ips-v4", timeout=8)
        if r.status_code == 200:
            for line in r.text.strip().splitlines():
                line = line.strip()
                if line and "/" in line:
                    try:
                        ranges.append(ipaddress.IPv4Network(line))
                    except ValueError:
                        pass
    except Exception:
        pass

    # Fallback hardcoded ranges if fetch fails
    if not ranges:
        fallback = [
            "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13",
            "131.0.72.0/22", "173.245.48.0/20", "103.21.244.0/22",
            "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
            "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
            "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15",
        ]
        for cidr in fallback:
            try:
                ranges.append(ipaddress.IPv4Network(cidr))
            except ValueError:
                pass

    _CF_RANGES_CACHE = ranges
    return ranges


def _is_cloudflare_ip(ip_str: str) -> bool:
    """Check if an IP belongs to Cloudflare's published ranges."""
    try:
        addr = ipaddress.IPv4Address(ip_str)
        return any(addr in net for net in _fetch_cloudflare_ranges())
    except (ValueError, TypeError):
        return False


def _get_cloudflare_ips(target_ip: str) -> list[str]:
    """Get the Cloudflare fronting IPs for the target."""
    cf_ips = []
    try:
        hostname = urlparse(target_ip).hostname if "://" in target_ip else target_ip.split("/")[0]
        # Try to get all IPs the domain resolves to
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET)
        for info in infos:
            ip = info[4][0]
            if _is_cloudflare_ip(ip) and ip not in cf_ips:
                cf_ips.append(ip)
    except Exception:
        pass
    return cf_ips


# ── Technique 1: Historical DNS records ───────────────────────────────────
def _query_dns_history(domain: str, api_key: Optional[str] = None) -> list[OriginCandidate]:
    """
    Query SecurityTrails for A records that predate the target moving
    behind Cloudflare. Requires API key — skipped gracefully without one.
    """
    results: list[OriginCandidate] = []
    if not api_key:
        info("DNS history: no SecurityTrails API key — skipped.")
        return results

    try:
        resp = requests.get(
            f"https://api.securitytrails.com/v1/history/{domain}/dns/a",
            headers={"APIKEY": api_key},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        for record in data.get("records", []):
            for value in record.get("values", []):
                ip = value.get("ip")
                if ip and not _is_cloudflare_ip(ip):
                    first_seen = record.get("first_seen", "?")
                    results.append(OriginCandidate(
                        ip=ip,
                        source="dns_history",
                        evidence=f"Historical A record (first seen {first_seen})",
                    ))
    except Exception as e:
        warn(f"DNS history lookup failed: {e}")

    return results


# ── Technique 2: Certificate Transparency (crt.sh — free, no key) ────────
def _query_crtsh(domain: str) -> list[OriginCandidate]:
    """
    Search crt.sh for certificates matching the target domain. The origin
    server often still presents its own cert even when Cloudflare proxies
    the public-facing connection. We resolve the IP from cert-reported hostnames.
    """
    results: list[OriginCandidate] = []

    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=15,
        )
        if resp.status_code != 200:
            return results

        entries = resp.json()
        hostnames_seen = set()
        for entry in entries:
            name_val = entry.get("name_value", "")
            for name in name_val.split("\n"):
                name = name.strip().lstrip("*.")
                if name and name not in hostnames_seen:
                    hostnames_seen.add(name)
                    # Try resolving this hostname
                    try:
                        ip = socket.gethostbyname(name)
                        if not _is_cloudflare_ip(ip):
                            results.append(OriginCandidate(
                                ip=ip,
                                source=f"cert_sh:{name}",
                                evidence=f"Certificate Transparency hostname {name} resolves to non-CF IP",
                            ))
                    except (socket.gaierror, OSError):
                        continue

    except Exception as e:
        warn(f"crt.sh query failed: {e}")

    return results


# ── Technique 3: Un-proxied subdomains ────────────────────────────────────
_COMMON_UNCLOAKED_PREFIXES = [
    "direct", "origin", "dev", "staging", "test", "ftp", "mail",
    "webmail", "cpanel", "autodiscover", "api-internal", "old", "legacy",
    "internal", "intranet", "vpn", "gateway", "proxy", "backup",
]


def _check_uncloaked_subdomains(domain: str) -> list[OriginCandidate]:
    """
    Resolve commonly-forgotten subdomains. Many teams put the main site
    behind Cloudflare but forget to proxy every subdomain.
    """
    results: list[OriginCandidate] = []

    for prefix in _COMMON_UNCLOAKED_PREFIXES:
        host = f"{prefix}.{domain}"
        try:
            ip = socket.gethostbyname(host)
        except (socket.gaierror, OSError):
            continue

        if not _is_cloudflare_ip(ip):
            results.append(OriginCandidate(
                ip=ip,
                source=f"subdomain:{prefix}",
                evidence=f"{host} resolves directly (not via Cloudflare)",
            ))

    return results


# ── Technique 4: MX records ───────────────────────────────────────────────
def _query_mx_records(domain: str) -> list[OriginCandidate]:
    """
    Mail servers are rarely proxied through Cloudflare. If the MX host
    shares infrastructure/subnet with the web server, it's a useful lead.
    Uses DNS-over-HTTPS (no dnspython needed).
    """
    results: list[OriginCandidate] = []

    try:
        resp = requests.get(
            "https://cloudflare-dns.com/dns-query",
            params={"name": domain, "type": "MX"},
            headers={"Accept": "application/dns-json"},
            timeout=8,
        )
        data = resp.json()
        answers = data.get("Answer", [])

        for ans in answers:
            mx_data = ans.get("data", "")
            # MX data format: "10 mail.example.com"
            parts = mx_data.split()
            if len(parts) < 2:
                continue
            mx_host = parts[1].rstrip(".")
            try:
                ip = socket.gethostbyname(mx_host)
                results.append(OriginCandidate(
                    ip=ip,
                    source=f"mx:{mx_host}",
                    evidence=f"Mail server {mx_host} — same-network lead",
                    confidence="possible",
                ))
            except (socket.gaierror, OSError):
                continue
    except Exception as e:
        warn(f"MX lookup failed: {e}")

    return results


# ── Technique 5: AlienVault OTX passive DNS (free) ────────────────────────
def _query_alienvault(domain: str) -> list[OriginCandidate]:
    """Query AlienVault OTX for passive DNS — reveals historical IPs."""
    results: list[OriginCandidate] = []

    try:
        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            headers={"Accept": "application/json"},
            timeout=12,
        )
        if resp.status_code != 200:
            return results

        seen = set()
        for record in resp.json().get("passive_dns", [])[:30]:
            ip = record.get("address", "")
            hostname_rec = record.get("hostname", "")
            last_seen = record.get("last", "")[:10]

            if ip and ip not in seen and not _is_cloudflare_ip(ip):
                seen.add(ip)
                results.append(OriginCandidate(
                    ip=ip,
                    source=f"otx:{hostname_rec}",
                    evidence=f"AlienVault passive DNS — last seen {last_seen}",
                ))
    except Exception as e:
        warn(f"AlienVault OTX query failed: {e}")

    return results


# ── Technique 6: URLScan.io (free) ────────────────────────────────────────
def _query_urlscan(domain: str) -> list[OriginCandidate]:
    """Search URLScan.io for historical scans revealing the origin IP."""
    results: list[OriginCandidate] = []

    try:
        resp = requests.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{domain}", "size": 20},
            timeout=12,
        )
        if resp.status_code != 200:
            return results

        seen = set()
        for scan in resp.json().get("results", []):
            page = scan.get("page", {})
            ip = page.get("ip", "")
            server = page.get("server", "")

            if ip and ip not in seen and not _is_cloudflare_ip(ip):
                seen.add(ip)
                results.append(OriginCandidate(
                    ip=ip,
                    source=f"urlscan:{server}",
                    evidence=f"URLScan.io historical scan — server: {server}",
                ))
    except Exception as e:
        warn(f"URLScan.io query failed: {e}")

    return results


# ── Technique 7: Verification — does the candidate actually serve the site? ─
def verify_origin_candidate(domain: str, ip: str, use_https: bool = True,
                             timeout: int = 10) -> Optional[str]:
    """
    Send a direct request to the candidate IP with the target's Host
    header. If we get back content resembling the real site (not a
    Cloudflare error page, not a default nginx/Apache page), this is a
    strong signal the IP is the true origin.
    """
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{ip}/"

    try:
        resp = requests.get(
            url,
            headers={"Host": domain},
            timeout=timeout,
            verify=False,  # origin cert won't match the IP — expected
            allow_redirects=False,
        )
        body = resp.text[:1000]
        body_lower = body.lower()

        # Negative signals — we did NOT reach the real origin
        if "cloudflare" in body_lower and resp.status_code in (403, 503):
            return None
        if re.search(r"default (apache|nginx|litespeed) (page|welcome|home)", body_lower):
            return None
        if resp.status_code == 0:
            return None

        # Positive signal — we got real content
        if resp.status_code in (200, 301, 302, 304, 403) and len(body) > 50:
            return body[:300]

        return None
    except requests.exceptions.SSLError:
        # SSL error with Host header = IP exists but cert doesn't match — still a lead
        return f"[SSL mismatch — origin serves different cert]"
    except Exception:
        return None


# ── Display helpers ────────────────────────────────────────────────────────
def _display_candidates(report: OriginIPReport):
    """Pretty-print the candidates to the terminal."""
    confirmed = report.confirmed()
    possible = report.possible()

    if confirmed:
        divider()
        critical(f"CONFIRMED origin candidates ({len(confirmed)}):")
        for c in confirmed:
            print(f"  {BR}{R}*{RS}  {W}{c.ip}{RS}")
            print(f"       {DM}Source   : {c.source}{RS}")
            print(f"       {DM}Evidence : {c.evidence}{RS}")
            if c.verified_response_snippet:
                snippet = c.verified_response_snippet[:120].replace("\n", " ")
                print(f"       {DM}Snippet  : {snippet}...{RS}")

    if possible:
        divider()
        warn(f"Possible origin candidates ({len(possible)}):")
        for c in possible:
            print(f"  {BR}{Y}?{RS}  {W}{c.ip}{RS}")
            print(f"       {DM}Source   : {c.source}{RS}")
            print(f"       {DM}Evidence : {c.evidence}{RS}")

    if not confirmed and not possible:
        divider()
        info("No non-Cloudflare origin candidates found.")
        info("Target may be well-protected (full CF proxy, no forgotten subdomains, clean DNS history).")


# ── Orchestrator ───────────────────────────────────────────────────────────
def find_origin_ip(
    domain: str,
    securitytrails_key: Optional[str] = None,
    verify: bool = True,
) -> OriginIPReport:
    """
    Run all origin-IP-discovery techniques and return a ranked report.
    """
    # Resolve target to identify Cloudflare fronting IPs
    parsed = urlparse(domain if "://" in domain else f"https://{domain}")
    hostname = parsed.hostname or domain

    section(f"ORIGIN IP DISCOVERY — {hostname}")

    target_ips = []
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET)
        target_ips = list(set(info[4][0] for info in infos))
    except Exception:
        warn(f"Could not resolve {hostname}")

    cf_ips = [ip for ip in target_ips if _is_cloudflare_ip(ip)]
    non_cf = [ip for ip in target_ips if not _is_cloudflare_ip(ip)]

    report = OriginIPReport(domain=hostname, cf_ips=cf_ips)

    # Show current Cloudflare fronting IPs
    if cf_ips:
        info(f"Cloudflare fronting IPs: {BR}{Y}{', '.join(cf_ips)}{RS}")
    if non_cf:
        ok(f"Non-Cloudflare IPs found: {BR}{G}{', '.join(non_cf)}{RS}")
        for ip in non_cf:
            report.add(OriginCandidate(
                ip=ip,
                source="direct_resolution",
                evidence=f"{hostname} resolves directly to non-CF IP",
                confidence="confirmed",
            ))

    print()

    # Technique 1: DNS history
    info("Running DNS history lookup...")
    for c in _query_dns_history(hostname, securitytrails_key):
        report.add(c)

    # Technique 2: Certificate Transparency (free)
    info("Running Certificate Transparency search...")
    for c in _query_crtsh(hostname):
        report.add(c)

    # Technique 3: Un-proxied subdomains
    info("Checking commonly-forgotten subdomains...")
    for c in _check_uncloaked_subdomains(hostname):
        report.add(c)

    # Technique 4: MX records
    info("Checking MX records...")
    for c in _query_mx_records(hostname):
        report.add(c)

    # Technique 5: AlienVault OTX (free)
    info("Querying AlienVault OTX passive DNS...")
    for c in _query_alienvault(hostname):
        report.add(c)

    # Technique 6: URLScan.io (free)
    info("Querying URLScan.io historical data...")
    for c in _query_urlscan(hostname):
        report.add(c)

    # Deduplicate before verification
    seen_ips = set()
    unique = []
    for c in report.candidates:
        if c.ip not in seen_ips:
            seen_ips.add(c.ip)
            unique.append(c)
    report.candidates = unique

    # Verification
    if verify and report.candidates:
        info(f"Verifying {len(report.candidates)} candidate(s) via Host-header requests...")
        for candidate in report.candidates:
            snippet = verify_origin_candidate(hostname, candidate.ip)
            if snippet:
                candidate.confidence = "confirmed"
                candidate.verified_response_snippet = snippet

    # Display results
    _display_candidates(report)

    return report


# ── Standalone runner ──────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else input("Target domain: ").strip()
    find_origin_ip(target)
