#!/usr/bin/env python3
"""
CSCAN — Shared Utilities
FIX #12: Single canonical resolve_host() used by scanner, exploit, and recon
         instead of three near-identical _resolve() copies.
"""
import socket
import ipaddress
from urllib.parse import urlparse, urlunparse

from modules.ui import alert, info, warn, BR, C, RS


def normalize_target(target: str, default_scheme: str = 'https') -> str:
    """Return a validated HTTP(S) target while preserving path and query."""
    if not target or not target.strip():
        raise ValueError("target cannot be empty")
    value = target.strip()
    if '://' not in value:
        value = f'{default_scheme}://{value}'
    parsed = urlparse(value)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        raise ValueError("target must be a hostname, IP, or http(s) URL")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("target contains an invalid port") from exc
    normalized = urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path or '/',
        parsed.params,
        parsed.query,
        '',
    ))
    return normalized.rstrip('/') or f'{parsed.scheme}://{parsed.netloc}'


def resolve_host(target: str) -> str:
    """
    Resolve a target (URL, hostname, or bare IP) to an IP address string.

    Behaviour:
    - If target is already a valid IP (v4 or v6), return it unchanged.
    - Prefer IPv4; fall back to IPv6 for dual-stack or IPv6-only hosts.
    - Informs the user when IPv6 is found alongside IPv4.
    - Returns None and prints an alert if resolution fails.
    """
    if not target or not target.strip():
        alert("Target cannot be empty")
        return None
    target = target.strip()

    # Strip protocol and path to get the raw hostname
    if '://' in target:
        hostname = urlparse(target).hostname or target
    elif '/' in target:
        hostname = target.split('/')[0]
    else:
        hostname = target

    hostname = hostname.strip('[]')

    # Already a bare IP address? Return as-is (handles IPv6 literals too)
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass

    # Resolve via getaddrinfo so we see both IPv4 and IPv6 records
    try:
        infos = socket.getaddrinfo(hostname, None)
        ipv4 = list(dict.fromkeys(r[4][0] for r in infos if r[0] == socket.AF_INET))
        ipv6 = list(dict.fromkeys(r[4][0] for r in infos if r[0] == socket.AF_INET6))

        if ipv4:
            if ipv6:
                info(f"IPv6 also available : {BR}{C}{ipv6[0]}{RS}  (scanning IPv4)")
            return ipv4[0]

        if ipv6:
            warn(f"No IPv4 found — using IPv6 address: {BR}{C}{ipv6[0]}{RS}")
            return ipv6[0]

    except Exception:
        pass

    alert(f"Cannot resolve {hostname}")
    return None
