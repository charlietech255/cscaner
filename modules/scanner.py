#!/usr/bin/env python3
"""
CSCAN — Network Scanning Modules
Port Scanner, Banner Grabber, SSL/TLS Inspector
"""

import socket
import ssl
import time
import random
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from modules.ui import (
    section, ok, warn, alert, info, critical, bold, divider,
    print_table, progress_bar, G, R, Y, C, M, W, B, BR, DM, RS
)

# ── FIX #6: Custom timeout override ───────────────────────────────────────────────
_custom_timeout: float | None = None   # overrides timing-profile timeout when set

def set_scan_timeout(t: float | None):
    """Called by cscan._apply_stealth() to push user-configured timeout override."""
    global _custom_timeout
    _custom_timeout = t

# ── define ports zote muhimu ──────────────────────────────────────────────────────────
COMMON_PORTS = {
    21:    'FTP',
    22:    'SSH',
    23:    'Telnet',
    25:    'SMTP',
    53:    'DNS',
    80:    'HTTP',
    110:   'POP3',
    111:   'RPCBind',
    135:   'MSRPC',
    139:   'NetBIOS',
    143:   'IMAP',
    443:   'HTTPS',
    445:   'SMB',
    465:   'SMTPS',
    587:   'SMTP/TLS',
    993:   'IMAPS',
    995:   'POP3S',
    1433:  'MSSQL',
    1723:  'PPTP',
    2222:  'SSH-alt',
    3306:  'MySQL',
    3389:  'RDP',
    5432:  'PostgreSQL',
    5900:  'VNC',
    6379:  'Redis',
    8080:  'HTTP-proxy',
    8443:  'HTTPS-alt',
    8888:  'Jupyter',
    9200:  'Elasticsearch',
    27017: 'MongoDB',
}

# Risky / ports hatari(potential)
RISKY_PORTS = {23, 135, 139, 445, 1723, 3389, 5900, 6379, 9200, 27017}

TIMEOUT = 1.5


# ── Core scan ─────────────────────────────────────────────────────────────────
def _probe_port(ip: str, port: int, timeout: float = TIMEOUT, delay: float = 0.0) -> tuple:
    """Try TCP connect with optional delay. Returns (port, is_open, banner)."""
    from modules.stealth import stealth_banner_probe
    if delay > 0:
        time.sleep(delay)
    # FIX #6: honour user-configured timeout override
    effective_timeout = _custom_timeout if _custom_timeout is not None else timeout
    return stealth_banner_probe(ip, port, timeout=effective_timeout)


def _display_port(port, banner, service):
    risk = f"  {BR}{R}◄ RISKY!{RS}" if port in RISKY_PORTS else ''
    b_str = (banner[:48] + '…') if len(banner) > 48 else banner
    print(f"  {BR}{G}[OPEN]{RS}  {BR}{W}{port:<6}{RS}  {C}{service:<14}{RS}  {DM}{b_str}{RS}{risk}")


# ── Common port scan ──────────────────────────────────────────────────────────
def port_scan_common(target: str, timing: str = 'normal', try_nmap: bool = False) -> list:
    from modules.stealth import TIMING_PROFILES, try_nmap_scan
    section("PORT SCANNER — COMMON PORTS")
    ip = _resolve(target)
    if not ip:
        return []
    info(f"Target IP     : {BR}{W}{ip}{RS}")
    info(f"Scanning      : {len(COMMON_PORTS)} common ports")
    info(f"Timing profile: {BR}{C}{timing}{RS}\n")

    if try_nmap:
        nmap_res = try_nmap_scan(ip, list(COMMON_PORTS.keys()), timing=timing, syn=False)
        if nmap_res is not None:
            open_ports = []
            for port, banner in nmap_res:
                open_ports.append((port, banner))
                print()
                _display_port(port, banner, COMMON_PORTS.get(port, 'unknown'))
            print(); divider()
            if open_ports:
                warn(f"Found {len(open_ports)} open port(s). Review each service carefully.")
            else:
                ok("No common ports open. Firewall appears well-configured.")
            return open_ports
        warn("nmap scan failed or unavailable. Falling back to TCP connect scan.")

    profile = TIMING_PROFILES.get(timing, TIMING_PROFILES['normal'])
    open_ports = []
    ports = list(COMMON_PORTS.keys())
    if timing in ('paranoid', 'sneaky'):
        random.shuffle(ports)

    with ThreadPoolExecutor(max_workers=profile['workers']) as ex:
        futures = {ex.submit(_probe_port, ip, p, profile['timeout'], profile['delay']): p for p in ports}
        done = 0
        for future in as_completed(futures):
            done += 1
            progress_bar(done, len(ports), 'scanning')
            port, is_open, banner = future.result()
            if is_open:
                open_ports.append((port, banner))
                print()
                _display_port(port, banner, COMMON_PORTS.get(port, 'unknown'))

    print()
    divider()
    if open_ports:
        warn(f"Found {len(open_ports)} open port(s). Review each service carefully.")
    else:
        ok("No common ports open. Firewall appears well-configured.")
    return open_ports


# ── Full port scan ────────────────────────────────────────────────────────────
def port_scan_full(target: str, start: int = 1, end: int = 65535, timing: str = 'normal', try_nmap: bool = False) -> list:
    from modules.stealth import TIMING_PROFILES, try_nmap_scan
    section(f"PORT SCANNER — FULL RANGE ({start}–{end})")
    ip = _resolve(target)
    if not ip:
        return []
    info(f"Target IP     : {BR}{W}{ip}{RS}")
    total = end - start + 1
    info(f"Scanning      : {total} ports — this may take a while…")
    info(f"Timing profile: {BR}{C}{timing}{RS}\n")

    if try_nmap and total > 1000:
        nmap_res = try_nmap_scan(ip, list(range(start, end + 1)), timing=timing, syn=False)
        if nmap_res is not None:
            open_ports = []
            for port, banner in nmap_res:
                open_ports.append((port, banner))
                print()
                _display_port(port, banner, COMMON_PORTS.get(port, 'unknown'))
            print(); divider()
            ok(f"Scan complete. {len(open_ports)} open port(s) found.")
            return open_ports
        warn("nmap scan failed or unavailable. Falling back to TCP connect scan.")

    profile = TIMING_PROFILES.get(timing, TIMING_PROFILES['normal'])
    open_ports = []
    lock = __import__('threading').Lock()

    def scan(p):
        port_num, is_open, banner = _probe_port(ip, p, profile['timeout'], profile['delay'])
        if is_open:
            with lock:
                open_ports.append((port_num, banner))
                svc = COMMON_PORTS.get(port_num, 'unknown')
                print()
                _display_port(port_num, banner, svc)

    with ThreadPoolExecutor(max_workers=profile['workers']) as ex:
        futures = [ex.submit(scan, p) for p in range(start, end + 1)]
        for i, _ in enumerate(as_completed(futures), 1):
            if i % 500 == 0:
                progress_bar(i, total, 'scanning')

    print()
    divider()
    ok(f"Scan complete. {len(open_ports)} open port(s) found.")
    return open_ports


# ── Banner Grabber ────────────────────────────────────────────────────────────
def banner_grabber(target: str, ports: list = None) -> dict:
    section("SERVICE BANNER GRABBER")
    ip = _resolve(target)
    if not ip:
        return {}
    grab_ports = ports or list(COMMON_PORTS.keys())
    info(f"Target IP     : {BR}{W}{ip}{RS}")
    info(f"Ports to grab : {len(grab_ports)}\n")

    results = {}
    for port in grab_ports:
        port_num, is_open, banner = _probe_port(ip, port, timeout=3.0, delay=0.0)
        if is_open and banner:
            svc = COMMON_PORTS.get(port_num, 'unknown')
            results[port_num] = banner
            print(f"  {BR}{G}{port_num}/{svc:<12}{RS}  {Y}{banner[:60]}{RS}")

    if not results:
        warn("No banners captured on open ports.")
    return results


# ── SSL/TLS Inspector ─────────────────────────────────────────────────────────
def ssl_inspect(target: str, port: int = 443) -> dict:
    section("SSL / TLS CERTIFICATE INSPECTOR")
    from urllib.parse import urlparse
    hostname = target
    if '://' in target:
        hostname = urlparse(target).hostname
    elif '/' in target:
        hostname = target.split('/')[0]

    info(f"Connecting    : {BR}{W}{hostname}:{port}{RS}\n")

    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(
            socket.create_connection((hostname, port), timeout=8),
            server_hostname=hostname
        )
        cert   = conn.getpeercert()
        # Read protocol and cipher BEFORE closing the connection
        tls_ver = conn.version()          # e.g. 'TLSv1.3'
        cipher  = conn.cipher()           # (name, protocol, bits)
        conn.close()

        fields = {
            'Subject':        dict(x[0] for x in cert.get('subject', [])),
            'Issuer':         dict(x[0] for x in cert.get('issuer', [])),
            'Version':        cert.get('version', 'N/A'),
            'Serial':         cert.get('serialNumber', 'N/A'),
            'Not Before':     cert.get('notBefore', 'N/A'),
            'Not After':      cert.get('notAfter', 'N/A'),
            'SANs':           [v for t, v in cert.get('subjectAltName', []) if t == 'DNS'],
            'Protocol':       tls_ver or 'N/A',
            'Cipher':         cipher[0] if cipher else 'N/A',
            'Cipher Bits':    cipher[2] if cipher else 'N/A',
        }

        # Parse expiry
        exp_raw = cert.get('notAfter', '')
        try:
            exp_dt  = datetime.strptime(exp_raw, '%b %d %H:%M:%S %Y %Z')
            days    = (exp_dt - datetime.utcnow()).days
            exp_col = G if days > 30 else (Y if days > 0 else R)
        except Exception:
            days, exp_col = '?', W

        labels = [
            ('Common Name',  fields['Subject'].get('commonName', 'N/A')),
            ('Issued By',    fields['Issuer'].get('organizationName', 'N/A')),
            ('Valid From',   fields['Not Before']),
            ('Valid Until',  fields['Not After']),
            ('Days Left',    f"{exp_col}{days} days{RS}"),
            ('Serial No.',   fields['Serial']),
            ('TLS Version',  fields['Protocol']),
            ('Cipher Suite', f"{fields['Cipher']}  ({fields['Cipher Bits']} bit)"),
        ]
        for label, val in labels:
            print(f"  {DM}◈{RS}  {BR}{Y}{label:<14}{RS}  {W}{val}{RS}")

        sans = fields['SANs']
        if sans:
            info(f"SANs ({len(sans)}) : " + ', '.join(sans[:8]) + ('…' if len(sans) > 8 else ''))

        if isinstance(days, int):
            if days < 0:
                critical("Certificate has EXPIRED!")
            elif days < 14:
                warn(f"Certificate expires in {days} days — renew ASAP!")
            elif days < 30:
                warn(f"Certificate expires in {days} days.")
            else:
                ok("Certificate is valid and not expiring soon.")

        return fields
    except ssl.CertificateError as e:
        critical(f"Certificate validation error: {e}")
    except ConnectionRefusedError:
        alert(f"Port {port} is closed or not accepting SSL connections.")
    except Exception as e:
        alert(f"SSL inspection failed: {e}")
    return {}


# FIX #12: resolve_host is the single canonical resolver in modules.utils.
# _resolve kept as an alias so all call sites in this file work unchanged.
def _resolve(target: str) -> str:
    from modules.utils import resolve_host
    return resolve_host(target)
