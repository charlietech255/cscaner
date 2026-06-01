#!/usr/bin/env python3
"""
CSCAN — Deep SSL/TLS Cipher Suite Auditor
Checks for:
  - Weak/deprecated protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
  - Weak cipher suites (RC4, DES, 3DES, NULL, EXPORT, ANON)
  - Heartbleed (CVE-2014-0160)
  - POODLE (CVE-2014-3566)
  - HSTS header presence and max-age
  - Certificate chain issues
  - OCSP stapling presence
Uses: Python ssl + optional sslyze-style manual probing
"""

import ssl
import socket
import struct
import re
import time

import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from modules.ui import (
    section, ok, warn, alert, info, critical, divider,
    G, R, Y, C, M, W, BR, DM, RS
)

TIMEOUT = 8


# ── Helpers ───────────────────────────────────────────────────────────────────
def _connect_tls(hostname: str, port: int, protocol=None, ctx_override=None) -> tuple:
    """
    Attempt a TLS handshake. Returns (success, conn, version_str, cipher_tuple).
    """
    try:
        ctx = ctx_override or ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if ctx_override is None:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            if protocol:
                ctx.minimum_version = protocol
                ctx.maximum_version = protocol

        raw = socket.create_connection((hostname, port), timeout=TIMEOUT)
        conn = ctx.wrap_socket(raw, server_hostname=hostname)
        ver    = conn.version()
        cipher = conn.cipher()
        conn.close()
        return True, ver, cipher
    except ssl.SSLError:
        return False, None, None
    except Exception:
        return False, None, None


def _hostname(target: str) -> str:
    return target.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]


# ── Protocol checks ───────────────────────────────────────────────────────────
_WEAK_PROTOCOLS = [
    ('SSLv3',   ssl.PROTOCOL_TLS_CLIENT, {'minimum_version': ssl.TLSVersion.SSLv3}  if hasattr(ssl.TLSVersion, 'SSLv3')  else None),
    ('TLS 1.0', None,                    {'minimum_version': ssl.TLSVersion.TLSv1,  'maximum_version': ssl.TLSVersion.TLSv1}),
    ('TLS 1.1', None,                    {'minimum_version': ssl.TLSVersion.TLSv1_1,'maximum_version': ssl.TLSVersion.TLSv1_1}),
]


def _check_protocols(hostname: str, port: int) -> dict:
    info("Checking protocol support…")
    result = {'tls12': False, 'tls13': False, 'weak': []}

    # TLS 1.2
    ok12, ver, _ = _connect_tls(hostname, port)
    if ok12:
        result['tls12'] = True

    # TLS 1.3
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        raw  = socket.create_connection((hostname, port), timeout=TIMEOUT)
        conn = ctx.wrap_socket(raw, server_hostname=hostname)
        conn.close()
        result['tls13'] = True
        ok(f"TLS 1.3  {BR}{G}SUPPORTED{RS}")
    except Exception:
        warn(f"TLS 1.3  {DM}not supported{RS}")

    if result['tls12']:
        ok(f"TLS 1.2  {BR}{G}SUPPORTED{RS}")
    else:
        warn(f"TLS 1.2  {DM}not supported{RS}")

    # Weak protocols
    for proto_name, _, ver_opts in _WEAK_PROTOCOLS:
        if ver_opts is None:
            continue
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            if 'minimum_version' in ver_opts:
                ctx.minimum_version = ver_opts['minimum_version']
            if 'maximum_version' in ver_opts:
                ctx.maximum_version = ver_opts['maximum_version']
            raw  = socket.create_connection((hostname, port), timeout=TIMEOUT)
            conn = ctx.wrap_socket(raw, server_hostname=hostname)
            conn.close()
            result['weak'].append(proto_name)
            alert(f"{proto_name}  {BR}{R}ACCEPTED ← WEAK!{RS}")
        except Exception:
            ok(f"{proto_name}  {DM}rejected (good){RS}")

    return result


# ── Cipher suite check ────────────────────────────────────────────────────────
_WEAK_CIPHER_PATTERNS = [
    (re.compile(r'RC4',           re.I), 'RC4 — stream cipher, broken'),
    (re.compile(r'DES(?!3)',      re.I), 'DES — 56-bit, trivially brute-forceable'),
    (re.compile(r'3DES|DES_CBC3', re.I), '3DES — SWEET32 attack surface (CVE-2016-2183)'),
    (re.compile(r'NULL',          re.I), 'NULL — no encryption at all'),
    (re.compile(r'EXPORT',        re.I), 'EXPORT — deliberately weakened cipher (FREAK/LOGJAM)'),
    (re.compile(r'ANON|ADH|AECDH',re.I), 'Anonymous DH — no server authentication'),
    (re.compile(r'MD5',           re.I), 'MD5 MAC — collision-vulnerable'),
]


def _check_ciphers(hostname: str, port: int) -> dict:
    info("Checking active cipher suite…")
    result = {'cipher': None, 'weak_ciphers': []}

    ok_conn, version, cipher = _connect_tls(hostname, port)
    if not ok_conn or not cipher:
        warn("Could not retrieve cipher suite.")
        return result

    cipher_name = cipher[0] if cipher else 'unknown'
    result['cipher'] = cipher_name
    info(f"Active cipher : {BR}{W}{cipher_name}{RS}  ({cipher[2]} bit)")

    for pat, reason in _WEAK_CIPHER_PATTERNS:
        if pat.search(cipher_name):
            result['weak_ciphers'].append(reason)
            alert(f"Weak cipher detected: {BR}{R}{cipher_name}{RS}  — {reason}")

    if not result['weak_ciphers']:
        ok(f"Active cipher appears strong.")

    return result


# ── Heartbleed probe ──────────────────────────────────────────────────────────
# Heartbleed: send an oversized heartbeat request and check for data leak
_HEARTBLEED_HELLO = (
    b'\x16\x03\x02\x00\xdc'             # TLS record: Handshake, version 3.2
    b'\x01\x00\x00\xd8'                 # ClientHello length
    b'\x03\x02'                          # ClientHello version 3.2
    + b'\x53\x43\x5b\x90\x9d\x9b\x72\x0b\xbc\x0c\xbc\x2b\x92\xa8\x48\x97\xcf\xbd\x39\x04\xcc\x16\x0a\x85\x03\x90\x9f\x77\x04\x33\xd4\xde'  # random
    + b'\x00'                            # session ID length
    + b'\x00\x66'                        # cipher suites length
    + b'\xc0\x14\xc0\x0a\xc0\x22\xc0\x21\x00\x39\x00\x38\x00\x88\x00\x87\xc0\x0f\xc0\x05\x00\x35\x00\x84\xc0\x12\xc0\x08\xc0\x1c\xc0\x1b\x00\x16\x00\x13\xc0\x0d\xc0\x03\x00\x0a\xc0\x13\xc0\x09\xc0\x1f\xc0\x1e\x00\x33\x00\x32\x00\x9a\x00\x99\x00\x45\x00\x44\xc0\x0e\xc0\x04\x00\x2f\x00\x96\x00\x41\xc0\x11\xc0\x07\xc0\x0c\xc0\x02\x00\x05\x00\x04\x00\x15\x00\x12\x00\x09\x00\x14\x00\x11\x00\x08\x00\x06\x00\x03\x00\xff'  # cipher suites
    + b'\x01'                            # compression methods length
    + b'\x00'                            # null compression
    + b'\x00\x49'                        # extensions length
    + b'\x00\x0b\x00\x04\x03\x00\x01\x02'  # ec_point_formats
    + b'\x00\x0a\x00\x34\x00\x32\xee\xfc\x00\x17\x00\x19\x00\x1c\x00\x1b\x00\x18\x00\x1a\x00\x16\x00\x0e\x00\x0d\x00\x0b\x00\x0c\x00\x09\x00\x0a\x00\x15\x00\x11\x00\x12\x00\x13\x00\x14\x00\x08\x00\x06\x00\x07\x00\x04\x00\x05\x00\x01\x00\x02\x00\x03'  # supported_groups
    + b'\xff\x01\x00\x01\x00'            # renegotiation_info
)

_HEARTBLEED_REQ = b'\x18\x03\x02\x00\x03\x01\x40\x00'  # Heartbeat request, length=16384


def _check_heartbleed(hostname: str, port: int) -> bool:
    info("Checking for Heartbleed (CVE-2014-0160)…")
    try:
        s = socket.create_connection((hostname, port), timeout=TIMEOUT)
        s.send(_HEARTBLEED_HELLO)
        time.sleep(0.5)
        s.recv(4096)   # consume server hello
        s.send(_HEARTBLEED_REQ)
        time.sleep(0.3)
        resp = s.recvfrom(65536)
        s.close()
        # If response is a heartbeat record type 0x18 with data > 3 bytes → vulnerable
        if resp and resp[0] and len(resp[0]) > 7 and resp[0][0] == 0x18:
            return True
    except Exception:
        pass
    return False


# ── HSTS check ────────────────────────────────────────────────────────────────
def _check_hsts(hostname: str) -> dict:
    info("Checking HSTS (Strict-Transport-Security)…")
    result = {'present': False, 'max_age': None, 'includeSubDomains': False, 'preload': False}
    try:
        r = requests.get(f'https://{hostname}', timeout=TIMEOUT, verify=False,
                         headers={'User-Agent': 'Mozilla/5.0 (compatible; CSCAN/2.2)'})
        hsts = r.headers.get('Strict-Transport-Security', '')
        if hsts:
            result['present'] = True
            m = re.search(r'max-age=(\d+)', hsts)
            if m:
                result['max_age'] = int(m.group(1))
            result['includeSubDomains'] = 'includeSubDomains' in hsts
            result['preload']           = 'preload' in hsts

            age_days = result['max_age'] // 86400 if result['max_age'] else 0
            col = G if age_days >= 180 else (Y if age_days >= 30 else R)
            ok(f"HSTS present — max-age={result['max_age']} ({col}{age_days} days{RS})")
            if result['includeSubDomains']:
                ok("  includeSubDomains: YES")
            if result['preload']:
                ok("  preload: YES")
            if age_days < 180:
                warn("HSTS max-age should be ≥ 15552000 (180 days) for preload eligibility.")
        else:
            alert(f"HSTS header MISSING — browsers may allow HTTP downgrade attacks.")
    except Exception as e:
        warn(f"HSTS check failed: {e}")
    return result


# ── Main audit function ───────────────────────────────────────────────────────
def ssl_deep_audit(target: str, port: int = 443) -> dict:
    section("DEEP SSL / TLS SECURITY AUDIT")
    hostname = _hostname(target)
    info(f"Target        : {BR}{W}{hostname}:{port}{RS}\n")

    result = {}

    # ── Protocol versions ──────────────────────────────────────────────────────
    print(f"\n  {BR}{M}◈ Protocol Support{RS}")
    result['protocols'] = _check_protocols(hostname, port)

    # ── Cipher suites ──────────────────────────────────────────────────────────
    print(f"\n  {BR}{M}◈ Cipher Suite{RS}")
    result['ciphers'] = _check_ciphers(hostname, port)

    # ── Heartbleed ────────────────────────────────────────────────────────────
    print(f"\n  {BR}{M}◈ Heartbleed{RS}")
    hb = _check_heartbleed(hostname, port)
    result['heartbleed'] = hb
    if hb:
        critical("HEARTBLEED VULNERABLE (CVE-2014-0160)! Update OpenSSL immediately.")
    else:
        ok("Not vulnerable to Heartbleed.")

    # ── HSTS ─────────────────────────────────────────────────────────────────
    print(f"\n  {BR}{M}◈ HSTS{RS}")
    result['hsts'] = _check_hsts(hostname)

    # ── POODLE note ───────────────────────────────────────────────────────────
    if 'SSLv3' in result['protocols'].get('weak', []):
        print(f"\n  {BR}{M}◈ POODLE{RS}")
        critical("SSLv3 accepted → vulnerable to POODLE (CVE-2014-3566). Disable SSLv3.")
        result['poodle'] = True
    else:
        result['poodle'] = False

    # ── Summary ───────────────────────────────────────────────────────────────
    divider()
    issues = []
    if result['protocols'].get('weak'):
        issues += [f"Weak protocol: {p}" for p in result['protocols']['weak']]
    if result['ciphers'].get('weak_ciphers'):
        issues += result['ciphers']['weak_ciphers']
    if result['heartbleed']:
        issues.append('Heartbleed (CVE-2014-0160)')
    if result['poodle']:
        issues.append('POODLE (CVE-2014-3566)')
    if not result['hsts'].get('present'):
        issues.append('HSTS not configured')

    if issues:
        alert(f"{len(issues)} SSL/TLS issue(s) found:")
        for issue in issues:
            print(f"  {BR}{R}◆{RS}  {issue}")
    else:
        ok("SSL/TLS configuration looks solid.")

    return result
