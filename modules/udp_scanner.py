#!/usr/bin/env python3
"""
CSCAN — UDP Service Scanner
Probes key UDP services:
  - SNMP (161): community string check, system info dump
  - DNS  (53) : zone transfer attempt
  - NTP  (123): monlist amplification check
  - TFTP (69) : unauthenticated file access check
"""

import socket
import struct
import time

from modules.ui import (
    section, ok, warn, alert, info, critical, divider,
    G, R, Y, C, M, W, BR, DM, RS
)

TIMEOUT = 4  # UDP is lossy — shorter timeout is fine


# ── SNMP v1/v2c community string probe ────────────────────────────────────────
# Minimal SNMP GET-REQUEST PDU for sysDescr (OID 1.3.6.1.2.1.1.1.0)
def _build_snmp_get(community: str, request_id: int = 1) -> bytes:
    """Build a raw SNMP v2c GET-REQUEST packet."""
    def _encode_len(n):
        if n < 0x80:
            return bytes([n])
        nb = (n.bit_length() + 7) // 8
        return bytes([0x80 | nb]) + n.to_bytes(nb, 'big')

    def _tlv(tag, value):
        return bytes([tag]) + _encode_len(len(value)) + value

    # sysDescr OID: 1.3.6.1.2.1.1.1.0
    oid_bytes = bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
    oid       = _tlv(0x06, oid_bytes)
    null      = _tlv(0x05, b'')
    varbind   = _tlv(0x30, oid + null)
    varbindlist = _tlv(0x30, varbind)

    req_id    = _tlv(0x02, struct.pack('>I', request_id))
    error     = _tlv(0x02, b'\x00')
    err_idx   = _tlv(0x02, b'\x00')
    get_req   = _tlv(0xa0, req_id + error + err_idx + varbindlist)  # GET-REQUEST

    comm      = _tlv(0x04, community.encode())
    version   = _tlv(0x02, b'\x01')  # v2c = 1
    msg       = _tlv(0x30, version + comm + get_req)
    return msg


def _parse_snmp_response(data: bytes) -> str | None:
    """Very rough SNMP response parser — extracts the first OctetString value."""
    try:
        idx = data.find(b'\x04')  # OctetString tag
        while idx != -1:
            ln = data[idx + 1]
            val = data[idx + 2: idx + 2 + ln]
            try:
                decoded = val.decode('ascii', errors='replace').strip()
                if len(decoded) > 3:
                    return decoded
            except Exception:
                pass
            idx = data.find(b'\x04', idx + 1)
    except Exception:
        pass
    return None


SNMP_COMMUNITIES = ['public', 'private', 'manager', 'admin', 'community', 'default', '']


def snmp_scan(target: str, port: int = 161) -> dict:
    section("SNMP COMMUNITY STRING AUDIT")
    info(f"Target        : {BR}{W}{target}:{port}{RS}")
    info(f"Communities   : testing {len(SNMP_COMMUNITIES)} common strings\n")

    result = {'open': False, 'community': None, 'sysDescr': None, 'communities_tried': []}

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)

    try:
        for comm in SNMP_COMMUNITIES:
            pkt = _build_snmp_get(comm)
            try:
                sock.sendto(pkt, (target, port))
                data, _ = sock.recvfrom(4096)
                result['open'] = True
                desc = _parse_snmp_response(data)
                result['community']  = comm or '(empty)'
                result['sysDescr']   = desc
                result['communities_tried'].append(comm or '(empty)')

                print()
                critical(f"SNMP OPEN with community: '{comm or '(empty)'}'")
                if desc:
                    info(f"sysDescr      : {BR}{Y}{desc[:120]}{RS}")
                info("Risk: SNMP v1/v2c provides full network topology to any knowing the community string.")
                info("Fix : Upgrade to SNMPv3 with authentication, or firewall UDP 161.")
                break
            except socket.timeout:
                result['communities_tried'].append(comm or '(empty)')
                continue
    finally:
        sock.close()

    if not result['open']:
        ok("SNMP port 161/udp did not respond (filtered or closed).")
    return result


# ── DNS Zone Transfer ─────────────────────────────────────────────────────────
def dns_zone_transfer(target: str, domain: str = None) -> dict:
    section("DNS ZONE TRANSFER ATTEMPT (AXFR)")
    result = {'vulnerable': False, 'records': []}

    if not domain:
        # Try to guess domain from target
        parts = target.replace('http://', '').replace('https://', '').split('/')
        host  = parts[0]
        segments = host.split('.')
        domain = '.'.join(segments[-2:]) if len(segments) >= 2 else host

    info(f"Target NS     : {BR}{W}{target}{RS}")
    info(f"Domain        : {BR}{W}{domain}{RS}")

    try:
        # Resolve nameservers for domain
        import subprocess
        ns_result = subprocess.run(
            ['dig', '+short', 'NS', domain],
            capture_output=True, text=True, timeout=8
        )
        nameservers = [ns.strip().rstrip('.') for ns in ns_result.stdout.strip().split('\n') if ns.strip()]
        if not nameservers:
            nameservers = [target]
        info(f"Nameservers   : {', '.join(nameservers[:3])}")
    except Exception:
        nameservers = [target]

    for ns in nameservers[:2]:
        info(f"Attempting AXFR from {BR}{C}{ns}{RS}…")
        try:
            proc = __import__('subprocess').run(
                ['dig', 'AXFR', domain, f'@{ns}'],
                capture_output=True, text=True, timeout=12
            )
            output = proc.stdout
            if 'Transfer failed' in output or '; Connection timed out' in output:
                ok(f"Zone transfer refused by {ns} (good).")
            elif 'ANSWER SECTION' in output and domain in output:
                result['vulnerable'] = True
                records = [line for line in output.split('\n') if domain in line and not line.startswith(';')]
                result['records'] = records[:50]
                critical(f"ZONE TRANSFER SUCCEEDED from {ns}!")
                warn(f"Extracted {len(records)} DNS record(s):")
                for rec in records[:15]:
                    print(f"    {DM}{rec}{RS}")
                if len(records) > 15:
                    print(f"    {DM}… and {len(records) - 15} more{RS}")
                info("Fix: Restrict AXFR to specific trusted IPs in your nameserver config.")
                break
            else:
                ok(f"Zone transfer not allowed from {ns}.")
        except FileNotFoundError:
            warn("'dig' not found — install dnsutils: sudo apt install dnsutils")
            break
        except Exception as e:
            warn(f"AXFR attempt failed: {e}")

    return result


# ── NTP Monlist Check ─────────────────────────────────────────────────────────
# NTP monlist request (mode 7 private, opcode 42)
_NTP_MONLIST_PKT = bytes([
    0x17, 0x00, 0x03, 0x2a,
    0x00, 0x00, 0x00, 0x00,
])


def ntp_monlist_check(target: str, port: int = 123) -> dict:
    section("NTP MONLIST AMPLIFICATION CHECK")
    info(f"Target        : {BR}{W}{target}:{port}{RS}\n")
    result = {'vulnerable': False, 'peers_returned': 0}

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    try:
        sock.sendto(_NTP_MONLIST_PKT, (target, port))
        packets_received = 0
        try:
            while True:
                data, _ = sock.recvfrom(4096)
                packets_received += 1
                if packets_received > 30:
                    break
        except socket.timeout:
            pass

        if packets_received > 1:
            result['vulnerable'] = True
            result['peers_returned'] = packets_received
            critical(f"NTP monlist ENABLED — received {packets_received} response packet(s)!")
            warn("This server can be used for DDoS amplification attacks (up to 700x amplification).")
            info("Fix: Upgrade NTP to ≥4.2.7p26 and add 'noquery' to restrict directive in ntp.conf.")
        else:
            ok("NTP monlist not enabled (good — CVE-2013-5211 not applicable).")
    except Exception:
        ok("NTP port 123/udp did not respond (filtered or closed).")
    finally:
        sock.close()

    return result


# ── TFTP Unauthenticated Access ───────────────────────────────────────────────
def tftp_check(target: str, port: int = 69) -> dict:
    section("TFTP UNAUTHENTICATED ACCESS CHECK")
    info(f"Target        : {BR}{W}{target}:{port}{RS}\n")
    result = {'open': False, 'readable': False}

    # TFTP RRQ (Read Request) for a common file
    test_files = ['passwd', 'boot.cfg', 'running-config', 'startup-config', 'config.txt']
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)

    try:
        for filename in test_files:
            # Build RRQ packet: opcode(2) + filename + 0 + "octet" + 0
            pkt = struct.pack('!H', 1) + filename.encode() + b'\x00octet\x00'
            sock.sendto(pkt, (target, port))
            try:
                data, addr = sock.recvfrom(516)
                opcode = struct.unpack('!H', data[:2])[0]
                if opcode == 3:   # DATA packet — file exists and was returned
                    result['open']     = True
                    result['readable'] = True
                    critical(f"TFTP is OPEN and readable — file '{filename}' returned!")
                    warn("TFTP has no authentication. Any file on the server may be downloadable.")
                    info("Fix: Disable TFTP or restrict by IP using xinetd/firewall rules.")
                    break
                elif opcode == 5:  # ERROR — server responded (port is open, file not found)
                    result['open'] = True
                    ok(f"TFTP is open but returned error for '{filename}' (access may be restricted).")
                    break
            except socket.timeout:
                continue
    finally:
        sock.close()

    if not result['open']:
        ok("TFTP port 69/udp did not respond (filtered or closed).")

    return result


# ── Main UDP scan suite ───────────────────────────────────────────────────────
def udp_scan_suite(target: str, domain: str = None) -> dict:
    """Run all UDP checks and return combined results."""
    section("UDP SERVICE SCANNER")
    warn("UDP scanning is inherently imprecise — firewalls often silently drop packets.")
    warn("A non-response does NOT guarantee the port is closed.\n")

    # Strip protocol
    host = target.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]

    results = {}

    info("1/4  SNMP Community String Check…")
    results['snmp'] = snmp_scan(host)
    print()

    info("2/4  DNS Zone Transfer…")
    results['dns_axfr'] = dns_zone_transfer(host, domain)
    print()

    info("3/4  NTP Monlist Amplification…")
    results['ntp'] = ntp_monlist_check(host)
    print()

    info("4/4  TFTP Unauthenticated Access…")
    results['tftp'] = tftp_check(host)

    # Summary
    divider()
    vulns = []
    if results['snmp'].get('open'):          vulns.append('SNMP open (community string known)')
    if results['dns_axfr'].get('vulnerable'): vulns.append('DNS zone transfer allowed')
    if results['ntp'].get('vulnerable'):      vulns.append('NTP monlist amplification enabled')
    if results['tftp'].get('readable'):       vulns.append('TFTP unauthenticated read')

    if vulns:
        alert(f"UDP vulnerabilities found: {len(vulns)}")
        for v in vulns:
            print(f"  {BR}{R}◆{RS}  {v}")
    else:
        ok("No critical UDP service vulnerabilities detected.")

    return results
