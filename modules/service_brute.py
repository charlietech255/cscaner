#!/usr/bin/env python3
"""
CSCAN — Multi-Protocol Service Brute Forcer
Covers: MySQL, PostgreSQL, Redis, MongoDB (unauth), RDP (banner)
SSH and HTTP basic auth are already in exploit.py — not duplicated here.
"""

import socket
import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

from modules.ui import (
    section, ok, warn, alert, info, critical, divider,
    progress_bar, G, R, Y, C, M, W, BR, DM, RS
)

WORDLISTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'wordlists')
TIMEOUT       = 5


def _load_creds(filename: str) -> list:
    path = os.path.join(WORDLISTS_DIR, filename)
    creds = []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split(':', 1)
                    creds.append((parts[0], parts[1] if len(parts) > 1 else ''))
    except Exception:
        pass
    return creds or [('root', ''), ('admin', 'admin'), ('root', 'root'),
                     ('admin', ''), ('test', 'test'), ('mysql', 'mysql')]


def _resolve(target: str) -> str:
    from modules.utils import resolve_host
    return resolve_host(target)


# ── MySQL brute force ─────────────────────────────────────────────────────────
def mysql_brute(target: str, port: int = 3306, custom_creds: list = None) -> dict:
    section("MYSQL CREDENTIAL AUDIT")
    ip = _resolve(target)
    if not ip:
        return {}
    info(f"Target        : {BR}{W}{ip}:{port}{RS}")

    try:
        import pymysql
    except ImportError:
        warn("pymysql not installed. Install with: pip install pymysql")
        return {'skipped': True}

    creds  = custom_creds or _load_creds('http_creds.txt')
    result = {'open': False, 'vulnerable': False, 'credential': None}
    info(f"Testing       : {len(creds)} credential pairs\n")

    consecutive_errors = 0
    for i, (user, pwd) in enumerate(creds, 1):
        progress_bar(i, len(creds), f'{user}:{pwd}')
        try:
            conn = pymysql.connect(
                host=ip, port=port, user=user, password=pwd,
                connect_timeout=TIMEOUT, read_timeout=TIMEOUT
            )
            conn.close()
            print()
            critical(f"MySQL LOGIN SUCCESS → {user}:{pwd}")
            result.update({'open': True, 'vulnerable': True, 'credential': (user, pwd)})
            consecutive_errors = 0
            break
        except pymysql.err.OperationalError as e:
            err = str(e)
            result['open'] = True
            if 'Access denied' in err:
                consecutive_errors = 0
            elif 'Connection refused' in err:
                alert("MySQL port not open or access refused at network level.")
                break
            else:
                consecutive_errors += 1
        except Exception:
            consecutive_errors += 1
        if consecutive_errors >= 5:
            warn("Too many consecutive errors — aborting MySQL brute force.")
            break

    print('\n')
    divider()
    if result.get('vulnerable'):
        critical("MySQL accepts weak credentials!")
        info("Fix: Use strong passwords and restrict remote access in MySQL config.")
    elif result.get('open'):
        ok("No weak MySQL credentials found.")
    else:
        warn("MySQL port did not respond.")
    return result


# ── PostgreSQL brute force ────────────────────────────────────────────────────
def pgsql_brute(target: str, port: int = 5432, custom_creds: list = None) -> dict:
    section("POSTGRESQL CREDENTIAL AUDIT")
    ip = _resolve(target)
    if not ip:
        return {}
    info(f"Target        : {BR}{W}{ip}:{port}{RS}")

    try:
        import psycopg2
    except ImportError:
        warn("psycopg2 not installed. Install with: pip install psycopg2-binary")
        return {'skipped': True}

    creds  = custom_creds or [
        ('postgres', 'postgres'), ('postgres', ''), ('postgres', 'admin'),
        ('admin', 'admin'), ('postgres', 'password'), ('root', 'root')
    ]
    result = {'open': False, 'vulnerable': False, 'credential': None}
    info(f"Testing       : {len(creds)} credential pairs\n")

    for i, (user, pwd) in enumerate(creds, 1):
        progress_bar(i, len(creds), f'{user}:{pwd}')
        try:
            conn = psycopg2.connect(
                host=ip, port=port, user=user, password=pwd,
                connect_timeout=TIMEOUT, dbname='postgres'
            )
            conn.close()
            print()
            critical(f"PostgreSQL LOGIN SUCCESS → {user}:{pwd}")
            result.update({'open': True, 'vulnerable': True, 'credential': (user, pwd)})
            break
        except psycopg2.OperationalError as e:
            err = str(e).lower()
            if 'password authentication failed' in err or 'role' in err:
                result['open'] = True
            elif 'connection refused' in err:
                break
        except Exception:
            pass

    print('\n')
    divider()
    if result.get('vulnerable'):
        critical("PostgreSQL accepts weak credentials!")
        info("Fix: Use md5 or scram-sha-256 auth in pg_hba.conf + strong passwords.")
    elif result.get('open'):
        ok("No weak PostgreSQL credentials found.")
    return result


# ── Redis unauthenticated check ───────────────────────────────────────────────
def redis_unauth_check(target: str, port: int = 6379) -> dict:
    section("REDIS AUTHENTICATION CHECK")
    ip = _resolve(target)
    if not ip:
        return {}
    info(f"Target        : {BR}{W}{ip}:{port}{RS}\n")

    result = {'open': False, 'unauth': False, 'info': ''}
    try:
        s = socket.create_connection((ip, port), timeout=TIMEOUT)
        result['open'] = True
        s.sendall(b'*1\r\n$4\r\nINFO\r\n')
        data = s.recv(4096).decode('utf-8', errors='ignore')
        s.close()

        if 'redis_version' in data.lower():
            result['unauth'] = True
            ver_match = __import__('re').search(r'redis_version:(\S+)', data, __import__('re').I)
            ver = ver_match.group(1) if ver_match else '?'
            result['info'] = data[:200]
            critical(f"Redis UNAUTHENTICATED! Version: {ver}")
            warn("Anyone on the network can read/write all Redis keys.")
            info("Fix: Set 'requirepass <strong_password>' in redis.conf")
            info("     Bind to 127.0.0.1 only if not used externally.")
        elif 'NOAUTH' in data or 'Authentication required' in data:
            ok("Redis requires authentication (good).")
        else:
            ok("Redis did not expose info without auth.")
    except ConnectionRefusedError:
        ok("Redis port 6379 is not open (or not accessible).")
    except Exception as e:
        warn(f"Redis check failed: {e}")

    return result


# ── MongoDB unauthenticated check ─────────────────────────────────────────────
# MongoDB wire protocol — minimal isMaster / hello command
_MONGO_HELLO = (
    b'\x41\x00\x00\x00'   # messageLength (65)
    b'\x01\x00\x00\x00'   # requestID
    b'\x00\x00\x00\x00'   # responseTo
    b'\xd4\x07\x00\x00'   # opCode: OP_QUERY (2004)
    b'\x00\x00\x00\x00'   # flags
    b'admin.$cmd\x00'      # fullCollectionName
    b'\x00\x00\x00\x00'   # numberToSkip
    b'\x01\x00\x00\x00'   # numberToReturn
    b'\x13\x00\x00\x00'   # document length (19)
    b'\x10'               # int32 type
    b'isMaster\x00'
    b'\x01\x00\x00\x00'
    b'\x00'               # doc terminator
)


def mongodb_unauth_check(target: str, port: int = 27017) -> dict:
    section("MONGODB AUTHENTICATION CHECK")
    ip = _resolve(target)
    if not ip:
        return {}
    info(f"Target        : {BR}{W}{ip}:{port}{RS}\n")

    result = {'open': False, 'unauth': False}
    try:
        s = socket.create_connection((ip, port), timeout=TIMEOUT)
        result['open'] = True
        s.sendall(_MONGO_HELLO)
        data = s.recv(4096)
        s.close()

        if b'ismaster' in data.lower() or b'isWritablePrimary' in data or b'ok' in data:
            result['unauth'] = True
            critical("MongoDB UNAUTHENTICATED! Server responded to isMaster without auth.")
            warn("All databases are accessible without credentials.")
            info("Fix: Enable --auth in mongod.conf and create admin user.")
            info("     Bind to 127.0.0.1 only if local use.")
        else:
            ok("MongoDB did not respond to unauthenticated query (auth may be enabled).")
    except ConnectionRefusedError:
        ok("MongoDB port 27017 is not open or accessible.")
    except Exception as e:
        warn(f"MongoDB check failed: {e}")

    return result


# ── Elasticsearch unauthenticated check ───────────────────────────────────────
def elasticsearch_unauth_check(target: str, port: int = 9200) -> dict:
    section("ELASTICSEARCH AUTHENTICATION CHECK")
    ip = _resolve(target)
    if not ip:
        return {}
    info(f"Target        : {BR}{W}{ip}:{port}{RS}\n")

    result = {'open': False, 'unauth': False, 'version': None}
    try:
        import requests as _req
        r = _req.get(f'http://{ip}:{port}/', timeout=TIMEOUT,
                     headers={'User-Agent': 'Mozilla/5.0 (compatible; CSCAN/2.2)'})
        result['open'] = True
        if r.status_code == 200:
            data = r.json()
            ver = data.get('version', {}).get('number', '?')
            result.update({'unauth': True, 'version': ver})
            critical(f"Elasticsearch UNAUTHENTICATED! Version: {ver}")
            warn("All indices are readable without credentials.")
            info("Fix: Enable X-Pack security (xpack.security.enabled: true)")
        elif r.status_code == 401:
            ok("Elasticsearch requires authentication (good).")
        else:
            ok(f"Elasticsearch returned HTTP {r.status_code}.")
    except ConnectionRefusedError:
        ok("Elasticsearch port 9200 is not open.")
    except Exception as e:
        warn(f"Elasticsearch check failed: {e}")

    return result


# ── RDP banner check ──────────────────────────────────────────────────────────
def rdp_check(target: str, port: int = 3389) -> dict:
    section("RDP (REMOTE DESKTOP) SERVICE CHECK")
    ip = _resolve(target)
    if not ip:
        return {}
    info(f"Target        : {BR}{W}{ip}:{port}{RS}\n")

    result = {'open': False, 'nla': None}
    # RDP Connection Request PDU (X.224 TPKT)
    rdp_pkt = bytes([
        0x03, 0x00, 0x00, 0x13,           # TPKT header
        0x0e, 0xe0, 0x00, 0x00,           # X.224 TPDU
        0x00, 0x00, 0x00,                 # dst/src refs
        0x01, 0x00,                       # class
        0x00,
        0x43, 0x6f, 0x6f, 0x6b, 0x69,    # "Cooki"
        0x65, 0x3a,                       # "e:"
        0x20, 0x6d, 0x73, 0x74,           # " mst"
        0x73, 0x68, 0x61, 0x73, 0x68,    # "shash"
        0x3d, 0x41, 0x64, 0x6d,           # "=Adm"
        0x69, 0x6e, 0x69, 0x73,           # "inis"
        0x74, 0x72, 0x61, 0x74,           # "trat"
        0x6f, 0x72, 0x0d, 0x0a,           # "or\r\n"
        0x01, 0x00, 0x08, 0x00,           # RDP_NEG_REQ
        0x00, 0x00, 0x00, 0x00,           # protocols: standard
    ])

    try:
        s = socket.create_connection((ip, port), timeout=TIMEOUT)
        result['open'] = True
        s.sendall(rdp_pkt)
        data = s.recvfrom(1024)[0]
        s.close()

        if len(data) >= 11:
            # Byte 11 = RDP_NEG_RSP type (0x02 = accepted)
            if data[11] == 0x02:
                protocol_flags = data[15]
                if protocol_flags & 0x02:
                    result['nla'] = True
                    ok("RDP uses Network Level Authentication (NLA) — good.")
                else:
                    result['nla'] = False
                    warn("RDP does NOT use NLA — authentication occurs after session setup.")
                    warn("Risk: BlueKeep (CVE-2019-0708) and DejaBlue may apply.")
                    info("Fix: Enable NLA via Group Policy or System Properties → Remote.")
        else:
            ok("RDP is open (could not determine NLA status).")

        info(f"RDP port {port} is OPEN.")
        warn("Exposed RDP = prime target for brute-force & ransomware. Restrict access!")
    except ConnectionRefusedError:
        ok(f"RDP port {port} is closed or not accessible.")
    except Exception as e:
        warn(f"RDP check failed: {e}")

    return result


# ── Combined service scan ─────────────────────────────────────────────────────
def service_brute_suite(target: str, open_ports: list = None) -> dict:
    """
    Run relevant service checks based on which ports are open.
    open_ports is the list of (port, banner) tuples from port_scan_common().
    """
    section("MULTI-SERVICE AUTHENTICATION AUDIT")

    port_set = {p for p, _ in (open_ports or [])}
    results  = {}

    checks = [
        (3306,  'MySQL',         mysql_brute),
        (5432,  'PostgreSQL',    pgsql_brute),
        (6379,  'Redis',         redis_unauth_check),
        (27017, 'MongoDB',       mongodb_unauth_check),
        (9200,  'Elasticsearch', elasticsearch_unauth_check),
        (3389,  'RDP',           rdp_check),
    ]

    ran_any = False
    for port, name, fn in checks:
        if not open_ports or port in port_set:
            info(f"Checking {name} on port {port}…")
            results[name.lower()] = fn(target, port)
            ran_any = True
            print()

    if not ran_any:
        info("No relevant service ports found — run port scan first.")

    return results
