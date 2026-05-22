#!/usr/bin/env python3
"""
CSCAN — Stealth, OPSEC & WAF Evasion Engine
Supports proxy rotation, request jitter, User-Agent rotation,
path mutation, adaptive backoff, and optional nmap SYN scanning.
"""

import os
import sys
import time
import random
import socket
import subprocess
from urllib.parse import quote

import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ── Realistic User-Agent pool ────────────────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/124.0.2478.67",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]

ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9", "en-GB,en;q=0.8", "fr-FR,fr;q=0.7,en;q=0.6",
    "de-DE,de;q=0.7,en;q=0.6", "es-ES,es;q=0.7,en;q=0.6", "ja-JP,ja;q=0.5,en;q=0.4",
]

REFERERS = [
    "https://www.google.com/", "https://duckduckgo.com/", "https://bing.com/",
    "https://search.yahoo.com/", "https://www.ecosia.org/",
]

# ── WAF/Block signatures ────────────────────────────────────────────────────
WAF_SIGNATURES = {
    "cloudflare": ["cloudflare", "cf-ray", "__cfduid", "cf-request-id"],
    "akamai":     ["akamai", "x-akamai-transformed"],
    "sucuri":     ["sucuri", "x-sucuri-id"],
    "aws":        ["x-amzn-requestid", "awselb"],
    "incapsula":  ["incap_ses", "visid_incap"],
}

# ── Timing profiles (like nmap -T1..T5) ─────────────────────────────────────
TIMING_PROFILES = {
    "paranoid":   {"workers": 1,   "timeout": 4.0, "delay": 3.0},
    "sneaky":     {"workers": 5,   "timeout": 3.5, "delay": 1.5},
    "polite":     {"workers": 10,  "timeout": 3.0, "delay": 0.8},
    "normal":     {"workers": 60,  "timeout": 2.0, "delay": 0.0},
    "aggressive": {"workers": 100, "timeout": 1.5, "delay": 0.0},
    "insane":     {"workers": 150, "timeout": 1.0, "delay": 0.0},
}

# ── Helpers ─────────────────────────────────────────────────────────────────
def has_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def nmap_available() -> bool:
    try:
        subprocess.run(["nmap", "-V"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except Exception:
        return False


def random_xff() -> str:
    return f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"


# ── StealthSession ──────────────────────────────────────────────────────────
class StealthSession:
    """
    Wraps requests with proxy support, jitter, UA/header rotation,
    cookie persistence, and adaptive WAF backoff.
    """

    def __init__(
        self,
        proxy: str = None,
        jitter_min: float = 0.0,
        jitter_max: float = 0.0,
        rotate_ua: bool = True,
        random_headers: bool = True,
        cookie_persist: bool = True,
        insecure_ssl: bool = False,
    ):
        self.proxy = self._parse_proxy(proxy)
        self.jitter_min = jitter_min
        self.jitter_max = jitter_max
        self.rotate_ua = rotate_ua
        self.random_headers = random_headers
        self.cookie_persist = cookie_persist
        self.insecure_ssl = insecure_ssl
        self._session = requests.Session() if cookie_persist else None
        self.blocked_count = 0
        self.last_request_time = 0.0

    def _parse_proxy(self, proxy_str: str):
        if not proxy_str:
            return None
        proxy_str = proxy_str.strip()
        # Auto-detect socks protocols and ensure PySocks is available
        if proxy_str.startswith(("socks4://", "socks5://")):
            try:
                import socks
            except ImportError:
                raise RuntimeError(
                    "SOCKS proxy requires PySocks. Run: pip install pysocks"
                )
        return {"http": proxy_str, "https": proxy_str}

    def _apply_jitter(self):
        if self.jitter_max <= 0:
            return
        delay = random.uniform(self.jitter_min, self.jitter_max)
        elapsed = time.time() - self.last_request_time
        if elapsed < delay:
            time.sleep(delay - elapsed)
        self.last_request_time = time.time()

    def _get_headers(self) -> dict:
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        if self.rotate_ua:
            headers["User-Agent"] = random.choice(USER_AGENTS)
        else:
            headers["User-Agent"] = "Mozilla/5.0 (compatible; CSCAN/2.1)"
        if self.random_headers:
            headers["Accept-Language"] = random.choice(ACCEPT_LANGUAGES)
            headers["Referer"] = random.choice(REFERERS)
            headers["X-Forwarded-For"] = random_xff()
            headers["X-Requested-With"] = "XMLHttpRequest" if random.random() > 0.7 else None
        # Prune None values
        return {k: v for k, v in headers.items() if v is not None}

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        self._apply_jitter()
        req_headers = self._get_headers()
        user_headers = kwargs.pop("headers", {}) or {}
        req_headers.update(user_headers)

        req_kwargs = {
            "headers": req_headers,
            "proxies": self.proxy,
            "timeout": kwargs.pop("timeout", 10),
            "verify": kwargs.pop("verify", not self.insecure_ssl),
            "allow_redirects": kwargs.pop("allow_redirects", False),
            **kwargs,
        }

        session_obj = self._session if self._session else requests
        response = session_obj.request(method, url, **req_kwargs)

        # Adaptive backoff on WAF/rate-limit signals
        if response.status_code in (403, 429, 502, 503):
            self.blocked_count += 1
            if self.blocked_count >= 2:
                backoff = random.uniform(3, 8) * self.blocked_count
                time.sleep(backoff)
        else:
            self.blocked_count = max(0, self.blocked_count - 1)

        return response

    def get(self, url: str, **kwargs) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        return self.request("POST", url, **kwargs)

    def detect_waf(self, response: requests.Response) -> list:
        """Return list of detected WAF names based on headers/body."""
        detected = []
        combined = (response.text or "").lower()
        for header, val in response.headers.items():
            combined += f" {header.lower()}: {val.lower()}"
        for waf_name, sigs in WAF_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in combined:
                    detected.append(waf_name)
                    break
        return list(set(detected))


# ── Path mutation / WAF bypass helpers ──────────────────────────────────────
def mutate_path(path: str, technique: str = "all") -> list:
    """
    Generate path mutations to bypass naive WAF/path filters.
    Returns a list of mutated path strings.
    """
    if not path or path == "/":
        return [path]

    mutations = {path}
    techniques = ["encoding", "double_slash", "case", "null", "path_traversal"] if technique == "all" else [technique]

    if "encoding" in techniques:
        mutations.add(quote(path, safe="/"))
        # Double URL encode some chars
        mutations.add(path.replace(".", "%252e").replace("/", "%252f"))

    if "double_slash" in techniques:
        mutations.add(path.replace("/", "//"))

    if "case" in techniques and any(c.isalpha() for c in path):
        # Random case swap for alpha chars
        mutated = "".join(c.upper() if random.random() > 0.5 else c.lower() for c in path)
        mutations.add(mutated)

    if "null" in techniques:
        mutations.add(path + "%00")
        mutations.add(path + "\x00")

    if "path_traversal" in techniques:
        mutations.add("/.." + path)
        mutations.add("/./" + path.lstrip("/"))
        mutations.add("/.../" + path.lstrip("/"))

    # Remove empty strings and original path duplicates
    return list(mutations)


# ── Stealth port scanner wrappers ───────────────────────────────────────────
def try_nmap_scan(target: str, ports: list, timing: str = "normal", syn: bool = False) -> list:
    """
    Attempt an nmap scan if python-nmap and the nmap binary are available.
    Returns a list of (port, banner) tuples, or None on failure.
    """
    if " " in target or target.startswith("-"):
        return None
    if not nmap_available():
        return None
    try:
        import nmap
    except ImportError:
        return None

    t_map = {
        "paranoid": "T1", "sneaky": "T2", "polite": "T3",
        "normal": "T4", "aggressive": "T5", "insane": "T5",
    }
    t_arg = t_map.get(timing, "T4")
    scan_type = "-sS" if (syn and has_root()) else "-sT"
    args = f"{scan_type} -{t_arg} --open --max-retries 2"

    port_str = ",".join(str(p) for p in ports)
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, ports=port_str, arguments=args)
    except Exception:
        return None

    results = []
    if target in nm.all_hosts():
        for proto in nm[target].all_protocols():
            ports_open = nm[target][proto].keys()
            for port in sorted(ports_open):
                state = nm[target][proto][port]["state"]
                if state == "open":
                    banner = nm[target][proto][port].get("name", "unknown")
                    results.append((port, banner))
    return results if results else []


def stealth_banner_probe(ip: str, port: int, timeout: float = 2.0) -> tuple:
    """
    TCP connect with randomized/generic banner probes instead of scanner signatures.
    Returns (port, is_open, banner).
    """
    generic_probes = {
        21:  b"USER anonymous\r\n",
        22:  b"SSH-2.0-OpenSSH_8.9\r\n",
        25:  b"EHLO example.com\r\n",
        80:  b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        110: b"USER postmaster\r\n",
        143: b"A001 CAPABILITY\r\n",
    }
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if sock.connect_ex((ip, port)) == 0:
            banner = ""
            try:
                sock.settimeout(timeout + 1)
                probe = generic_probes.get(port, b"\r\n")
                sock.send(probe)
                banner = sock.recv(1024).decode(errors="ignore").strip()
            except Exception:
                pass
            sock.close()
            return (port, True, banner)
        sock.close()
    except Exception:
        pass
    return (port, False, "")
