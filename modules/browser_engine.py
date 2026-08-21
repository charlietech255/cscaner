#!/usr/bin/env python3
"""
CSCAN — Advanced Browser Engine
═══════════════════════════════════════════════════════════════════

A full-featured, fingerprint-resistant browser engine natively integrated
into cscaner for advanced reconnaissance and WAF evasion.

Capabilities added to cscaner:
  ① Cloudflare UAM + Turnstile bypass         → cf_clearance + user-agent
  ② JS-rendered page source & DOM extraction  → bypasses SPAs & WAFs
  ③ Network traffic capture & HAR logging     → expose hidden API endpoints
  ④ Form-based login tester (HTTP auth / SPA) → credential validation
  ⑤ Screenshot recon                          → visual evidence capture
  ⑥ Browser fingerprint probe                → detect what target sees
  ⑦ Cookie & session harvester               → dump all cookies post-auth
  ⑧ JS secret / token scanner                → env vars, API keys in page JS

Install:
    pip install "camoufox[geoip]"
    python -m camoufox fetch
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

from modules.ui import (
    section, ok, warn, alert, info, critical, bold, divider, progress_bar,
    G, R, Y, C, M, W, BR, DM, RS, pause
)


# ── Safe asyncio.run() that works inside a running event loop ─────────────────
def _run_async(coro):
    """
    Run an async coroutine from sync code. Works correctly even if called
    from within an already-running event loop (e.g. from cscan.py's async main).
    """
    try:
        asyncio.get_running_loop()
        # Already in a running loop — offload to a new thread
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            return pool.submit(asyncio.run, coro).result()
    except RuntimeError:
        # No running loop — safe to call directly
        return asyncio.run(coro)

# ── Availability guard ────────────────────────────────────────────────────────
_CAMOUFOX_OK = False
try:
    from camoufox.async_api import AsyncCamoufox
    _CAMOUFOX_OK = True
except ImportError:
    pass


# ─────────────────────────────────────────────────────────────────────────────
#  CONFIG DATACLASS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class BrowserConfig:
    """Shared config for all browser engine functions."""
    target: str
    headless: bool = True
    proxy: Optional[str] = None          # http://user:pass@host:port
    os_fp: Optional[str] = None          # 'windows' | 'macos' | 'linux'
    locale: str = "en-US"
    humanize: bool = True
    geoip: bool = False
    block_webrtc: bool = True
    block_images: bool = False           # True = faster (skips image downloads)
    disable_coop: bool = True            # Required for Cloudflare Turnstile
    timeout_ms: int = 30_000


def _build_camoufox_opts(cfg: BrowserConfig) -> dict:
    """Translate BrowserConfig into AsyncCamoufox keyword arguments."""
    opts: dict = {
        "headless":       cfg.headless,
        "humanize":       cfg.humanize,
        "block_webrtc":   cfg.block_webrtc,
        "block_images":   cfg.block_images,
        "disable_coop":   cfg.disable_coop,
        "locale":         cfg.locale,
        "geoip":          True if (cfg.geoip and cfg.proxy) else False,
        "i_know_what_im_doing": True,
    }
    if cfg.os_fp:
        opts["os"] = cfg.os_fp
    if cfg.proxy:
        try:
            after  = cfg.proxy.split("://", 1)[1]       # user:pass@host:port
            creds, hostport = after.rsplit("@", 1)
            user, passwd    = creds.split(":", 1)
            opts["proxy"] = {
                "server":   f"http://{hostport}",
                "username": user,
                "password": passwd,
            }
        except Exception:
            warn(f"Could not parse proxy string — ignoring.")
    return opts


def _need_camoufox(fn_name: str) -> bool:
    if not _CAMOUFOX_OK:
        alert(f"Browser engine dependencies are not installed — cannot run '{fn_name}'.")
        print(f"""
  {Y}Please install the required dependencies:{RS}
    {W}pip install "camoufox[geoip]"{RS}
    {W}python -m camoufox fetch{RS}
""")
        return False
    return True


# ─────────────────────────────────────────────────────────────────────────────
#  ① CLOUDFLARE UAM + TURNSTILE BYPASS
# ─────────────────────────────────────────────────────────────────────────────

async def _bypass_cloudflare(cfg: BrowserConfig) -> dict | None:
    """
    Navigate to target in a fingerprint-safe browser, wait up to 30 s for
    Cloudflare to issue a cf_clearance cookie, then return all cookies +
    the user-agent used.
    """
    opts = _build_camoufox_opts(cfg)
    result = {"cf_clearance": None, "user_agent": None, "all_cookies": []}

    async with AsyncCamoufox(**opts) as browser:
        page = await browser.new_page()
        await page.goto(cfg.target, wait_until="networkidle", timeout=cfg.timeout_ms)

        # Wait up to 30 s for cf_clearance
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            cookies = await page.context.cookies()
            for c in cookies:
                if c.get("name") == "cf_clearance":
                    result["cf_clearance"] = c["value"]
                    break
            if result["cf_clearance"]:
                break
            await asyncio.sleep(1)

        result["all_cookies"] = await page.context.cookies()
        result["user_agent"]  = await page.evaluate("navigator.userAgent")

    return result if result["cf_clearance"] else None


def browser_cf_bypass(cfg: BrowserConfig) -> dict | None:
    """Public sync wrapper for Cloudflare bypass."""
    if not _need_camoufox("CF bypass"):
        return None
    try:
        return _run_async(_bypass_cloudflare(cfg))
    except Exception as e:
        alert(f"CF bypass error: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
#  ② JS-RENDERED PAGE SOURCE + DOM EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────

async def _js_render(cfg: BrowserConfig) -> dict:
    """
    Render a page fully in the browser (executes all JS) and return:
    - Full rendered HTML source
    - Page title
    - Meta tags (description, keywords, og:*)
    - All anchor hrefs (internal + external links)
    - All form actions and input names
    - Inline scripts content
    - Script src URLs (third-party includes)
    """
    opts = _build_camoufox_opts(cfg)
    opts["block_images"] = True  # speed up

    result: dict = {
        "html": "",
        "title": "",
        "metas": {},
        "links": {"internal": [], "external": []},
        "forms": [],
        "inline_scripts": [],
        "script_srcs": [],
        "status": None,
    }

    async with AsyncCamoufox(**opts) as browser:
        page = await browser.new_page()

        # Track response status for the main request
        async def on_response(resp):
            if resp.url.rstrip("/") == cfg.target.rstrip("/"):
                result["status"] = resp.status

        page.on("response", on_response)
        await page.goto(cfg.target, wait_until="networkidle", timeout=cfg.timeout_ms)

        result["html"]  = await page.content()
        result["title"] = await page.title()

        # Meta tags
        result["metas"] = await page.evaluate("""() => {
            const m = {};
            document.querySelectorAll('meta').forEach(el => {
                const k = el.name || el.property || el.httpEquiv;
                if (k) m[k] = el.content;
            });
            return m;
        }""")

        # Links
        host = urlparse(cfg.target).hostname or ""
        all_hrefs = await page.evaluate("""() =>
            [...document.querySelectorAll('a[href]')].map(a => a.href)
        """)
        for href in all_hrefs:
            h = urlparse(href).hostname or ""
            if h and host and (h == host or h.endswith("." + host)):
                result["links"]["internal"].append(href)
            elif href.startswith("http"):
                result["links"]["external"].append(href)

        # Forms
        result["forms"] = await page.evaluate("""() =>
            [...document.querySelectorAll('form')].map(f => ({
                action: f.action,
                method: f.method,
                inputs: [...f.querySelectorAll('input,textarea,select')].map(i => ({
                    name: i.name, type: i.type, id: i.id
                }))
            }))
        """)

        # Script tags
        scripts = await page.evaluate("""() => {
            const ext = [...document.querySelectorAll('script[src]')].map(s => s.src);
            const inl = [...document.querySelectorAll('script:not([src])')].map(s => s.textContent.trim());
            return {ext, inl};
        }""")
        result["script_srcs"]    = scripts["ext"]
        result["inline_scripts"] = scripts["inl"]

    return result


def browser_js_render(cfg: BrowserConfig) -> dict:
    """Public sync wrapper for JS rendering."""
    if not _need_camoufox("JS render"):
        return {}
    try:
        return _run_async(_js_render(cfg))
    except Exception as e:
        alert(f"JS render error: {e}")
        return {}


# ─────────────────────────────────────────────────────────────────────────────
#  ③ NETWORK TRAFFIC CAPTURE (hidden APIs, tokens in headers)
# ─────────────────────────────────────────────────────────────────────────────

_SENSITIVE_HEADER_PATTERNS = re.compile(
    r"authorization|bearer|api[_-]?key|x-api|token|secret|session|jwt",
    re.IGNORECASE,
)
_SECRET_VALUE_RE = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|apikey|token|bearer)[\"'\s:=]+([A-Za-z0-9_\-\.=+/]{8,})",
    re.IGNORECASE,
)


def _redacted_value(value: str) -> dict:
    """Keep enough metadata to identify a repeated secret without exposing it."""
    text = str(value or '')
    return {
        'value': '[REDACTED]',
        'length': len(text),
        'sha256_12': hashlib.sha256(text.encode('utf-8')).hexdigest()[:12],
    }


def _safe_headers(headers: dict) -> dict:
    """Redact reusable credentials while retaining non-sensitive headers."""
    safe = {}
    for name, value in headers.items():
        if _SENSITIVE_HEADER_PATTERNS.search(name) or name.lower() == 'cookie':
            safe[name] = _redacted_value(value)
        else:
            safe[name] = value
    return safe


async def _capture_network(cfg: BrowserConfig, wait_extra_ms: int = 3000) -> dict:
    """
    Open the target page and intercept ALL network requests/responses.
    Returns categorised traffic: API calls, sensitive headers, form posts.
    """
    opts = _build_camoufox_opts(cfg)
    opts["block_images"] = True

    traffic: dict = {
        "requests":          [],   # all requests
        "api_endpoints":     [],   # likely API/XHR calls
        "sensitive_headers": [],   # auth / token headers spotted
        "form_posts":        [],   # POST submissions
        "websockets":        [],   # WS URLs
    }
    _ws_seen: set = set()

    async with AsyncCamoufox(**opts) as browser:
        page = await browser.new_page()

        # Intercept requests
        async def handle_request(req):
            entry = {
                "url":     req.url,
                "method":  req.method,
                "headers": _safe_headers(dict(req.headers)),
            }
            traffic["requests"].append(entry)

            # Sensitive request headers
            for hname, hval in req.headers.items():
                if _SENSITIVE_HEADER_PATTERNS.search(hname):
                    traffic["sensitive_headers"].append({
                        "direction": "request",
                        "url": req.url, "header": hname,
                        **_redacted_value(hval),
                    })

            # API endpoints heuristic (XHR/fetch, JSON, /api/, graphql)
            u = req.url.lower()
            rt = req.resource_type
            if rt in ("xhr", "fetch") or "/api/" in u or "/graphql" in u or u.endswith(".json"):
                traffic["api_endpoints"].append({
                    "url": req.url, "method": req.method, "type": rt,
                })

            # POST interceptions
            if req.method == "POST":
                try:
                    body = req.post_data or ""
                except Exception:
                    body = ""
                traffic["form_posts"].append({
                    "url": req.url,
                    "body_present": bool(body),
                    "body_length": len(body),
                })

        async def handle_response(resp):
            # Sensitive response headers
            for hname, hval in resp.headers.items():
                if _SENSITIVE_HEADER_PATTERNS.search(hname):
                    traffic["sensitive_headers"].append({
                        "direction": "response",
                        "url": resp.url, "header": hname,
                        **_redacted_value(hval),
                    })

        page.on("request",  handle_request)
        page.on("response", handle_response)

        # WebSockets
        page.on("websocket", lambda ws: traffic["websockets"].append(ws.url)
                if ws.url not in _ws_seen and not _ws_seen.add(ws.url) else None)

        await page.goto(cfg.target, wait_until="networkidle", timeout=cfg.timeout_ms)
        await page.wait_for_timeout(wait_extra_ms)  # catch lazy-loaded XHR

    return traffic


def browser_capture_network(cfg: BrowserConfig, wait_extra_ms: int = 3000) -> dict:
    """Public sync wrapper for network traffic capture."""
    if not _need_camoufox("Network capture"):
        return {}
    try:
        return _run_async(_capture_network(cfg, wait_extra_ms))
    except Exception as e:
        alert(f"Network capture error: {e}")
        return {}


# ─────────────────────────────────────────────────────────────────────────────
#  ④ FORM LOGIN TESTER
# ─────────────────────────────────────────────────────────────────────────────

async def _test_login(
    cfg: BrowserConfig,
    username: str,
    password: str,
    user_sel: str = "input[type='text'],input[name*='user'],input[name*='email'],input[id*='user']",
    pass_sel: str = "input[type='password']",
    submit_sel: str = "input[type='submit'],button[type='submit'],button",
    success_indicators: list | None = None,
    failure_indicators: list | None = None,
) -> dict:
    """
    Attempt a browser-based form login, return result dict.
    success_indicators: strings to look for in post-submit HTML → success
    failure_indicators: strings to look for → failure
    """
    success_indicators = success_indicators or [
        "dashboard", "logout", "sign out", "welcome", "my account",
        "profile", "log out", "settings", "home"
    ]
    failure_indicators = failure_indicators or [
        "invalid", "incorrect", "wrong", "failed", "error",
        "denied", "unauthorized", "bad credentials", "try again"
    ]

    opts = _build_camoufox_opts(cfg)
    result = {
        "success": False,
        "url_after": "",
        "page_title": "",
        "cookies": [],
        "indicator": "",
    }

    async with AsyncCamoufox(**opts) as browser:
        page = await browser.new_page()
        await page.goto(cfg.target, wait_until="domcontentloaded", timeout=cfg.timeout_ms)

        # Fill username
        try:
            await page.locator(user_sel).first.fill(username)
        except Exception as e:
            result["indicator"] = f"No username field: {e}"
            return result

        # Fill password
        try:
            await page.locator(pass_sel).first.fill(password)
        except Exception as e:
            result["indicator"] = f"No password field: {e}"
            return result

        # Submit
        try:
            await page.locator(submit_sel).first.click()
            await page.wait_for_load_state("networkidle", timeout=10_000)
        except Exception as e:
            result["indicator"] = f"Submit failed: {e}"
            return result

        body_lower = (await page.content()).lower()
        result["url_after"]  = page.url
        result["page_title"] = await page.title()
        result["cookies"]    = await page.context.cookies()

        # Check indicators
        for s in success_indicators:
            if s.lower() in body_lower:
                result["success"]   = True
                result["indicator"] = s
                return result
        for f in failure_indicators:
            if f.lower() in body_lower:
                result["success"]   = False
                result["indicator"] = f
                return result

        # Fallback: URL changed = likely success
        if page.url.rstrip("/") != cfg.target.rstrip("/"):
            result["success"]   = True
            result["indicator"] = f"URL changed → {page.url}"

    return result


def browser_test_login(
    cfg: BrowserConfig,
    username: str,
    password: str,
) -> dict:
    """Public sync wrapper for form login test."""
    if not _need_camoufox("Login test"):
        return {}
    try:
        return _run_async(_test_login(cfg, username, password))
    except Exception as e:
        alert(f"Login test error: {e}")
        return {}


# ─────────────────────────────────────────────────────────────────────────────
#  ⑤ SCREENSHOT RECON
# ─────────────────────────────────────────────────────────────────────────────

async def _take_screenshot(cfg: BrowserConfig, full_page: bool = True) -> str | None:
    """Navigate and capture a screenshot. Returns saved file path or None."""
    opts = _build_camoufox_opts(cfg)
    opts["block_images"] = False  # images needed for visual recon

    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    host = urlparse(cfg.target).hostname or "target"
    out  = f"screenshot_{host}_{ts}.png"

    async with AsyncCamoufox(**opts) as browser:
        page = await browser.new_page()
        await page.goto(cfg.target, wait_until="networkidle", timeout=cfg.timeout_ms)
        await page.wait_for_timeout(1500)  # let lazy images load
        await page.screenshot(path=out, full_page=full_page)

    return out


def browser_screenshot(cfg: BrowserConfig, full_page: bool = True) -> str | None:
    """Public sync wrapper for screenshot capture."""
    if not _need_camoufox("Screenshot"):
        return None
    try:
        return _run_async(_take_screenshot(cfg, full_page))
    except Exception as e:
        alert(f"Screenshot error: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
#  ⑥ BROWSER FINGERPRINT PROBE
# ─────────────────────────────────────────────────────────────────────────────

_FP_SCRIPT = """() => ({
    userAgent:       navigator.userAgent,
    platform:        navigator.platform,
    language:        navigator.language,
    languages:       navigator.languages,
    doNotTrack:      navigator.doNotTrack,
    cookiesEnabled:  navigator.cookieEnabled,
    javaEnabled:     navigator.javaEnabled(),
    hardwareConcurrency: navigator.hardwareConcurrency,
    deviceMemory:    navigator.deviceMemory,
    screenWidth:     screen.width,
    screenHeight:    screen.height,
    colorDepth:      screen.colorDepth,
    timezone:        Intl.DateTimeFormat().resolvedOptions().timeZone,
    webglVendor:     (() => { try { const c=document.createElement('canvas'); const g=c.getContext('webgl'); const d=g.getExtension('WEBGL_debug_renderer_info'); return g.getParameter(d.UNMASKED_VENDOR_WEBGL); } catch(e){return 'N/A';} })(),
    webglRenderer:   (() => { try { const c=document.createElement('canvas'); const g=c.getContext('webgl'); const d=g.getExtension('WEBGL_debug_renderer_info'); return g.getParameter(d.UNMASKED_RENDERER_WEBGL); } catch(e){return 'N/A';} })(),
    webrtcSupported: typeof RTCPeerConnection !== 'undefined',
    plugins:         [...navigator.plugins].map(p => p.name),
    touchPoints:     navigator.maxTouchPoints,
    connectionType:  (navigator.connection || {}).effectiveType,
})"""


async def _probe_fingerprint(cfg: BrowserConfig) -> dict:
    """Open target and collect the browser fingerprint we present to it."""
    opts = _build_camoufox_opts(cfg)
    opts["block_images"] = True

    async with AsyncCamoufox(**opts) as browser:
        page = await browser.new_page()
        await page.goto(cfg.target, wait_until="domcontentloaded", timeout=cfg.timeout_ms)
        fp = await page.evaluate(_FP_SCRIPT)
    return fp


def browser_fingerprint_probe(cfg: BrowserConfig) -> dict:
    """Public sync wrapper for fingerprint probing."""
    if not _need_camoufox("Fingerprint probe"):
        return {}
    try:
        return _run_async(_probe_fingerprint(cfg))
    except Exception as e:
        alert(f"Fingerprint probe error: {e}")
        return {}


# ─────────────────────────────────────────────────────────────────────────────
#  ⑦ COOKIE & SESSION HARVESTER
# ─────────────────────────────────────────────────────────────────────────────

async def _harvest_cookies(cfg: BrowserConfig) -> list[dict]:
    """Navigate and collect all cookies the target sets."""
    opts = _build_camoufox_opts(cfg)
    opts["block_images"] = True

    async with AsyncCamoufox(**opts) as browser:
        page = await browser.new_page()
        await page.goto(cfg.target, wait_until="networkidle", timeout=cfg.timeout_ms)
        await page.wait_for_timeout(2000)
        cookies = await page.context.cookies()
        return [{**cookie, **_redacted_value(cookie.get('value', ''))}
            for cookie in cookies]


def browser_harvest_cookies(cfg: BrowserConfig) -> list[dict]:
    """Public sync wrapper for cookie harvesting."""
    if not _need_camoufox("Cookie harvest"):
        return []
    try:
        return _run_async(_harvest_cookies(cfg))
    except Exception as e:
        alert(f"Cookie harvest error: {e}")
        return []


# ─────────────────────────────────────────────────────────────────────────────
#  ⑧ JS SECRET / TOKEN SCANNER
# ─────────────────────────────────────────────────────────────────────────────

_JS_SECRET_PATTERNS = [
    # API Keys / Tokens
    (r'(?:api[_-]?key|apikey)["\'\s:=]+([A-Za-z0-9_\-]{16,})',        "API Key"),
    (r'(?:secret[_-]?key|secret)["\'\s:=]+([A-Za-z0-9_\-]{16,})',     "Secret Key"),
    (r'(?:access[_-]?token|accesstoken)["\'\s:=]+([A-Za-z0-9_\-.]{16,})', "Access Token"),
    (r'(?:auth[_-]?token|authtoken)["\'\s:=]+([A-Za-z0-9_\-.]{16,})',  "Auth Token"),
    (r'Bearer\s+([A-Za-z0-9_\-\.]{20,})',                              "Bearer Token"),
    # AWS
    (r'AKIA[0-9A-Z]{16}',                                              "AWS Access Key"),
    (r'(?:aws[_-]?secret)["\'\s:=]+([A-Za-z0-9/+=]{40})',             "AWS Secret"),
    # Firebase
    (r'"apiKey"\s*:\s*"(AIza[0-9A-Za-z\-_]{35})"',                    "Firebase API Key"),
    # Stripe
    (r'(sk_live_[0-9a-zA-Z]{24,})',                                    "Stripe Live Key"),
    (r'(pk_live_[0-9a-zA-Z]{24,})',                                    "Stripe Pub Key"),
    # JWT
    (r'(eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)',      "JWT Token"),
    # Passwords in JS
    (r'(?:password|passwd)["\'\s:=]+([^\s"\']{6,})',                   "Password"),
    # Generic long hex secrets
    (r'(?:token|key|secret)["\'\s:=]+([0-9a-fA-F]{32,})',             "Hex Secret"),
]


async def _scan_js_secrets(cfg: BrowserConfig) -> list[dict]:
    """
    Load target, then fetch every <script src> and scan inline scripts
    for secrets, API keys, tokens, and credentials.
    """
    opts = _build_camoufox_opts(cfg)
    opts["block_images"] = True

    findings: list[dict] = []

    async with AsyncCamoufox(**opts) as browser:
        page = await browser.new_page()
        await page.goto(cfg.target, wait_until="networkidle", timeout=cfg.timeout_ms)

        # Inline scripts
        inline = await page.evaluate("""() =>
            [...document.querySelectorAll('script:not([src])')].map(s => ({
                src: '[inline]', content: s.textContent
            }))
        """)

        # External script URLs
        ext_srcs = await page.evaluate("""() =>
            [...document.querySelectorAll('script[src]')].map(s => s.src)
        """)

        scripts_to_scan = inline[:]

        # Fetch external scripts content
        for src in ext_srcs:
            try:
                resp = await page.evaluate(f"""async () => {{
                    const r = await fetch("{src}", {{credentials:'include'}});
                    return r.ok ? await r.text() : null;
                }}""")
                if resp:
                    scripts_to_scan.append({"src": src, "content": resp})
            except Exception:
                pass

        # Scan each script
        for script in scripts_to_scan:
            content = script.get("content", "") or ""
            src     = script.get("src", "[inline]")
            for pattern, label in _JS_SECRET_PATTERNS:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    val = match.group(0 if match.lastindex is None else 1)
                    if len(val) < 8:
                        continue
                    # Skip obvious placeholders
                    if val.lower() in ("your_api_key", "xxx", "placeholder", "undefined", "null"):
                        continue
                    findings.append({
                        "type":     label,
                        **_redacted_value(val),
                        "source":   src if len(src) < 100 else src[-80:],
                        "context":  (
                            content[max(0, match.start()-30): match.start()+len(val)+30]
                            .replace(val, '[REDACTED]')
                            .strip()
                        ),
                    })

    return findings


def browser_scan_js_secrets(cfg: BrowserConfig) -> list[dict]:
    """Public sync wrapper for JS secret scanning."""
    if not _need_camoufox("JS secrets scan"):
        return []
    try:
        return _run_async(_scan_js_secrets(cfg))
    except Exception as e:
        alert(f"JS secrets scan error: {e}")
        return []


# ─────────────────────────────────────────────────────────────────────────────
#  DISPLAY HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def display_network_results(traffic: dict, target: str):
    section("NETWORK TRAFFIC CAPTURE RESULTS")
    info(f"Target           : {BR}{C}{target}{RS}")
    info(f"Total requests   : {BR}{W}{len(traffic.get('requests', []))}{RS}")

    api = traffic.get("api_endpoints", [])
    if api:
        print(f"\n  {BR}{M}  API Endpoints Discovered ({len(api)}):{RS}")
        for ep in api[:30]:
            col = G if ep["method"] == "GET" else Y
            print(f"  {col}[{ep['method']}]{RS}  {ep['url']}")

    sens = traffic.get("sensitive_headers", [])
    if sens:
        print(f"\n  {BR}{R}  Sensitive Headers ({len(sens)}):{RS}")
        for s in sens[:20]:
            print(f"  {R}[{s['direction'].upper()}]{RS} {Y}{s['header']}{RS}: {DM}{s['value'][:60]}{RS}")
            print(f"    {DM}→ {s['url'][:80]}{RS}")

    posts = traffic.get("form_posts", [])
    if posts:
        print(f"\n  {BR}{Y}  POST Submissions ({len(posts)}):{RS}")
        for p in posts[:10]:
            print(f"  {Y}[POST]{RS}  {p['url']}")
            if p.get("body_preview"):
                print(f"    {DM}{p['body_preview'][:100]}{RS}")

    ws = traffic.get("websockets", [])
    if ws:
        print(f"\n  {BR}{C}  WebSocket URLs ({len(ws)}):{RS}")
        for w in ws:
            print(f"  {C}[WS]{RS}  {w}")

    if not api and not sens and not posts and not ws:
        ok("No API endpoints, sensitive headers, or POST data detected.")


def display_js_secrets(findings: list[dict]):
    if not findings:
        ok("No secrets or tokens found in JavaScript.")
        return
    print(f"\n  {BR}{R}  ⚠  {len(findings)} SECRET(S) FOUND IN JS  ⚠{RS}\n")
    seen = set()
    for f in findings:
        key = (f["type"], f["value"])
        if key in seen:
            continue
        seen.add(key)
        critical(f"{f['type']}: {BR}{R}{f['value']}{RS}")
        print(f"    {DM}Source : {f['source']}{RS}")
        if f.get("context"):
            print(f"    {DM}Context: …{f['context'][:100]}…{RS}")


def display_fingerprint(fp: dict):
    section("BROWSER FINGERPRINT PRESENTED TO TARGET")
    rows = [
        ("User-Agent",    fp.get("userAgent", "N/A")),
        ("Platform",      fp.get("platform", "N/A")),
        ("Language",      fp.get("language", "N/A")),
        ("Timezone",      fp.get("timezone", "N/A")),
        ("Screen",        f"{fp.get('screenWidth')}×{fp.get('screenHeight')} @ {fp.get('colorDepth')}bit"),
        ("CPU cores",     str(fp.get("hardwareConcurrency", "N/A"))),
        ("Device RAM",    f"{fp.get('deviceMemory', 'N/A')} GB"),
        ("Touch points",  str(fp.get("touchPoints", 0))),
        ("WebGL Vendor",  fp.get("webglVendor", "N/A")),
        ("WebGL Renderer",fp.get("webglRenderer", "N/A")),
        ("WebRTC",        "Enabled" if fp.get("webrtcSupported") else "Blocked"),
        ("Cookies",       "Enabled" if fp.get("cookiesEnabled") else "Disabled"),
        ("DoNotTrack",    str(fp.get("doNotTrack", "N/A"))),
        ("Connection",    fp.get("connectionType", "N/A")),
        ("Plugins",       ", ".join(fp.get("plugins", [])[:4]) or "none"),
    ]
    for k, v in rows:
        print(f"  {DM}{k:<18}{RS} : {W}{v}{RS}")


def display_cookies(cookies: list[dict]):
    if not cookies:
        warn("No cookies found.")
        return
    print(f"\n  {BR}{C}  Cookies ({len(cookies)}):{RS}")
    for c in cookies:
        flags  = []
        if c.get("secure"):    flags.append(f"{G}Secure{RS}")
        if c.get("httpOnly"):  flags.append(f"{G}HttpOnly{RS}")
        if not c.get("secure"): flags.append(f"{R}!Secure{RS}")
        same   = c.get("sameSite", "")
        if same: flags.append(f"{Y}SameSite={same}{RS}")
        exp    = c.get("expires", -1)
        expiry = "Session" if exp == -1 else datetime.fromtimestamp(exp).strftime("%Y-%m-%d")
        print(f"  {M}[cookie]{RS} {BR}{W}{c['name']}{RS}")
        print(f"    {DM}Value  :{RS} {c['value'][:50]}{'…' if len(c['value'])>50 else ''}")
        print(f"    {DM}Domain :{RS} {c.get('domain','?')}   {DM}Path:{RS} {c.get('path','/')}")
        print(f"    {DM}Flags  :{RS} {' '.join(flags) or 'none'}   {DM}Expires:{RS} {expiry}")


def display_js_render(data: dict):
    section("JS-RENDERED PAGE ANALYSIS")
    ok(f"Title  : {BR}{W}{data.get('title', 'N/A')}{RS}")
    info(f"Status : {data.get('status', 'unknown')}")
    info(f"HTML   : {len(data.get('html', ''))} bytes")

    ints = data.get("links", {}).get("internal", [])
    exts = data.get("links", {}).get("external", [])
    info(f"Links  : {len(ints)} internal, {len(exts)} external")

    forms = data.get("forms", [])
    if forms:
        print(f"\n  {BR}{Y}  Forms ({len(forms)}):{RS}")
        for i, form in enumerate(forms, 1):
            print(f"  {Y}[{i}]{RS}  {form.get('method','?').upper()} → {form.get('action','?')}")
            for inp in form.get("inputs", [])[:8]:
                print(f"       {DM}{inp.get('type','?'):<12} name={inp.get('name','?')}{RS}")

    srcs = data.get("script_srcs", [])
    if srcs:
        print(f"\n  {BR}{C}  External Scripts ({len(srcs)}):{RS}")
        for s in srcs[:15]:
            print(f"  {DM}{s[:90]}{RS}")

    metas = data.get("metas", {})
    if metas:
        print(f"\n  {BR}{M}  Meta Tags:{RS}")
        for k, v in list(metas.items())[:8]:
            print(f"  {DM}{k:<25}{RS} : {W}{v[:80]}{RS}")


# ─────────────────────────────────────────────────────────────────────────────
#  INTERACTIVE MENU BUILDERS  (called from cscan.py)
# ─────────────────────────────────────────────────────────────────────────────

def _build_cfg(session: dict, extra_opts: dict | None = None) -> BrowserConfig:
    """Build BrowserConfig from the cscaner SESSION dict."""
    stealth = session.get("stealth", {})
    proxy   = stealth.get("proxy") if stealth.get("enabled") else None
    cfg = BrowserConfig(
        target    = session.get("target") or "",
        headless  = True,
        proxy     = proxy,
        geoip     = bool(proxy),
        humanize  = True,
        block_webrtc = True,
        disable_coop = True,
    )
    if extra_opts:
        for k, v in extra_opts.items():
            if hasattr(cfg, k):
                setattr(cfg, k, v)
    return cfg


def _check_target(session: dict) -> str | None:
    t = session.get("target")
    if not t:
        t = input(f"  {BR}{W}Enter target URL: {RS}").strip()
        if t:
            session["target"] = t
    if not t:
        warn("No target set.")
    return t or None


def menu_js_render(session: dict) -> dict:
    section("JS-RENDERED PAGE SOURCE & DOM EXTRACTION")
    if not _need_camoufox("JS render"): return {}
    t = _check_target(session)
    if not t: return {}
    cfg = _build_cfg(session)
    info("Loading page in stealth browser, executing all JavaScript...")
    data = browser_js_render(cfg)
    if data:
        display_js_render(data)
        session["results"]["browser_js_render"] = {
            "title": data.get("title"), "status": data.get("status"),
            "internal_links": data.get("links", {}).get("internal", []),
            "external_links":  data.get("links", {}).get("external", []),
            "forms": data.get("forms", []),
            "script_srcs": data.get("script_srcs", []),
        }
    return data


def menu_network_capture(session: dict) -> dict:
    section("NETWORK TRAFFIC CAPTURE")
    if not _need_camoufox("Network capture"): return {}
    t = _check_target(session)
    if not t: return {}
    cfg = _build_cfg(session)

    raw = input(f"  {BR}{W}Extra wait seconds after page load [3]: {RS}").strip()
    extra_ms = int(raw) * 1000 if raw.isdigit() else 3000

    info("Intercepting all browser network traffic...")
    traffic = browser_capture_network(cfg, extra_ms) if _CAMOUFOX_OK else {}
    if traffic:
        display_network_results(traffic, t)
        session["results"]["browser_network"] = {
            "api_count":      len(traffic.get("api_endpoints", [])),
            "sensitive_hdrs": len(traffic.get("sensitive_headers", [])),
            "post_count":     len(traffic.get("form_posts", [])),
            "ws_count":       len(traffic.get("websockets", [])),
            "api_endpoints":  traffic.get("api_endpoints", []),
            "sensitive_headers": traffic.get("sensitive_headers", []),
        }
    return traffic


async def _browser_capture_network_async(cfg, extra_ms):
    return await _capture_network(cfg, extra_ms)


def menu_screenshot(session: dict) -> str | None:
    section("SCREENSHOT RECON")
    if not _need_camoufox("Screenshot"): return None
    t = _check_target(session)
    if not t: return None
    cfg = _build_cfg(session, {"block_images": False, "headless": True})
    full = input(f"  {BR}{W}Full page screenshot? [Y/n]: {RS}").strip().lower() not in ("n", "no")
    info("Capturing screenshot in stealth browser...")
    path = browser_screenshot(cfg, full_page=full)
    if path:
        ok(f"Screenshot saved → {BR}{G}{path}{RS}")
        session["results"]["browser_screenshot"] = path
    return path


def menu_fingerprint_probe(session: dict) -> dict:
    section("BROWSER FINGERPRINT PROBE")
    if not _need_camoufox("Fingerprint probe"): return {}
    t = _check_target(session)
    if not t: return {}
    cfg = _build_cfg(session)
    info("Probing fingerprint from target's perspective...")
    fp = browser_fingerprint_probe(cfg)
    if fp:
        display_fingerprint(fp)
        session["results"]["browser_fingerprint"] = fp
    return fp


def menu_harvest_cookies(session: dict) -> list:
    section("COOKIE & SESSION HARVESTER")
    if not _need_camoufox("Cookie harvest"): return []
    t = _check_target(session)
    if not t: return []
    cfg = _build_cfg(session)
    info("Harvesting all cookies from target...")
    cookies = browser_harvest_cookies(cfg)
    if cookies:
        display_cookies(cookies)
        session["results"]["browser_cookies"] = cookies
        # Flag suspicious session cookies missing Secure/HttpOnly
        risky = [c for c in cookies if not c.get("secure") or not c.get("httpOnly")]
        if risky:
            alert(f"{len(risky)} cookie(s) missing Secure / HttpOnly flags!")
    return cookies


def menu_js_secrets(session: dict) -> list:
    section("JS SECRET & TOKEN SCANNER")
    if not _need_camoufox("JS secrets"): return []
    t = _check_target(session)
    if not t: return []
    cfg = _build_cfg(session)
    info("Scanning all JavaScript files for secrets, tokens, and keys...")
    findings = browser_scan_js_secrets(cfg)
    display_js_secrets(findings)
    session["results"]["browser_js_secrets"] = findings
    return findings


def menu_login_test(session: dict) -> dict:
    section("FORM LOGIN TESTER")
    if not _need_camoufox("Login test"): return {}
    t = _check_target(session)
    if not t: return {}
    cfg = _build_cfg(session)

    user = input(f"  {BR}{W}Username / Email: {RS}").strip()
    pw   = input(f"  {BR}{W}Password       : {RS}").strip()
    if not user or not pw:
        warn("Both username and password required.")
        return {}

    info(f"Attempting login as {BR}{C}{user}{RS} in stealth browser...")
    result = browser_test_login(cfg, user, pw)

    divider()
    if result.get("success"):
        critical(f"LOGIN SUCCESS!  ({result.get('indicator', '')})")
        ok(f"URL after login : {result['url_after']}")
        ok(f"Page title      : {result['page_title']}")
        cookies = result.get("cookies", [])
        if cookies:
            ok(f"Harvested {len(cookies)} cookie(s) post-login:")
            display_cookies(cookies)
    else:
        ok(f"Login failed. Indicator: {result.get('indicator', 'none')}")

    session["results"]["browser_login_test"] = result
    return result
